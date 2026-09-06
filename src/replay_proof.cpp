#include "guff/replay_proof.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <locale>
#include <sstream>
#include <utility>

namespace guff {
namespace {

void append_field(std::ostringstream& out,
                  std::string_view key,
                  std::string_view value) {
    out << key.size() << ':' << key
        << '=' << value.size() << ':' << value
        << ';';
}

template <typename T>
void append_number(std::ostringstream& out,
                   std::string_view key,
                   T value) {
    append_field(out, key, std::to_string(value));
}

std::string format_double(double value) {
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << std::setprecision(17) << value;
    return out.str();
}

bool prefixed_sha(std::string_view value, std::string_view prefix) noexcept {
    return value.starts_with(prefix) && is_sha256(value.substr(prefix.size()));
}

bool plain_sha(std::string_view value) noexcept {
    return is_sha256(value);
}

std::string selected_model(const KernelTaskResult& result) {
    if (result.provenance && !result.provenance->model_id.empty()) {
        return result.provenance->model_id;
    }
    if (result.route.selected_model_id) return *result.route.selected_model_id;
    if (result.artifact) return result.artifact->model_id;
    return {};
}

std::string route_trace_digest(const KernelTaskResult& result) {
    return sha256(result.route.trace.describe());
}

} // namespace

std::string replay_request_contract_sha256(const KernelTaskRequest& request) {
    std::ostringstream out;
    append_number(out, "schema_version", 1U);
    append_field(out, "instruction_sha256", sha256(request.instruction));
    append_field(out, "intent", request.route_request.signal.intent);
    append_field(out, "layer", to_string(request.route_request.signal.layer));
    append_field(out, "complexity", format_double(request.route_request.signal.complexity));
    append_field(out, "uncertainty", format_double(request.route_request.signal.uncertainty));
    append_number(out, "requires_execution", request.route_request.signal.requires_execution ? 1 : 0);
    append_number(out, "destructive", request.route_request.signal.destructive ? 1 : 0);
    append_field(out, "task", to_string(request.route_request.task));
    append_field(out, "profile_name", request.route_request.profile_name);
    append_field(out, "weight_quality", format_double(request.route_request.weights.quality));
    append_field(out, "weight_speed", format_double(request.route_request.weights.speed));
    append_field(out, "weight_memory", format_double(request.route_request.weights.memory_efficiency));
    append_field(out, "weight_reliability", format_double(request.route_request.weights.reliability));
    append_field(out, "weight_energy", format_double(request.route_request.weights.energy_efficiency));
    append_field(out, "minimum_score", format_double(request.route_request.minimum_score));
    append_number(out, "require_verified", request.route_request.require_verified ? 1 : 0);
    append_number(out, "context_max_slices", request.context_budget.max_slices);
    append_number(out, "context_max_total_bytes", request.context_budget.max_total_bytes);

    for (std::size_t index = 0U; index < request.context_slices.size(); ++index) {
        const auto& slice = request.context_slices[index];
        append_number(out, "context_index", index);
        append_field(out, "context_source_id", slice.source_id);
        append_field(out, "context_kind", to_string(slice.kind));
        append_field(out, "context_layer", to_string(slice.layer));
        append_field(out, "context_locator", slice.locator);
        append_field(out, "context_source_sha256", slice.content_sha256);
        append_number(out, "context_offset", slice.offset);
        append_field(out, "context_data_sha256", sha256(slice.data));
        append_number(out, "context_truncated", slice.truncated ? 1 : 0);
    }

    append_field(out, "artifact_mode", to_string(request.artifact_mode));
    append_number(out, "forge_max_wall_time_ms", request.forge_budget.max_wall_time_ms);
    append_number(out, "forge_max_output_bytes", request.forge_budget.max_output_bytes);

    auto permissions = request.permission_tokens;
    std::sort(permissions.begin(), permissions.end());
    for (const auto& permission : permissions) append_field(out, "permission", permission);
    append_number(out, "require_semantic_verification",
                  request.require_semantic_verification ? 1 : 0);
    return sha256(out.str());
}

std::vector<std::string> KernelFailureProof::validate() const {
    std::vector<std::string> errors;
    if (schema_version != 1U) errors.emplace_back("unsupported failure-proof schema_version");
    if (task_status == KernelTaskStatus::Completed) {
        errors.emplace_back("failure proof cannot describe a completed task");
    }
    if (!plain_sha(request_contract_sha256)) {
        errors.emplace_back("request_contract_sha256 must be a SHA-256 digest");
    }
    if (!prefixed_sha(hardware_id, "guff:hardware:sha256:")) {
        errors.emplace_back("hardware_id must be a GUFF hardware identity");
    }
    if (!selected_model_id.empty() &&
        !prefixed_sha(selected_model_id, "guff:model:sha256:")) {
        errors.emplace_back("selected_model_id must be empty or a GUFF model identity");
    }
    if (!artifact_id.empty() &&
        !prefixed_sha(artifact_id, "guff:artifact:sha256:")) {
        errors.emplace_back("artifact_id must be empty or a GUFF artifact identity");
    }
    if (!binding_id.empty() &&
        !prefixed_sha(binding_id, "guff:gguf-binding:sha256:")) {
        errors.emplace_back("binding_id must be empty or a GUFF GGUF binding identity");
    }
    if (!slot_immutable_id.empty() &&
        !prefixed_sha(slot_immutable_id, "guff:slot:sha256:")) {
        errors.emplace_back("slot_immutable_id must be empty or a GUFF slot identity");
    }
    if (!plain_sha(route_trace_sha256)) {
        errors.emplace_back("route_trace_sha256 must be a SHA-256 digest");
    }
    if (!captured_output_sha256.empty() && !plain_sha(captured_output_sha256)) {
        errors.emplace_back("captured_output_sha256 must be empty or a SHA-256 digest");
    }
    if (!plain_sha(reason_sha256)) {
        errors.emplace_back("reason_sha256 must be a SHA-256 digest");
    }
    if (!execution_present && forge_status != ForgeStatus::InvalidRequest) {
        errors.emplace_back("forge_status must remain INVALID_REQUEST when execution is absent");
    }
    return errors;
}

std::string KernelFailureProof::canonical_payload() const {
    std::ostringstream out;
    append_number(out, "schema_version", schema_version);
    append_field(out, "task_status", to_string(task_status));
    append_number(out, "execution_present", execution_present ? 1 : 0);
    append_field(out, "forge_status", to_string(forge_status));
    append_number(out, "exit_code", exit_code);
    append_field(out, "request_contract_sha256", request_contract_sha256);
    append_field(out, "hardware_id", hardware_id);
    append_field(out, "selected_model_id", selected_model_id);
    append_field(out, "artifact_id", artifact_id);
    append_field(out, "binding_id", binding_id);
    append_field(out, "slot_immutable_id", slot_immutable_id);
    append_field(out, "route_trace_sha256", route_trace_sha256);
    append_field(out, "captured_output_sha256", captured_output_sha256);
    append_field(out, "reason_sha256", reason_sha256);
    return out.str();
}

std::string KernelFailureProof::immutable_id() const {
    return "guff:failure-proof:sha256:" + sha256(canonical_payload());
}

std::vector<std::string> KernelReplayCapsule::validate() const {
    std::vector<std::string> errors;
    if (schema_version != 1U) errors.emplace_back("unsupported replay-capsule schema_version");
    if (!plain_sha(request_contract_sha256)) {
        errors.emplace_back("request_contract_sha256 must be a SHA-256 digest");
    }
    if (!prefixed_sha(hardware_id, "guff:hardware:sha256:")) {
        errors.emplace_back("hardware_id must be a GUFF hardware identity");
    }

    if (source_outcome == ReplaySourceOutcome::Completed) {
        if (expected_task_status != KernelTaskStatus::Completed) {
            errors.emplace_back("completed replay capsule must expect COMPLETED");
        }
        if (!prefixed_sha(source_proof_id, "guff:task-proof:sha256:")) {
            errors.emplace_back("completed replay capsule requires a task-proof identity");
        }
        if (!prefixed_sha(model_id, "guff:model:sha256:")) {
            errors.emplace_back("completed replay capsule requires a model identity");
        }
        if (!prefixed_sha(cartridge_id, "guff:kernel-cartridge:sha256:")) {
            errors.emplace_back("completed replay capsule requires a cartridge identity");
        }
        if (!prefixed_sha(artifact_id, "guff:artifact:sha256:")) {
            errors.emplace_back("completed replay capsule requires an artifact identity");
        }
        if (!prefixed_sha(binding_id, "guff:gguf-binding:sha256:")) {
            errors.emplace_back("completed replay capsule requires a GGUF binding identity");
        }
        if (!prefixed_sha(slot_immutable_id, "guff:slot:sha256:")) {
            errors.emplace_back("completed replay capsule requires a slot identity");
        }
        if (!plain_sha(prompt_sha256) || !plain_sha(context_sha256) ||
            !plain_sha(answer_sha256)) {
            errors.emplace_back("completed replay capsule requires prompt/context/answer SHA-256 values");
        }
        if (!failure_proof_id.empty()) {
            errors.emplace_back("completed replay capsule cannot carry failure_proof_id");
        }
    } else {
        if (expected_task_status == KernelTaskStatus::Completed) {
            errors.emplace_back("failed replay capsule cannot expect COMPLETED");
        }
        if (!prefixed_sha(source_proof_id, "guff:failure-proof:sha256:") ||
            source_proof_id != failure_proof_id) {
            errors.emplace_back("failed replay capsule requires its exact failure-proof identity");
        }
    }
    return errors;
}

std::string KernelReplayCapsule::canonical_payload() const {
    std::ostringstream out;
    append_number(out, "schema_version", schema_version);
    append_field(out, "source_outcome", to_string(source_outcome));
    append_field(out, "source_proof_id", source_proof_id);
    append_field(out, "request_contract_sha256", request_contract_sha256);
    append_field(out, "hardware_id", hardware_id);
    append_field(out, "expected_task_status", to_string(expected_task_status));
    append_field(out, "model_id", model_id);
    append_field(out, "cartridge_id", cartridge_id);
    append_field(out, "artifact_id", artifact_id);
    append_field(out, "binding_id", binding_id);
    append_field(out, "slot_immutable_id", slot_immutable_id);
    append_field(out, "prompt_sha256", prompt_sha256);
    append_field(out, "context_sha256", context_sha256);
    append_field(out, "answer_sha256", answer_sha256);
    append_number(out, "semantic_verified", semantic_verified ? 1 : 0);
    append_field(out, "failure_proof_id", failure_proof_id);
    return out.str();
}

std::string KernelReplayCapsule::immutable_id() const {
    return "guff:replay-capsule:sha256:" + sha256(canonical_payload());
}

bool ReplayPreflight::ready() const noexcept {
    return status == ReplayPreflightStatus::Ready;
}

bool ReplayVerification::matched() const noexcept {
    return status == ReplayVerificationStatus::ExactMatch ||
           status == ReplayVerificationStatus::ReproducedFailure;
}

std::optional<KernelFailureProof> KernelReplayProof::capture_failure(
    const KernelTaskRequest& request,
    const KernelTaskResult& result,
    const HardwareProfile& hardware) const {
    if (result.succeeded() || result.status == KernelTaskStatus::Completed) {
        return std::nullopt;
    }

    KernelFailureProof proof;
    proof.task_status = result.status;
    proof.request_contract_sha256 = replay_request_contract_sha256(request);
    proof.hardware_id = hardware.immutable_id();
    proof.selected_model_id = selected_model(result);
    proof.route_trace_sha256 = route_trace_digest(result);
    proof.reason_sha256 = sha256(result.reason);

    if (result.artifact) proof.artifact_id = result.artifact->artifact_id;
    if (result.provenance) {
        proof.binding_id = result.provenance->binding_id;
        proof.slot_immutable_id = result.provenance->slot_immutable_id;
        if (proof.artifact_id.empty()) proof.artifact_id = result.provenance->artifact_id;
    }
    if (result.execution) {
        proof.execution_present = true;
        proof.forge_status = result.execution->status;
        proof.exit_code = result.execution->exit_code;
        proof.slot_immutable_id = result.execution->slot_immutable_id;
        proof.captured_output_sha256 = result.execution->captured_output_sha256;
    }

    if (!proof.validate().empty()) return std::nullopt;
    return proof;
}

std::optional<KernelReplayCapsule> KernelReplayProof::capture(
    const KernelTaskRequest& request,
    const KernelTaskResult& result,
    const HardwareProfile& hardware) const {
    KernelReplayCapsule capsule;
    capsule.request_contract_sha256 = replay_request_contract_sha256(request);
    capsule.hardware_id = hardware.immutable_id();
    capsule.expected_task_status = result.status;

    if (result.succeeded() && result.provenance) {
        const auto& provenance = *result.provenance;
        capsule.source_outcome = ReplaySourceOutcome::Completed;
        capsule.source_proof_id = provenance.immutable_id();
        capsule.model_id = provenance.model_id;
        capsule.cartridge_id = provenance.cartridge_id;
        capsule.artifact_id = provenance.artifact_id;
        capsule.binding_id = provenance.binding_id;
        capsule.slot_immutable_id = provenance.slot_immutable_id;
        capsule.prompt_sha256 = provenance.prompt_sha256;
        capsule.context_sha256 = provenance.context_sha256;
        capsule.answer_sha256 = provenance.answer_sha256;
        capsule.semantic_verified = provenance.semantic_verified;
    } else {
        const auto failure = capture_failure(request, result, hardware);
        if (!failure) return std::nullopt;
        capsule.source_outcome = ReplaySourceOutcome::Failed;
        capsule.source_proof_id = failure->immutable_id();
        capsule.failure_proof_id = capsule.source_proof_id;
        capsule.model_id = failure->selected_model_id;
        capsule.artifact_id = failure->artifact_id;
        capsule.binding_id = failure->binding_id;
        capsule.slot_immutable_id = failure->slot_immutable_id;
    }

    if (!capsule.validate().empty()) return std::nullopt;
    return capsule;
}

ReplayPreflight KernelReplayProof::preflight(
    const KernelReplayCapsule& capsule,
    const KernelTaskRequest& replay_request,
    const HardwareProfile& hardware) const {
    ReplayPreflight result;
    result.capsule_id = capsule.immutable_id();
    result.request_contract_sha256 = replay_request_contract_sha256(replay_request);
    result.hardware_id = hardware.immutable_id();

    const auto errors = capsule.validate();
    if (!errors.empty()) {
        result.status = ReplayPreflightStatus::InvalidCapsule;
        result.reason = errors.front();
        return result;
    }
    if (result.request_contract_sha256 != capsule.request_contract_sha256) {
        result.status = ReplayPreflightStatus::InputDrift;
        result.reason = "rehydrated replay request does not match the captured task contract";
        return result;
    }
    if (result.hardware_id != capsule.hardware_id) {
        result.status = ReplayPreflightStatus::HardwareDrift;
        result.reason = "replay hardware identity differs from the captured hardware identity";
        return result;
    }

    result.status = ReplayPreflightStatus::Ready;
    result.reason = "request and hardware match the replay capsule; execution remains caller-controlled";
    return result;
}

ReplayVerification KernelReplayProof::verify(
    const KernelReplayCapsule& capsule,
    const KernelTaskRequest& replay_request,
    const KernelTaskResult& replay_result,
    const HardwareProfile& hardware) const {
    ReplayVerification verification;
    verification.capsule_id = capsule.immutable_id();

    const auto gate = preflight(capsule, replay_request, hardware);
    if (!gate.ready()) {
        switch (gate.status) {
        case ReplayPreflightStatus::InvalidCapsule:
            verification.status = ReplayVerificationStatus::InvalidCapsule;
            break;
        case ReplayPreflightStatus::InputDrift:
            verification.status = ReplayVerificationStatus::InputDrift;
            break;
        case ReplayPreflightStatus::HardwareDrift:
            verification.status = ReplayVerificationStatus::HardwareDrift;
            break;
        case ReplayPreflightStatus::Ready:
            break;
        }
        verification.reason = gate.reason;
        return verification;
    }

    if (capsule.source_outcome == ReplaySourceOutcome::Failed) {
        if (replay_result.succeeded()) {
            if (replay_result.provenance) {
                verification.observed_proof_id = replay_result.provenance->immutable_id();
            }
            verification.status = ReplayVerificationStatus::FailureDrift;
            verification.reason = "source task failed but replay completed successfully";
            return verification;
        }
        const auto observed = capture_failure(replay_request, replay_result, hardware);
        if (!observed) {
            verification.status = ReplayVerificationStatus::ReplayIncomplete;
            verification.reason = "replay failure could not be converted into a valid failure proof";
            return verification;
        }
        verification.observed_proof_id = observed->immutable_id();
        if (verification.observed_proof_id == capsule.failure_proof_id) {
            verification.status = ReplayVerificationStatus::ReproducedFailure;
            verification.reason = "replay reproduced the same content-addressed failure boundary";
        } else {
            verification.status = ReplayVerificationStatus::FailureDrift;
            verification.reason = "replay failed, but not with the same failure proof";
        }
        return verification;
    }

    if (!replay_result.succeeded() || !replay_result.provenance) {
        verification.status = ReplayVerificationStatus::ReplayIncomplete;
        verification.reason = "source task completed but replay did not produce a completed task proof";
        return verification;
    }

    const auto& observed = *replay_result.provenance;
    verification.observed_proof_id = observed.immutable_id();

    const bool runtime_match =
        replay_result.status == capsule.expected_task_status &&
        observed.model_id == capsule.model_id &&
        observed.cartridge_id == capsule.cartridge_id &&
        observed.artifact_id == capsule.artifact_id &&
        observed.binding_id == capsule.binding_id &&
        observed.slot_immutable_id == capsule.slot_immutable_id &&
        observed.hardware_id == capsule.hardware_id &&
        observed.prompt_sha256 == capsule.prompt_sha256 &&
        observed.context_sha256 == capsule.context_sha256 &&
        observed.semantic_verified == capsule.semantic_verified;

    if (!runtime_match) {
        verification.status = ReplayVerificationStatus::RuntimeDrift;
        verification.reason = "replay crossed a different model/artifact/binding/slot/prompt/context verification state";
        return verification;
    }

    if (observed.answer_sha256 != capsule.answer_sha256) {
        verification.status = ReplayVerificationStatus::OutputDrift;
        verification.reason = "runtime identity matched but replay answer SHA-256 changed";
        return verification;
    }

    verification.status = ReplayVerificationStatus::ExactMatch;
    verification.reason = "replay matched captured input, hardware, runtime identity, prompt/context and answer hashes";
    return verification;
}

std::string_view to_string(ReplaySourceOutcome outcome) noexcept {
    switch (outcome) {
    case ReplaySourceOutcome::Completed: return "COMPLETED";
    case ReplaySourceOutcome::Failed: return "FAILED";
    }
    return "FAILED";
}

std::string_view to_string(ReplayPreflightStatus status) noexcept {
    switch (status) {
    case ReplayPreflightStatus::Ready: return "READY";
    case ReplayPreflightStatus::InvalidCapsule: return "INVALID_CAPSULE";
    case ReplayPreflightStatus::InputDrift: return "INPUT_DRIFT";
    case ReplayPreflightStatus::HardwareDrift: return "HARDWARE_DRIFT";
    }
    return "INVALID_CAPSULE";
}

std::string_view to_string(ReplayVerificationStatus status) noexcept {
    switch (status) {
    case ReplayVerificationStatus::ExactMatch: return "EXACT_MATCH";
    case ReplayVerificationStatus::ReproducedFailure: return "REPRODUCED_FAILURE";
    case ReplayVerificationStatus::InvalidCapsule: return "INVALID_CAPSULE";
    case ReplayVerificationStatus::InputDrift: return "INPUT_DRIFT";
    case ReplayVerificationStatus::HardwareDrift: return "HARDWARE_DRIFT";
    case ReplayVerificationStatus::RuntimeDrift: return "RUNTIME_DRIFT";
    case ReplayVerificationStatus::OutputDrift: return "OUTPUT_DRIFT";
    case ReplayVerificationStatus::FailureDrift: return "FAILURE_DRIFT";
    case ReplayVerificationStatus::ReplayIncomplete: return "REPLAY_INCOMPLETE";
    }
    return "INVALID_CAPSULE";
}

} // namespace guff
