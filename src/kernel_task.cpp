#include "guff/kernel_task.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <sstream>
#include <system_error>
#include <utility>

namespace guff {
namespace {

constexpr std::string_view kModelPrefix = "guff:model:sha256:";

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

bool canonical_model_id(std::string_view value) noexcept {
    return value.starts_with(kModelPrefix) && is_sha256(value.substr(kModelPrefix.size()));
}

bool token_id(std::string_view value) noexcept {
    if (value.empty() || value.size() > 96U) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isalnum(ch) != 0 || ch == '-' || ch == '_' || ch == '.' || ch == ':';
    });
}

bool safe_text(std::string_view value, std::size_t max_bytes) noexcept {
    return !value.empty() && value.size() <= max_bytes &&
           value.find('\0') == std::string_view::npos;
}

std::string context_digest(const ContextArena& arena) {
    std::ostringstream out;
    for (const auto& slice : arena.slices()) {
        append_field(out, "source_id", slice.source_id);
        append_field(out, "locator", slice.locator);
        append_field(out, "content_sha256", slice.content_sha256);
        append_number(out, "offset", slice.offset);
        append_field(out, "slice_sha256", sha256(slice.data));
        append_number(out, "truncated", slice.truncated ? 1 : 0);
    }
    return sha256(out.str());
}

std::string compose_prompt(const KernelTaskRequest& request,
                           const ContextArena& arena) {
    std::ostringstream out;
    out << "GUFF_TASK_V1\n"
        << "intent=" << request.route_request.signal.intent << '\n'
        << "task=" << to_string(request.route_request.task) << '\n'
        << "layer=" << to_string(request.route_request.signal.layer) << '\n'
        << "instruction_sha256=" << sha256(request.instruction) << '\n'
        << "context_slices=" << arena.slices().size() << '\n'
        << "context_bytes=" << arena.used_bytes() << "\n\n"
        << "[INSTRUCTION]\n"
        << request.instruction << "\n[/INSTRUCTION]\n";

    std::size_t index = 0U;
    for (const auto& slice : arena.slices()) {
        out << "\n[CONTEXT " << index++ << "]\n"
            << "source_id=" << slice.source_id << '\n'
            << "locator=" << slice.locator << '\n'
            << "source_sha256=" << slice.content_sha256 << '\n'
            << "offset=" << slice.offset << '\n'
            << "truncated=" << (slice.truncated ? "yes" : "no") << '\n'
            << slice.data << "\n[/CONTEXT]\n";
    }
    return out.str();
}

bool same_path(const std::filesystem::path& lhs,
               const std::filesystem::path& rhs) {
    std::error_code lhs_ec;
    std::error_code rhs_ec;
    const auto a = std::filesystem::weakly_canonical(lhs, lhs_ec);
    const auto b = std::filesystem::weakly_canonical(rhs, rhs_ec);
    return !lhs_ec && !rhs_ec && a == b;
}

std::vector<std::string> validate_request(const KernelTaskRequest& request) {
    std::vector<std::string> errors;
    if (!token_id(request.correlation_id)) {
        errors.emplace_back("correlation_id must be a 1-96 byte token");
    }
    if (!safe_text(request.instruction, 256U * 1024U)) {
        errors.emplace_back("instruction must be 1-262144 bytes and contain no NUL");
    }
    if (request.route_request.profile_name.empty()) {
        errors.emplace_back("route profile_name is required");
    }
    if (request.forge_budget.max_wall_time_ms == 0U ||
        request.forge_budget.max_output_bytes == 0U) {
        errors.emplace_back("FORGE budgets must be non-zero");
    }
    if (request.permission_tokens.empty()) {
        errors.emplace_back("at least one permission token is required");
    }
    return errors;
}

} // namespace

std::vector<std::string> KernelCartridge::validate() const {
    std::vector<std::string> errors;
    if (schema_version != 1U) errors.emplace_back("unsupported kernel cartridge schema_version");
    if (!canonical_model_id(model_id)) errors.emplace_back("kernel cartridge model_id must be canonical");
    if (slot_name.empty() || slot_name.size() > 256U) errors.emplace_back("kernel cartridge slot_name is required and must be <=256 bytes");
    if (tags.size() > 32U) errors.emplace_back("kernel cartridge supports at most 32 tags");
    for (const auto& tag : tags) {
        if (tag.empty() || tag.size() > 128U) {
            errors.emplace_back("kernel cartridge tags must be 1-128 bytes");
            break;
        }
    }
    return errors;
}

std::string KernelCartridge::canonical_payload() const {
    auto ordered_tags = tags;
    std::sort(ordered_tags.begin(), ordered_tags.end());
    std::ostringstream out;
    append_number(out, "schema_version", schema_version);
    append_field(out, "role", to_string(role));
    append_field(out, "model_id", model_id);
    append_field(out, "slot_name", slot_name);
    append_number(out, "enabled", enabled ? 1 : 0);
    for (const auto& tag : ordered_tags) append_field(out, "tag", tag);
    return out.str();
}

std::string KernelCartridge::immutable_id() const {
    return "guff:kernel-cartridge:sha256:" + sha256(canonical_payload());
}

bool KernelRoster::install(KernelCartridge cartridge,
                           std::vector<std::string>* errors) {
    auto validation = cartridge.validate();
    if (by_model_.contains(cartridge.model_id)) {
        validation.emplace_back("model already has a kernel cartridge");
    }
    if (!validation.empty()) {
        if (errors) *errors = std::move(validation);
        return false;
    }
    by_model_.emplace(cartridge.model_id, std::move(cartridge));
    if (errors) errors->clear();
    return true;
}

std::optional<KernelCartridge> KernelRoster::find_model(std::string_view model_id) const {
    const auto found = by_model_.find(std::string(model_id));
    if (found == by_model_.end() || !found->second.enabled) return std::nullopt;
    return found->second;
}

std::vector<KernelCartridge> KernelRoster::list(KernelRole role) const {
    std::vector<KernelCartridge> result;
    for (const auto& [_, cartridge] : by_model_) {
        if (cartridge.enabled && cartridge.role == role) result.push_back(cartridge);
    }
    std::sort(result.begin(), result.end(), [](const KernelCartridge& lhs,
                                               const KernelCartridge& rhs) {
        if (lhs.slot_name != rhs.slot_name) return lhs.slot_name < rhs.slot_name;
        return lhs.model_id < rhs.model_id;
    });
    return result;
}

std::size_t KernelRoster::size() const noexcept { return by_model_.size(); }

bool KernelVerification::accepted(bool semantic_required) const noexcept {
    return transport_integrity && (!semantic_required || semantic_verified);
}

std::string KernelTaskProvenance::canonical_payload() const {
    std::ostringstream out;
    append_number(out, "schema_version", schema_version);
    append_field(out, "correlation_id", correlation_id);
    append_field(out, "model_id", model_id);
    append_field(out, "role", to_string(role));
    append_field(out, "cartridge_id", cartridge_id);
    append_field(out, "artifact_id", artifact_id);
    append_field(out, "source_uri", source_uri);
    append_field(out, "binding_id", binding_id);
    append_field(out, "slot_immutable_id", slot_immutable_id);
    append_field(out, "hardware_id", hardware_id);
    append_field(out, "prompt_sha256", prompt_sha256);
    append_field(out, "context_sha256", context_sha256);
    append_field(out, "answer_sha256", answer_sha256);
    append_field(out, "route_trace_sha256", route_trace_sha256);
    append_number(out, "context_slices", context_slices);
    append_number(out, "context_bytes", context_bytes);
    append_number(out, "answer_bytes", answer_bytes);
    append_number(out, "wall_time_ms", wall_time_ms);
    append_number(out, "artifact_from_cache", artifact_from_cache ? 1 : 0);
    append_number(out, "semantic_verified", semantic_verified ? 1 : 0);
    return out.str();
}

std::string KernelTaskProvenance::immutable_id() const {
    return "guff:task-proof:sha256:" + sha256(canonical_payload());
}

bool KernelTaskResult::succeeded() const noexcept {
    return status == KernelTaskStatus::Completed &&
           execution.has_value() && execution->succeeded();
}

KernelTaskRunner::KernelTaskRunner(const ModelRegistry& models,
                                   const CaddyRouter& router,
                                   const ClubhouseRegistry& clubhouse,
                                   const KernelRoster& roster,
                                   const ArtifactVault& vault,
                                   const GgufInferenceBridge& bridge) noexcept
    : models_(models),
      router_(router),
      clubhouse_(clubhouse),
      roster_(roster),
      vault_(vault),
      bridge_(bridge) {}

KernelTaskResult KernelTaskRunner::run(
    const KernelTaskRequest& request,
    const HardwareProfile& hardware,
    const ArtifactVault::FetchFunction& fetcher,
    const SemanticVerifier& verifier) const {
    KernelTaskResult result;

    const auto request_errors = validate_request(request);
    if (!request_errors.empty()) {
        result.status = KernelTaskStatus::InvalidRequest;
        result.reason = request_errors.front();
        return result;
    }

    result.route = router_.select(request.route_request, hardware);
    if (!result.route.selected() || !result.route.selected_model_id) {
        result.status = KernelTaskStatus::RouteRejected;
        result.reason = "CADDY did not select an autonomous local model: " +
                        std::string(to_string(result.route.status));
        return result;
    }

    const auto model_id = *result.route.selected_model_id;
    const auto cartridge = roster_.find_model(model_id);
    if (!cartridge) {
        result.status = KernelTaskStatus::KernelUnavailable;
        result.reason = "selected model is not installed in the mini-kernel roster";
        return result;
    }
    result.cartridge = *cartridge;

    const auto manifest = models_.find(model_id);
    if (!manifest || !models_.is_verified(model_id)) {
        result.status = KernelTaskStatus::KernelUnavailable;
        result.reason = "selected kernel is absent from the verified model registry";
        return result;
    }

    auto artifact = vault_.resolve_model(*manifest, request.artifact_mode, fetcher);
    result.artifact = artifact;
    if (!artifact.ok()) {
        result.status = KernelTaskStatus::ArtifactUnavailable;
        result.reason = artifact.errors.empty()
            ? "selected kernel artifact is unavailable"
            : artifact.errors.front();
        return result;
    }

    const auto slot = clubhouse_.find(cartridge->slot_name);
    if (!slot || slot->kind != SlotKind::Model ||
        !slot->supports(SlotCapability::ModelInfer)) {
        result.status = KernelTaskStatus::KernelUnavailable;
        result.reason = "kernel cartridge does not resolve to a MODEL_INFER slot";
        return result;
    }

    const auto binding = bridge_.find_binding(slot->immutable_id());
    if (!binding || binding->model_id != model_id ||
        binding->model_sha256 != artifact.sha256 ||
        !same_path(binding->model_path, artifact.local_path)) {
        result.status = KernelTaskStatus::BindingMismatch;
        result.reason = "selected kernel, cached artifact and llama.cpp binding are not the same immutable model";
        return result;
    }

    ContextArena arena(request.context_budget);
    for (const auto& slice : request.context_slices) {
        if (!arena.add(slice)) {
            result.status = KernelTaskStatus::ContextRejected;
            result.reason = "context slice exceeds the bounded L28 context arena or duplicates an existing slice";
            return result;
        }
    }

    const auto prompt = compose_prompt(request, arena);
    if (prompt.empty() || prompt.size() > slot->max_payload_bytes ||
        prompt.size() > binding->profile.max_prompt_bytes) {
        result.status = KernelTaskStatus::ContextRejected;
        result.reason = "composed task prompt exceeds the selected kernel payload ceiling";
        return result;
    }

    ForgeExecutionRequest forge_request;
    forge_request.invocation.invocation_id = request.correlation_id + ":model-infer";
    forge_request.invocation.slot_id = cartridge->slot_name;
    forge_request.invocation.capability = SlotCapability::ModelInfer;
    forge_request.invocation.layer = request.route_request.signal.layer;
    forge_request.invocation.input_sha256 = sha256(prompt);
    forge_request.invocation.payload_bytes = prompt.size();
    forge_request.invocation.permission_tokens = request.permission_tokens;
    forge_request.payload = prompt;
    forge_request.budget = request.forge_budget;

    const auto slot_resolution = clubhouse_.resolve(forge_request.invocation);
    if (!slot_resolution.ready()) {
        result.status = KernelTaskStatus::InvocationRejected;
        result.reason = slot_resolution.reason;
        return result;
    }

    std::string transient_answer;
    ForgeAdapter forge(clubhouse_);
    const auto execution = forge.execute(
        forge_request,
        [&](const SlotManifest& executing_slot,
            const ForgeExecutionRequest& executing_request,
            ForgeOutputSink& output) {
            const auto report = bridge_(executing_slot, executing_request, output);
            transient_answer.assign(output.captured());
            return report;
        });
    result.execution = execution;

    if (!execution.succeeded()) {
        transient_answer.clear();
        result.status = KernelTaskStatus::ExecutionFailed;
        result.reason = execution.reason;
        return result;
    }

    const auto answer_sha = sha256(transient_answer);
    result.verification.transport_integrity =
        !transient_answer.empty() &&
        !execution.output_truncated &&
        execution.captured_output_bytes == transient_answer.size() &&
        execution.captured_output_sha256 == answer_sha;
    result.verification.confidence = result.verification.transport_integrity ? 1.0 : 0.0;
    result.verification.reason = result.verification.transport_integrity
        ? "FORGE delivery bytes match the execution SHA-256"
        : "FORGE delivery integrity check failed";

    if (verifier && result.verification.transport_integrity) {
        auto semantic = verifier(request, transient_answer);
        result.verification.semantic_verified = semantic.semantic_verified;
        result.verification.confidence = std::clamp(semantic.confidence, 0.0, 1.0);
        if (!semantic.reason.empty()) result.verification.reason = std::move(semantic.reason);
    }

    KernelTaskProvenance provenance;
    provenance.correlation_id = request.correlation_id;
    provenance.model_id = model_id;
    provenance.role = cartridge->role;
    provenance.cartridge_id = cartridge->immutable_id();
    provenance.artifact_id = artifact.artifact_id;
    provenance.source_uri = artifact.source.uri();
    provenance.binding_id = binding->immutable_id();
    provenance.slot_immutable_id = slot->immutable_id();
    provenance.hardware_id = hardware.immutable_id();
    provenance.prompt_sha256 = sha256(prompt);
    provenance.context_sha256 = context_digest(arena);
    provenance.answer_sha256 = answer_sha;
    provenance.route_trace_sha256 = sha256(result.route.trace.describe());
    provenance.context_slices = arena.slices().size();
    provenance.context_bytes = arena.used_bytes();
    provenance.answer_bytes = transient_answer.size();
    provenance.wall_time_ms = execution.wall_time_ms;
    provenance.artifact_from_cache = artifact.from_cache;
    provenance.semantic_verified = result.verification.semantic_verified;
    result.provenance = std::move(provenance);

    if (!result.verification.accepted(request.require_semantic_verification)) {
        transient_answer.clear();
        result.status = KernelTaskStatus::VerificationFailed;
        result.reason = request.require_semantic_verification && !verifier
            ? "semantic verification was required but no verifier was supplied"
            : result.verification.reason;
        return result;
    }

    result.answer = std::move(transient_answer);
    result.status = KernelTaskStatus::Completed;
    result.reason = "CADDY selected a verified cached mini-kernel and GUFF completed the bounded local inference task";
    return result;
}

std::string_view to_string(KernelRole role) noexcept {
    switch (role) {
    case KernelRole::Router: return "kernel.router";
    case KernelRole::Fast: return "kernel.fast";
    case KernelRole::Code: return "kernel.code";
    case KernelRole::World: return "kernel.world";
    case KernelRole::Media: return "kernel.media";
    case KernelRole::Deep: return "kernel.deep";
    }
    return "kernel.fast";
}

std::string_view to_string(KernelTaskStatus status) noexcept {
    switch (status) {
    case KernelTaskStatus::Completed: return "COMPLETED";
    case KernelTaskStatus::InvalidRequest: return "INVALID_REQUEST";
    case KernelTaskStatus::RouteRejected: return "ROUTE_REJECTED";
    case KernelTaskStatus::KernelUnavailable: return "KERNEL_UNAVAILABLE";
    case KernelTaskStatus::ArtifactUnavailable: return "ARTIFACT_UNAVAILABLE";
    case KernelTaskStatus::BindingMismatch: return "BINDING_MISMATCH";
    case KernelTaskStatus::ContextRejected: return "CONTEXT_REJECTED";
    case KernelTaskStatus::InvocationRejected: return "INVOCATION_REJECTED";
    case KernelTaskStatus::ExecutionFailed: return "EXECUTION_FAILED";
    case KernelTaskStatus::VerificationFailed: return "VERIFICATION_FAILED";
    }
    return "INVALID_REQUEST";
}

} // namespace guff
