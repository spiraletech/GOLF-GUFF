#include "guff/replay_proof.hpp"
#include "guff/sha256.hpp"

#include <cassert>
#include <string>

namespace {

guff::HardwareProfile hardware() {
    guff::HardwareProfile profile;
    profile.platform = guff::Platform::Linux;
    profile.architecture = guff::CpuArchitecture::X86_64;
    profile.logical_threads = 8U;
    profile.ram_mb = 16384U;
    profile.cpu_name = "l30-replay-cpu";
    return profile;
}

guff::KernelTaskRequest request(std::string correlation) {
    guff::KernelTaskRequest value;
    value.correlation_id = std::move(correlation);
    value.instruction = "Return the deterministic replay marker.";
    value.route_request.signal.intent = "replay local kernel";
    value.route_request.signal.layer = guff::RealityLayer::Project;
    value.route_request.signal.complexity = 0.25;
    value.route_request.signal.uncertainty = 0.05;
    value.route_request.task = guff::TaskClass::Coding;
    value.route_request.profile_name = "kernel-code-replay";
    value.route_request.minimum_score = 50.0;
    value.route_request.require_verified = true;
    value.context_budget.max_slices = 2U;
    value.context_budget.max_total_bytes = 4096U;
    value.artifact_mode = guff::ArtifactResolveMode::CacheOnly;
    value.forge_budget.max_wall_time_ms = 5000U;
    value.forge_budget.max_output_bytes = 4096U;
    value.permission_tokens = {"device:execute", "model:infer"};
    value.require_semantic_verification = true;

    guff::ContextSlice slice;
    slice.source_id = "guff:source:sha256:" + guff::sha256("replay.cpp");
    slice.kind = guff::SourceKind::RepoFile;
    slice.layer = guff::RealityLayer::Project;
    slice.locator = "src/replay.cpp";
    slice.content_sha256 = guff::sha256("int replay = 30;");
    slice.data = "int replay = 30;";
    value.context_slices.push_back(slice);
    return value;
}

guff::KernelTaskResult completed(const guff::HardwareProfile& profile,
                                 std::string answer = "L30_REPLAY_OK\n") {
    guff::KernelTaskResult result;
    result.status = guff::KernelTaskStatus::Completed;

    guff::ForgeExecutionResult execution;
    execution.status = guff::ForgeStatus::Completed;
    execution.invocation_status = guff::InvocationStatus::Ready;
    execution.exit_code = 0;
    execution.slot_immutable_id = "guff:slot:sha256:" + guff::sha256("l30-slot");
    execution.wall_time_ms = 42U;
    execution.captured_output_bytes = answer.size();
    execution.observed_output_bytes = answer.size();
    execution.captured_output_sha256 = guff::sha256(answer);
    result.execution = execution;

    result.verification.transport_integrity = true;
    result.verification.semantic_verified = true;
    result.verification.confidence = 1.0;
    result.answer = answer;

    guff::KernelTaskProvenance provenance;
    provenance.correlation_id = "source-correlation";
    provenance.model_id = "guff:model:sha256:" + guff::sha256("l30-model");
    provenance.role = guff::KernelRole::Code;
    provenance.cartridge_id = "guff:kernel-cartridge:sha256:" + guff::sha256("l30-cartridge");
    provenance.artifact_id = "guff:artifact:sha256:" + guff::sha256("l30-artifact");
    provenance.source_uri = "hf://spiraletech/l30@deadbeef/replay.gguf";
    provenance.binding_id = "guff:gguf-binding:sha256:" + guff::sha256("l30-binding");
    provenance.slot_immutable_id = execution.slot_immutable_id;
    provenance.hardware_id = profile.immutable_id();
    provenance.prompt_sha256 = guff::sha256("l30-prompt");
    provenance.context_sha256 = guff::sha256("l30-context");
    provenance.answer_sha256 = guff::sha256(answer);
    provenance.route_trace_sha256 = guff::sha256("l30-route");
    provenance.context_slices = 1U;
    provenance.context_bytes = 16U;
    provenance.answer_bytes = answer.size();
    provenance.wall_time_ms = execution.wall_time_ms;
    provenance.artifact_from_cache = true;
    provenance.semantic_verified = true;
    result.provenance = provenance;
    return result;
}

guff::KernelTaskResult failed(std::string reason = "executor exceeded FORGE wall-time budget") {
    guff::KernelTaskResult result;
    result.status = guff::KernelTaskStatus::ExecutionFailed;
    result.route.status = guff::ModelRouteStatus::Selected;
    result.route.selected_model_id = "guff:model:sha256:" + guff::sha256("l30-model");

    guff::ForgeExecutionResult execution;
    execution.status = guff::ForgeStatus::Timeout;
    execution.invocation_status = guff::InvocationStatus::Ready;
    execution.exit_code = 137;
    execution.slot_immutable_id = "guff:slot:sha256:" + guff::sha256("l30-slot");
    execution.captured_output_sha256 = guff::sha256("partial-output");
    result.execution = execution;
    result.reason = std::move(reason);
    return result;
}

} // namespace

int main() {
    const auto profile = hardware();
    const auto source_request = request("l30-source");
    const auto source_result = completed(profile);

    guff::KernelReplayProof replay;
    const auto capsule = replay.capture(source_request, source_result, profile);
    assert(capsule.has_value());
    assert(capsule->source_outcome == guff::ReplaySourceOutcome::Completed);
    assert(capsule->immutable_id().rfind("guff:replay-capsule:sha256:", 0U) == 0U);

    auto replay_request = request("l30-replay-new-correlation");
    assert(guff::replay_request_contract_sha256(source_request) ==
           guff::replay_request_contract_sha256(replay_request));

    const auto gate = replay.preflight(*capsule, replay_request, profile);
    assert(gate.ready());
    assert(gate.status == guff::ReplayPreflightStatus::Ready);

    auto replay_result = completed(profile);
    replay_result.provenance->correlation_id = replay_request.correlation_id;
    replay_result.provenance->wall_time_ms = 97U;
    replay_result.execution->wall_time_ms = 97U;
    const auto exact = replay.verify(*capsule, replay_request, replay_result, profile);
    assert(exact.matched());
    assert(exact.status == guff::ReplayVerificationStatus::ExactMatch);

    auto drift_request = replay_request;
    drift_request.instruction = "Return a different marker.";
    const auto input_drift = replay.preflight(*capsule, drift_request, profile);
    assert(input_drift.status == guff::ReplayPreflightStatus::InputDrift);

    auto different_hardware = profile;
    different_hardware.logical_threads = 12U;
    const auto hardware_drift = replay.preflight(*capsule, replay_request, different_hardware);
    assert(hardware_drift.status == guff::ReplayPreflightStatus::HardwareDrift);

    auto runtime_drift_result = replay_result;
    runtime_drift_result.provenance->binding_id =
        "guff:gguf-binding:sha256:" + guff::sha256("different-binding");
    const auto runtime_drift = replay.verify(
        *capsule, replay_request, runtime_drift_result, profile);
    assert(runtime_drift.status == guff::ReplayVerificationStatus::RuntimeDrift);

    auto output_drift_result = replay_result;
    output_drift_result.answer = "L30_REPLAY_CHANGED\n";
    output_drift_result.provenance->answer_sha256 = guff::sha256(output_drift_result.answer);
    output_drift_result.execution->captured_output_sha256 =
        guff::sha256(output_drift_result.answer);
    const auto output_drift = replay.verify(
        *capsule, replay_request, output_drift_result, profile);
    assert(output_drift.status == guff::ReplayVerificationStatus::OutputDrift);

    const auto source_failure = failed();
    const auto failure_proof = replay.capture_failure(source_request, source_failure, profile);
    assert(failure_proof.has_value());
    assert(failure_proof->immutable_id().rfind("guff:failure-proof:sha256:", 0U) == 0U);

    const auto failure_capsule = replay.capture(source_request, source_failure, profile);
    assert(failure_capsule.has_value());
    assert(failure_capsule->source_outcome == guff::ReplaySourceOutcome::Failed);
    assert(failure_capsule->source_proof_id == failure_capsule->failure_proof_id);

    const auto reproduced = replay.verify(
        *failure_capsule, replay_request, failed(), profile);
    assert(reproduced.matched());
    assert(reproduced.status == guff::ReplayVerificationStatus::ReproducedFailure);

    const auto changed_failure = replay.verify(
        *failure_capsule,
        replay_request,
        failed("executor failed for a different reason"),
        profile);
    assert(changed_failure.status == guff::ReplayVerificationStatus::FailureDrift);

    const auto unexpected_success = replay.verify(
        *failure_capsule, replay_request, replay_result, profile);
    assert(unexpected_success.status == guff::ReplayVerificationStatus::FailureDrift);

    return 0;
}
