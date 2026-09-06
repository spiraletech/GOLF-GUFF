#include "guff/benchmark_probe.hpp"
#include "guff/sha256.hpp"

#include <cassert>
#include <cmath>
#include <string>

namespace {

bool near(double lhs, double rhs, double epsilon = 0.0001) {
    return std::fabs(lhs - rhs) <= epsilon;
}

guff::HardwareProfile hardware() {
    guff::HardwareProfile profile;
    profile.platform = guff::Platform::Linux;
    profile.architecture = guff::CpuArchitecture::X86_64;
    profile.logical_threads = 8U;
    profile.ram_mb = 16384U;
    profile.cpu_name = "l29-test-cpu";
    return profile;
}

guff::KernelTaskRequest task_request() {
    guff::KernelTaskRequest request;
    request.correlation_id = "l29-benchmark-task";
    request.instruction = "Return the deterministic benchmark answer.";
    request.route_request.signal.intent = "benchmark local coding kernel";
    request.route_request.signal.layer = guff::RealityLayer::Project;
    request.route_request.task = guff::TaskClass::Coding;
    request.route_request.profile_name = "kernel-code-q4";
    return request;
}

guff::KernelTaskResult completed_task(const guff::HardwareProfile& profile) {
    guff::KernelTaskResult result;
    result.status = guff::KernelTaskStatus::Completed;

    guff::ForgeExecutionResult execution;
    execution.status = guff::ForgeStatus::Completed;
    execution.invocation_status = guff::InvocationStatus::Ready;
    execution.exit_code = 0;
    execution.wall_time_ms = 500U;
    execution.first_output_observed = true;
    execution.time_to_first_output_ms = 30U;
    execution.process_memory_observed = true;
    execution.peak_resident_memory_bytes = 64U * 1024U * 1024U;
    execution.captured_output_bytes = 10U;
    execution.observed_output_bytes = 10U;
    execution.captured_output_sha256 = guff::sha256("BENCHMARK\n");
    result.execution = execution;

    result.verification.transport_integrity = true;
    result.verification.semantic_verified = true;
    result.verification.confidence = 0.95;
    result.verification.reason = "deterministic verifier passed";
    result.answer = "BENCHMARK\n";

    guff::KernelTaskProvenance provenance;
    provenance.correlation_id = "l29-benchmark-task";
    provenance.model_id = "guff:model:sha256:" + guff::sha256("l29-model");
    provenance.role = guff::KernelRole::Code;
    provenance.cartridge_id = "guff:kernel-cartridge:sha256:" + guff::sha256("cartridge");
    provenance.artifact_id = "guff:artifact:sha256:" + guff::sha256("artifact");
    provenance.source_uri = "hf://spiraletech/l29@deadbeef/model.gguf";
    provenance.binding_id = "guff:gguf-binding:sha256:" + guff::sha256("binding");
    provenance.slot_immutable_id = "guff:slot:sha256:" + guff::sha256("slot");
    provenance.hardware_id = profile.immutable_id();
    provenance.prompt_sha256 = guff::sha256("prompt");
    provenance.context_sha256 = guff::sha256("context");
    provenance.answer_sha256 = guff::sha256(result.answer);
    provenance.route_trace_sha256 = guff::sha256("route");
    provenance.context_slices = 1U;
    provenance.context_bytes = 128U;
    provenance.answer_bytes = result.answer.size();
    provenance.wall_time_ms = execution.wall_time_ms;
    provenance.artifact_from_cache = true;
    provenance.semantic_verified = true;
    result.provenance = provenance;
    return result;
}

} // namespace

int main() {
    const auto profile = hardware();
    const auto request = task_request();
    auto result = completed_task(profile);

    guff::BenchmarkCaptureRequest capture;
    capture.run_id = "l29-course-001";
    capture.recorded_at_utc = "2026-09-06T07:00:00Z";
    capture.token_telemetry = guff::RunnerTokenTelemetry{
        100U,
        20U,
        50.0,
        100.0,
        25.0
    };

    guff::KernelBenchmarkProbe probe;
    const auto proof = probe.capture(request, result, profile, capture);
    assert(proof.ready());
    assert(proof.status == guff::BenchmarkProofStatus::Ready);
    assert(proof.first_output_measured);
    assert(near(proof.time_to_first_output_ms, 30.0));
    assert(proof.process_memory_measured);
    assert(near(proof.peak_resident_memory_mb, 64.0));
    assert(proof.token_telemetry_measured);
    assert(proof.scorecard_record.has_value());
    assert(proof.immutable_id().rfind("guff:benchmark-proof:sha256:", 0U) == 0U);

    const auto& record = *proof.scorecard_record;
    assert(record.model_id == result.provenance->model_id);
    assert(record.hardware_id == profile.immutable_id());
    assert(record.context_tokens == 100U);
    assert(record.output_tokens == 20U);
    assert(near(record.metrics.prompt_tokens_per_second, 2000.0));
    assert(near(record.metrics.generation_tokens_per_second, 200.0));
    assert(near(record.metrics.time_to_first_token_ms, 25.0));
    assert(near(record.metrics.wall_time_ms, 500.0));
    assert(near(record.metrics.peak_ram_mb, 64.0));
    assert(near(record.metrics.accuracy, 0.95));
    assert(record.metrics.tool_success_rate == 1.0);
    assert(record.metrics.verification_pass_rate == 1.0);
    assert(record.metrics.completed);

    guff::Scorecard scorecard;
    assert(scorecard.add(record));
    const auto best = scorecard.best(guff::TaskClass::Coding, profile);
    assert(best.has_value());
    assert(best->record.run_id == capture.run_id);

    auto missing_tokens = capture;
    missing_tokens.run_id = "l29-course-002";
    missing_tokens.token_telemetry.reset();
    const auto refused_tokens = probe.capture(request, result, profile, missing_tokens);
    assert(refused_tokens.status == guff::BenchmarkProofStatus::MissingTokenTelemetry);
    assert(!refused_tokens.scorecard_record.has_value());

    missing_tokens.require_token_telemetry = false;
    const auto partial = probe.capture(request, result, profile, missing_tokens);
    assert(partial.ready());
    assert(!partial.scorecard_record.has_value());
    assert(!partial.token_telemetry_measured);

    auto missing_memory_result = result;
    missing_memory_result.execution->process_memory_observed = false;
    missing_memory_result.execution->peak_resident_memory_bytes = 0U;
    auto missing_memory_capture = capture;
    missing_memory_capture.run_id = "l29-course-003";
    const auto refused_memory = probe.capture(
        request, missing_memory_result, profile, missing_memory_capture);
    assert(refused_memory.status == guff::BenchmarkProofStatus::MissingProcessTelemetry);

    return 0;
}
