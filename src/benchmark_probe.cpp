#include "guff/benchmark_probe.hpp"

#include "guff/sha256.hpp"

#include <cmath>
#include <sstream>

namespace guff {
namespace {

bool finite_nonnegative(double value) noexcept {
    return std::isfinite(value) && value >= 0.0;
}

bool safe_required_text(std::string_view value, std::size_t max_bytes) noexcept {
    return !value.empty() && value.size() <= max_bytes &&
           value.find('\0') == std::string_view::npos;
}

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

double bytes_to_mib(std::uint64_t bytes) noexcept {
    return static_cast<double>(bytes) / (1024.0 * 1024.0);
}

} // namespace

std::vector<std::string> RunnerTokenTelemetry::validate() const {
    std::vector<std::string> errors;
    if (prompt_tokens == 0U) errors.emplace_back("prompt_tokens must be greater than zero");
    if (generated_tokens == 0U) errors.emplace_back("generated_tokens must be greater than zero");
    if (!std::isfinite(prompt_eval_ms) || prompt_eval_ms <= 0.0) {
        errors.emplace_back("prompt_eval_ms must be finite and greater than zero");
    }
    if (!std::isfinite(generation_eval_ms) || generation_eval_ms <= 0.0) {
        errors.emplace_back("generation_eval_ms must be finite and greater than zero");
    }
    if (!finite_nonnegative(time_to_first_token_ms)) {
        errors.emplace_back("time_to_first_token_ms must be finite and non-negative");
    }
    return errors;
}

bool KernelBenchmarkProof::ready() const noexcept {
    return status == BenchmarkProofStatus::Ready;
}

std::string KernelBenchmarkProof::canonical_payload() const {
    std::ostringstream out;
    append_number(out, "schema_version", schema_version);
    append_field(out, "status", to_string(status));
    append_field(out, "run_id", run_id);
    append_field(out, "task_proof_id", task_proof_id);
    append_field(out, "model_id", model_id);
    append_field(out, "hardware_id", hardware_id);
    append_field(out, "task", to_string(task));
    append_field(out, "profile_name", profile_name);
    append_number(out, "first_output_measured", first_output_measured ? 1 : 0);
    append_field(out, "time_to_first_output_ms", std::to_string(time_to_first_output_ms));
    append_number(out, "process_memory_measured", process_memory_measured ? 1 : 0);
    append_field(out, "peak_resident_memory_mb", std::to_string(peak_resident_memory_mb));
    append_number(out, "token_telemetry_measured", token_telemetry_measured ? 1 : 0);

    if (scorecard_record) {
        const auto& record = *scorecard_record;
        append_field(out, "scorecard_run_id", record.run_id);
        append_number(out, "prompt_tokens", record.context_tokens);
        append_number(out, "output_tokens", record.output_tokens);
        append_field(out, "prompt_tps", std::to_string(record.metrics.prompt_tokens_per_second));
        append_field(out, "generation_tps", std::to_string(record.metrics.generation_tokens_per_second));
        append_field(out, "ttft_ms", std::to_string(record.metrics.time_to_first_token_ms));
        append_field(out, "wall_ms", std::to_string(record.metrics.wall_time_ms));
        append_field(out, "peak_ram_mb", std::to_string(record.metrics.peak_ram_mb));
        append_field(out, "peak_vram_mb", std::to_string(record.metrics.peak_vram_mb));
        append_field(out, "verification", std::to_string(record.metrics.verification_pass_rate));
        append_field(out, "energy_wh", std::to_string(record.metrics.energy_wh));
        append_number(out, "retries", record.metrics.retries);
        append_number(out, "completed", record.metrics.completed ? 1 : 0);
    }
    return out.str();
}

std::string KernelBenchmarkProof::immutable_id() const {
    return "guff:benchmark-proof:sha256:" + sha256(canonical_payload());
}

KernelBenchmarkProof KernelBenchmarkProbe::capture(
    const KernelTaskRequest& task_request,
    const KernelTaskResult& task_result,
    const HardwareProfile& hardware,
    const BenchmarkCaptureRequest& capture_request) const {
    KernelBenchmarkProof proof;
    proof.run_id = capture_request.run_id;
    proof.hardware_id = hardware.immutable_id();
    proof.task = task_request.route_request.task;
    proof.profile_name = task_request.route_request.profile_name;

    if (!safe_required_text(capture_request.run_id, 160U) ||
        !safe_required_text(capture_request.recorded_at_utc, 128U) ||
        !finite_nonnegative(capture_request.peak_vram_mb) ||
        !finite_nonnegative(capture_request.energy_wh)) {
        proof.status = BenchmarkProofStatus::InvalidInput;
        proof.reason = "benchmark capture metadata is invalid";
        return proof;
    }

    if (capture_request.token_telemetry &&
        !capture_request.token_telemetry->validate().empty()) {
        proof.status = BenchmarkProofStatus::InvalidInput;
        proof.reason = capture_request.token_telemetry->validate().front();
        return proof;
    }

    if (!task_result.succeeded() || !task_result.execution || !task_result.provenance) {
        proof.status = BenchmarkProofStatus::TaskIncomplete;
        proof.reason = "benchmark proof requires a completed L28 task with execution and provenance";
        return proof;
    }

    proof.task_proof_id = task_result.provenance->immutable_id();
    proof.model_id = task_result.provenance->model_id;
    if (task_result.provenance->hardware_id != proof.hardware_id) {
        proof.status = BenchmarkProofStatus::InvalidInput;
        proof.reason = "task proof hardware identity does not match benchmark hardware";
        return proof;
    }

    const auto& execution = *task_result.execution;
    proof.first_output_measured = execution.first_output_observed;
    proof.time_to_first_output_ms = execution.first_output_observed
        ? static_cast<double>(execution.time_to_first_output_ms)
        : 0.0;
    proof.process_memory_measured = execution.process_memory_observed;
    proof.peak_resident_memory_mb = execution.process_memory_observed
        ? bytes_to_mib(execution.peak_resident_memory_bytes)
        : 0.0;
    proof.token_telemetry_measured = capture_request.token_telemetry.has_value();

    if (capture_request.require_process_memory && !proof.process_memory_measured) {
        proof.status = BenchmarkProofStatus::MissingProcessTelemetry;
        proof.reason = "native runner did not provide peak resident-memory telemetry";
        return proof;
    }
    if (capture_request.require_token_telemetry && !capture_request.token_telemetry) {
        proof.status = BenchmarkProofStatus::MissingTokenTelemetry;
        proof.reason = "exact runner token timing is required; GUFF will not invent token throughput";
        return proof;
    }

    if (capture_request.token_telemetry) {
        const auto& tokens = *capture_request.token_telemetry;
        BenchmarkRecord record;
        record.run_id = capture_request.run_id;
        record.model_id = proof.model_id;
        record.hardware_id = proof.hardware_id;
        record.task = task_request.route_request.task;
        record.profile_name = task_request.route_request.profile_name;
        record.context_tokens = tokens.prompt_tokens;
        record.output_tokens = tokens.generated_tokens;
        record.recorded_at_utc = capture_request.recorded_at_utc;
        record.metrics.prompt_tokens_per_second =
            (static_cast<double>(tokens.prompt_tokens) * 1000.0) / tokens.prompt_eval_ms;
        record.metrics.generation_tokens_per_second =
            (static_cast<double>(tokens.generated_tokens) * 1000.0) / tokens.generation_eval_ms;
        record.metrics.time_to_first_token_ms = tokens.time_to_first_token_ms;
        record.metrics.wall_time_ms = static_cast<double>(execution.wall_time_ms);
        record.metrics.peak_ram_mb = proof.peak_resident_memory_mb;
        record.metrics.peak_vram_mb = capture_request.peak_vram_mb;
        record.metrics.accuracy = task_result.verification.semantic_verified
            ? task_result.verification.confidence
            : 0.0;
        record.metrics.tool_success_rate = execution.succeeded() ? 1.0 : 0.0;
        record.metrics.verification_pass_rate = task_result.verification.semantic_verified ? 1.0 : 0.0;
        record.metrics.energy_wh = capture_request.energy_wh;
        record.metrics.retries = capture_request.retries;
        record.metrics.completed = task_result.succeeded();
        record.tags = {
            "l29",
            "benchmark-proof",
            proof.process_memory_measured ? "process-memory:measured" : "process-memory:unavailable",
            proof.first_output_measured ? "first-output:measured" : "first-output:unavailable",
            "token-telemetry:exact",
            task_result.provenance->artifact_from_cache ? "artifact-cache:hit" : "artifact-cache:miss"
        };

        const auto validation = record.validate();
        if (!validation.empty()) {
            proof.status = BenchmarkProofStatus::InvalidInput;
            proof.reason = validation.front();
            return proof;
        }
        proof.scorecard_record = std::move(record);
    }

    proof.status = BenchmarkProofStatus::Ready;
    proof.reason = proof.scorecard_record
        ? "measured process telemetry and exact runner token timing produced a SCORECARD-ready benchmark proof"
        : "measured process telemetry produced a benchmark proof; token throughput remains intentionally unset";
    return proof;
}

std::string_view to_string(BenchmarkProofStatus status) noexcept {
    switch (status) {
    case BenchmarkProofStatus::Ready: return "READY";
    case BenchmarkProofStatus::InvalidInput: return "INVALID_INPUT";
    case BenchmarkProofStatus::TaskIncomplete: return "TASK_INCOMPLETE";
    case BenchmarkProofStatus::MissingProcessTelemetry: return "MISSING_PROCESS_TELEMETRY";
    case BenchmarkProofStatus::MissingTokenTelemetry: return "MISSING_TOKEN_TELEMETRY";
    }
    return "INVALID_INPUT";
}

} // namespace guff
