#pragma once

#include "guff/hardware_profile.hpp"
#include "guff/kernel_task.hpp"
#include "guff/scorecard.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class BenchmarkProofStatus : std::uint8_t {
    Ready,
    InvalidInput,
    TaskIncomplete,
    MissingProcessTelemetry,
    MissingTokenTelemetry
};

struct RunnerTokenTelemetry {
    std::uint64_t prompt_tokens{0U};
    std::uint64_t generated_tokens{0U};
    double prompt_eval_ms{0.0};
    double generation_eval_ms{0.0};
    double time_to_first_token_ms{0.0};

    [[nodiscard]] std::vector<std::string> validate() const;
};

struct BenchmarkCaptureRequest {
    std::string run_id;
    std::string recorded_at_utc;
    std::optional<RunnerTokenTelemetry> token_telemetry;
    double peak_vram_mb{0.0};
    double energy_wh{0.0};
    std::uint32_t retries{0U};
    bool require_process_memory{true};
    bool require_token_telemetry{true};
};

struct KernelBenchmarkProof {
    std::uint32_t schema_version{1U};
    BenchmarkProofStatus status{BenchmarkProofStatus::InvalidInput};
    std::string run_id;
    std::string task_proof_id;
    std::string model_id;
    std::string hardware_id;
    TaskClass task{TaskClass::General};
    std::string profile_name;
    bool first_output_measured{false};
    double time_to_first_output_ms{0.0};
    bool process_memory_measured{false};
    double peak_resident_memory_mb{0.0};
    bool token_telemetry_measured{false};
    std::optional<BenchmarkRecord> scorecard_record;
    std::string reason;

    [[nodiscard]] bool ready() const noexcept;
    [[nodiscard]] std::string canonical_payload() const;
    [[nodiscard]] std::string immutable_id() const;
};

class KernelBenchmarkProbe {
public:
    [[nodiscard]] KernelBenchmarkProof capture(
        const KernelTaskRequest& task_request,
        const KernelTaskResult& task_result,
        const HardwareProfile& hardware,
        const BenchmarkCaptureRequest& capture_request) const;
};

[[nodiscard]] std::string_view to_string(BenchmarkProofStatus status) noexcept;

} // namespace guff
