#pragma once

#include "guff/hardware_profile.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class TaskClass : std::uint8_t {
    General,
    Chat,
    Coding,
    Reasoning,
    ToolUse,
    Audio,
    Vision,
    WorldSimulation
};

struct BenchmarkMetrics {
    double prompt_tokens_per_second{0.0};
    double generation_tokens_per_second{0.0};
    double time_to_first_token_ms{0.0};
    double wall_time_ms{0.0};
    double peak_ram_mb{0.0};
    double peak_vram_mb{0.0};
    double accuracy{0.0};
    double tool_success_rate{0.0};
    double verification_pass_rate{0.0};
    double energy_wh{0.0};
    std::uint32_t retries{0};
    bool completed{false};
};

struct BenchmarkRecord {
    std::uint32_t schema_version{1};
    std::string run_id;
    std::string model_id;
    std::string hardware_id;
    TaskClass task{TaskClass::General};
    std::string profile_name;
    std::uint64_t context_tokens{0};
    std::uint64_t output_tokens{0};
    std::string recorded_at_utc;
    BenchmarkMetrics metrics;
    std::vector<std::string> tags;

    [[nodiscard]] std::vector<std::string> validate() const;
};

struct ScoreWeights {
    double quality{0.40};
    double speed{0.20};
    double memory_efficiency{0.15};
    double reliability{0.20};
    double energy_efficiency{0.05};
};

struct ScorecardScore {
    double total{0.0};
    double quality{0.0};
    double speed{0.0};
    double memory_efficiency{0.0};
    double reliability{0.0};
    double energy_efficiency{0.0};
};

struct RankedBenchmark {
    BenchmarkRecord record;
    ScorecardScore score;
};

class ScorecardEvaluator {
public:
    [[nodiscard]] ScorecardScore evaluate(const BenchmarkRecord& record,
                                          const HardwareProfile& hardware,
                                          ScoreWeights weights = {}) const;
};

class Scorecard {
public:
    [[nodiscard]] bool add(BenchmarkRecord record, std::vector<std::string>* errors = nullptr);
    [[nodiscard]] std::vector<RankedBenchmark> rank(TaskClass task,
                                                    const HardwareProfile& hardware,
                                                    ScoreWeights weights = {}) const;
    [[nodiscard]] std::optional<RankedBenchmark> best(TaskClass task,
                                                      const HardwareProfile& hardware,
                                                      ScoreWeights weights = {}) const;
    [[nodiscard]] std::size_t size() const noexcept;

private:
    std::vector<BenchmarkRecord> records_;
};

[[nodiscard]] std::string_view to_string(TaskClass task) noexcept;

} // namespace guff
