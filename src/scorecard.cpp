#include "guff/scorecard.hpp"
#include "guff/sha256.hpp"

#include <algorithm>
#include <cmath>
#include <utility>

namespace guff {
namespace {

bool finite_nonnegative(double value) noexcept { return std::isfinite(value) && value >= 0.0; }
bool unit_interval(double value) noexcept { return std::isfinite(value) && value >= 0.0 && value <= 1.0; }
double clamp01(double value) noexcept { return std::clamp(value, 0.0, 1.0); }

double saturation(double value, double half_saturation) noexcept {
    if (!finite_nonnegative(value) || value <= 0.0) return 0.0;
    return value / (value + half_saturation);
}

double latency_score(double milliseconds) noexcept {
    if (!finite_nonnegative(milliseconds)) return 0.0;
    return 1.0 / (1.0 + (milliseconds / 1000.0));
}

double memory_headroom(double used_mb, std::uint64_t capacity_mb) noexcept {
    if (capacity_mb == 0 || used_mb <= 0.0) return 0.5;
    return clamp01(1.0 - (used_mb / static_cast<double>(capacity_mb)));
}

bool valid_model_id(std::string_view value) {
    constexpr std::string_view prefix = "guff:model:sha256:";
    return value.starts_with(prefix) && is_sha256(value.substr(prefix.size()));
}

bool valid_hardware_id(std::string_view value) {
    constexpr std::string_view prefix = "guff:hardware:sha256:";
    return value.starts_with(prefix) && is_sha256(value.substr(prefix.size()));
}

} // namespace

std::vector<std::string> BenchmarkRecord::validate() const {
    std::vector<std::string> errors;
    if (schema_version != 1) errors.emplace_back("unsupported benchmark schema_version");
    if (run_id.empty()) errors.emplace_back("run_id is required");
    if (!valid_model_id(model_id)) errors.emplace_back("model_id must be a GOLF immutable model id");
    if (!valid_hardware_id(hardware_id)) errors.emplace_back("hardware_id must be a GOLF immutable hardware id");
    if (profile_name.empty()) errors.emplace_back("profile_name is required");
    if (!finite_nonnegative(metrics.prompt_tokens_per_second)) errors.emplace_back("prompt_tokens_per_second must be finite and non-negative");
    if (!finite_nonnegative(metrics.generation_tokens_per_second)) errors.emplace_back("generation_tokens_per_second must be finite and non-negative");
    if (!finite_nonnegative(metrics.time_to_first_token_ms)) errors.emplace_back("time_to_first_token_ms must be finite and non-negative");
    if (!finite_nonnegative(metrics.wall_time_ms)) errors.emplace_back("wall_time_ms must be finite and non-negative");
    if (!finite_nonnegative(metrics.peak_ram_mb)) errors.emplace_back("peak_ram_mb must be finite and non-negative");
    if (!finite_nonnegative(metrics.peak_vram_mb)) errors.emplace_back("peak_vram_mb must be finite and non-negative");
    if (!unit_interval(metrics.accuracy)) errors.emplace_back("accuracy must be between 0 and 1");
    if (!unit_interval(metrics.tool_success_rate)) errors.emplace_back("tool_success_rate must be between 0 and 1");
    if (!unit_interval(metrics.verification_pass_rate)) errors.emplace_back("verification_pass_rate must be between 0 and 1");
    if (!finite_nonnegative(metrics.energy_wh)) errors.emplace_back("energy_wh must be finite and non-negative");
    return errors;
}

ScorecardScore ScorecardEvaluator::evaluate(const BenchmarkRecord& record,
                                             const HardwareProfile& hardware,
                                             ScoreWeights weights) const {
    ScorecardScore score;

    score.quality = 100.0 * clamp01((record.metrics.accuracy +
                                     record.metrics.tool_success_rate +
                                     record.metrics.verification_pass_rate) / 3.0);

    const double throughput = saturation(record.metrics.generation_tokens_per_second, 30.0);
    const double prompt = saturation(record.metrics.prompt_tokens_per_second, 100.0);
    const double ttft = latency_score(record.metrics.time_to_first_token_ms);
    score.speed = 100.0 * clamp01((0.55 * throughput) + (0.15 * prompt) + (0.30 * ttft));

    const double ram = memory_headroom(record.metrics.peak_ram_mb, hardware.ram_mb);
    double memory = ram;
    if (hardware.gpu_present && hardware.vram_mb > 0) {
        const double vram = memory_headroom(record.metrics.peak_vram_mb, hardware.vram_mb);
        memory = (ram + vram) / 2.0;
    }
    score.memory_efficiency = 100.0 * clamp01(memory);

    const double retry_factor = 1.0 / (1.0 + static_cast<double>(record.metrics.retries));
    const double completion = record.metrics.completed ? 1.0 : 0.0;
    score.reliability = 100.0 * clamp01(completion * retry_factor *
        ((record.metrics.verification_pass_rate + record.metrics.tool_success_rate) / 2.0));

    score.energy_efficiency = record.metrics.energy_wh > 0.0
        ? 100.0 * (1.0 / (1.0 + (record.metrics.energy_wh / 5.0)))
        : 50.0;

    weights.quality = std::max(0.0, weights.quality);
    weights.speed = std::max(0.0, weights.speed);
    weights.memory_efficiency = std::max(0.0, weights.memory_efficiency);
    weights.reliability = std::max(0.0, weights.reliability);
    weights.energy_efficiency = std::max(0.0, weights.energy_efficiency);
    double weight_sum = weights.quality + weights.speed + weights.memory_efficiency +
                        weights.reliability + weights.energy_efficiency;
    if (weight_sum <= 0.0) {
        weights = {};
        weight_sum = 1.0;
    }

    score.total = ((score.quality * weights.quality) +
                   (score.speed * weights.speed) +
                   (score.memory_efficiency * weights.memory_efficiency) +
                   (score.reliability * weights.reliability) +
                   (score.energy_efficiency * weights.energy_efficiency)) / weight_sum;
    return score;
}

bool Scorecard::add(BenchmarkRecord record, std::vector<std::string>* errors) {
    auto validation = record.validate();
    if (std::any_of(records_.begin(), records_.end(), [&](const BenchmarkRecord& existing) {
            return existing.run_id == record.run_id;
        })) {
        validation.emplace_back("run_id already exists");
    }
    if (!validation.empty()) {
        if (errors) *errors = std::move(validation);
        return false;
    }
    records_.push_back(std::move(record));
    if (errors) errors->clear();
    return true;
}

std::vector<RankedBenchmark> Scorecard::rank(TaskClass task,
                                             const HardwareProfile& hardware,
                                             ScoreWeights weights) const {
    const auto hardware_id = hardware.immutable_id();
    ScorecardEvaluator evaluator;
    std::vector<RankedBenchmark> ranked;
    for (const auto& record : records_) {
        if (record.task != task || record.hardware_id != hardware_id) continue;
        ranked.push_back({record, evaluator.evaluate(record, hardware, weights)});
    }
    std::sort(ranked.begin(), ranked.end(), [](const RankedBenchmark& lhs, const RankedBenchmark& rhs) {
        if (lhs.score.total != rhs.score.total) return lhs.score.total > rhs.score.total;
        if (lhs.record.metrics.generation_tokens_per_second != rhs.record.metrics.generation_tokens_per_second) {
            return lhs.record.metrics.generation_tokens_per_second > rhs.record.metrics.generation_tokens_per_second;
        }
        return lhs.record.model_id < rhs.record.model_id;
    });
    return ranked;
}

std::optional<RankedBenchmark> Scorecard::best(TaskClass task,
                                               const HardwareProfile& hardware,
                                               ScoreWeights weights) const {
    auto ranked = rank(task, hardware, weights);
    if (ranked.empty()) return std::nullopt;
    return ranked.front();
}

std::size_t Scorecard::size() const noexcept { return records_.size(); }

std::string_view to_string(TaskClass task) noexcept {
    switch (task) {
    case TaskClass::General: return "general";
    case TaskClass::Chat: return "chat";
    case TaskClass::Coding: return "coding";
    case TaskClass::Reasoning: return "reasoning";
    case TaskClass::ToolUse: return "tool-use";
    case TaskClass::Audio: return "audio";
    case TaskClass::Vision: return "vision";
    case TaskClass::WorldSimulation: return "world-simulation";
    }
    return "general";
}

} // namespace guff
