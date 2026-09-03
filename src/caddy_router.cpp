#include "guff/caddy_router.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>
#include <unordered_set>

namespace guff {
namespace {

bool equal_ascii_ci(std::string_view lhs, std::string_view rhs) noexcept {
    if (lhs.size() != rhs.size()) return false;
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        const auto a = static_cast<unsigned char>(lhs[i]);
        const auto b = static_cast<unsigned char>(rhs[i]);
        if (std::tolower(a) != std::tolower(b)) return false;
    }
    return true;
}

std::string_view required_capability(TaskClass task) noexcept {
    switch (task) {
    case TaskClass::General: return {};
    case TaskClass::Chat: return "chat";
    case TaskClass::Coding: return "coding";
    case TaskClass::Reasoning: return "reasoning";
    case TaskClass::ToolUse: return "tool-use";
    case TaskClass::Audio: return "audio";
    case TaskClass::Vision: return "vision";
    case TaskClass::WorldSimulation: return "world-simulation";
    }
    return {};
}

bool supports_task(const ModelManifest& manifest, TaskClass task) noexcept {
    const auto required = required_capability(task);
    if (required.empty()) return true;
    return std::any_of(manifest.capabilities.begin(), manifest.capabilities.end(),
                       [&](const std::string& capability) {
                           return equal_ascii_ci(capability, required);
                       });
}

bool hardware_compatible(const ModelManifest& manifest,
                         const HardwareProfile& hardware) noexcept {
    if (hardware.ram_mb == 0 || manifest.hardware.min_ram_mb > hardware.ram_mb) {
        return false;
    }

    if (!manifest.hardware.cpu_only_supported && !hardware.gpu_present) {
        return false;
    }

    if (manifest.hardware.min_vram_mb > 0) {
        if (!hardware.gpu_present || hardware.vram_mb == 0 ||
            manifest.hardware.min_vram_mb > hardware.vram_mb) {
            return false;
        }
    }

    return true;
}

} // namespace

bool ModelRouteDecision::selected() const noexcept {
    return status == ModelRouteStatus::Selected && selected_model_id.has_value();
}

CaddyRouter::CaddyRouter(const ModelRegistry& registry, const Scorecard& scorecard) noexcept
    : registry_(registry), scorecard_(scorecard) {}

ModelRouteDecision CaddyRouter::select(const ModelRouteRequest& request,
                                       const HardwareProfile& hardware) const {
    ModelRouteDecision decision;
    Caddy caddy;
    decision.task_route = caddy.route(request.signal);
    decision.recursion_depth = decision.task_route.recursion_depth;
    decision.require_verification = decision.task_route.require_verification;

    if (decision.task_route.target == RouteTarget::HumanReview) {
        decision.status = ModelRouteStatus::HumanReviewRequired;
        decision.reason = "base CADDY risk gate requires human review before model routing";
        return decision;
    }

    if (decision.task_route.target == RouteTarget::DeterministicTool) {
        decision.status = ModelRouteStatus::DeterministicPreferred;
        decision.reason = "base CADDY prefers a deterministic tool; model selection intentionally skipped";
        return decision;
    }

    const auto ranked = scorecard_.rank(request.task, hardware, request.weights);
    if (ranked.empty()) {
        decision.status = ModelRouteStatus::NoBenchmarkEvidence;
        decision.reason = "no SCORECARD evidence exists for this task on this exact hardware identity";
        return decision;
    }

    const double minimum_score = std::clamp(request.minimum_score, 0.0, 100.0);
    std::unordered_set<std::string> seen_models;

    for (const auto& ranked_benchmark : ranked) {
        const auto& record = ranked_benchmark.record;
        if (!request.profile_name.empty() && record.profile_name != request.profile_name) {
            continue;
        }
        if (ranked_benchmark.score.total < minimum_score) {
            continue;
        }
        if (!seen_models.emplace(record.model_id).second) {
            continue;
        }

        const auto manifest = registry_.find(record.model_id);
        if (!manifest) {
            continue;
        }
        if (request.require_verified && !registry_.is_verified(record.model_id)) {
            continue;
        }
        if (!hardware_compatible(*manifest, hardware)) {
            continue;
        }
        if (!supports_task(*manifest, request.task)) {
            continue;
        }

        decision.candidates.push_back({
            .model_id = record.model_id,
            .display_name = manifest->display_name,
            .benchmark_run_id = record.run_id,
            .score = ranked_benchmark.score,
        });
    }

    if (decision.candidates.empty()) {
        decision.status = ModelRouteStatus::NoEligibleModel;
        decision.reason = "benchmarks exist, but no model passes registry, verification, capability, hardware, profile and score gates";
        return decision;
    }

    const auto& winner = decision.candidates.front();
    decision.status = ModelRouteStatus::Selected;
    decision.selected_model_id = winner.model_id;
    decision.selected_score = winner.score;

    auto depth = decision.task_route.recursion_depth;
    if (winner.score.total < 55.0) {
        depth += 2;
    } else if (winner.score.total < 70.0) {
        depth += 1;
    } else if (winner.score.total >= 90.0 && request.signal.uncertainty < 0.15 && depth > 1) {
        depth -= 1;
    }
    decision.recursion_depth = std::clamp<std::size_t>(depth, 1U, 6U);
    decision.require_verification = decision.task_route.require_verification ||
                                    request.signal.requires_execution ||
                                    winner.score.total < 85.0;
    decision.reason = "selected the highest-scoring eligible verified model measured on the current task and hardware course";
    return decision;
}

std::string_view to_string(ModelRouteStatus status) noexcept {
    switch (status) {
    case ModelRouteStatus::Selected: return "SELECTED";
    case ModelRouteStatus::DeterministicPreferred: return "DETERMINISTIC_PREFERRED";
    case ModelRouteStatus::HumanReviewRequired: return "HUMAN_REVIEW_REQUIRED";
    case ModelRouteStatus::NoBenchmarkEvidence: return "NO_BENCHMARK_EVIDENCE";
    case ModelRouteStatus::NoEligibleModel: return "NO_ELIGIBLE_MODEL";
    }
    return "NO_BENCHMARK_EVIDENCE";
}

} // namespace guff
