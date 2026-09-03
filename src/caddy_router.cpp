#include "guff/caddy_router.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
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

std::string score_detail(const RankedBenchmark& benchmark) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(2)
        << "score=" << benchmark.score.total
        << " run=" << benchmark.record.run_id;
    return out.str();
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
    decision.trace.add("risk-gate", RouteTraceOutcome::Info,
                       std::string(to_string(decision.task_route.target)) + ": " + decision.task_route.reason);

    if (decision.task_route.target == RouteTarget::HumanReview) {
        decision.status = ModelRouteStatus::HumanReviewRequired;
        decision.reason = "base CADDY risk gate requires human review before model routing";
        decision.trace.add("route-stop", RouteTraceOutcome::Stop, decision.reason);
        return decision;
    }

    if (decision.task_route.target == RouteTarget::DeterministicTool) {
        decision.status = ModelRouteStatus::DeterministicPreferred;
        decision.reason = "base CADDY prefers a deterministic tool; model selection intentionally skipped";
        decision.trace.add("route-stop", RouteTraceOutcome::Stop, decision.reason);
        return decision;
    }

    const auto ranked = scorecard_.rank(request.task, hardware, request.weights);
    if (ranked.empty()) {
        decision.status = ModelRouteStatus::NoBenchmarkEvidence;
        decision.reason = "no SCORECARD evidence exists for this task on this exact hardware identity";
        decision.trace.add("scorecard", RouteTraceOutcome::Stop, decision.reason);
        return decision;
    }
    decision.trace.add("scorecard", RouteTraceOutcome::Pass,
                       "matched benchmark rows=" + std::to_string(ranked.size()));

    const double minimum_score = std::clamp(request.minimum_score, 0.0, 100.0);
    std::unordered_set<std::string> seen_models;

    for (const auto& ranked_benchmark : ranked) {
        const auto& record = ranked_benchmark.record;
        const auto detail = score_detail(ranked_benchmark);
        if (!request.profile_name.empty() && record.profile_name != request.profile_name) {
            decision.trace.add("profile-gate", RouteTraceOutcome::Reject,
                               "benchmark profile mismatch; " + detail, record.model_id);
            continue;
        }
        if (ranked_benchmark.score.total < minimum_score) {
            decision.trace.add("score-gate", RouteTraceOutcome::Reject,
                               "below minimum score; " + detail, record.model_id);
            continue;
        }
        if (!seen_models.emplace(record.model_id).second) {
            decision.trace.add("dedupe-gate", RouteTraceOutcome::Reject,
                               "lower-ranked duplicate model observation; " + detail, record.model_id);
            continue;
        }

        const auto manifest = registry_.find(record.model_id);
        if (!manifest) {
            decision.trace.add("registry-gate", RouteTraceOutcome::Reject,
                               "benchmark model is absent from the current registry; " + detail,
                               record.model_id);
            continue;
        }
        if (request.require_verified && !registry_.is_verified(record.model_id)) {
            decision.trace.add("verification-gate", RouteTraceOutcome::Reject,
                               "model is registered but not cryptographically verified; " + detail,
                               record.model_id);
            continue;
        }
        if (!hardware_compatible(*manifest, hardware)) {
            decision.trace.add("hardware-gate", RouteTraceOutcome::Reject,
                               "manifest hardware contract does not fit current machine; " + detail,
                               record.model_id);
            continue;
        }
        if (!supports_task(*manifest, request.task)) {
            decision.trace.add("capability-gate", RouteTraceOutcome::Reject,
                               "manifest does not declare the required task capability; " + detail,
                               record.model_id);
            continue;
        }

        decision.trace.add("eligibility", RouteTraceOutcome::Pass,
                           "candidate passed all routing gates; " + detail, record.model_id);
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
        decision.trace.add("route-stop", RouteTraceOutcome::Stop, decision.reason);
        return decision;
    }

    const auto& winner = decision.candidates.front();
    decision.status = ModelRouteStatus::Selected;
    decision.selected_model_id = winner.model_id;
    decision.selected_score = winner.score;
    decision.trace.add("selection", RouteTraceOutcome::Select,
                       "highest-scoring eligible candidate", winner.model_id);

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
    decision.trace.add("budget", RouteTraceOutcome::Info,
                       "recursion_depth=" + std::to_string(decision.recursion_depth) +
                       " verify=" + (decision.require_verification ? std::string("yes") : std::string("no")),
                       winner.model_id);
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
