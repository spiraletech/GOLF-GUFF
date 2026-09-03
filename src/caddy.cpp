#include "guff/caddy.hpp"

#include <algorithm>

namespace guff {

RouteDecision Caddy::route(const TaskSignal& signal) const {
    const double complexity = std::clamp(signal.complexity, 0.0, 1.0);
    const double uncertainty = std::clamp(signal.uncertainty, 0.0, 1.0);

    RouteDecision decision;
    decision.require_verification = signal.requires_execution || uncertainty >= 0.35;

    if (signal.destructive && uncertainty >= 0.20) {
        decision.target = RouteTarget::HumanReview;
        decision.recursion_depth = 1;
        decision.reason = "destructive task with unresolved uncertainty";
        return decision;
    }

    if (signal.requires_execution && complexity < 0.35 && uncertainty < 0.25) {
        decision.target = RouteTarget::DeterministicTool;
        decision.recursion_depth = 1;
        decision.reason = "low-ambiguity executable task; prefer deterministic tool";
        return decision;
    }

    if (complexity < 0.25 && uncertainty < 0.20) {
        decision.target = RouteTarget::LocalTiny;
        decision.recursion_depth = 1;
        decision.reason = "low complexity and low uncertainty";
    } else if (complexity < 0.70 && uncertainty < 0.55) {
        decision.target = RouteTarget::LocalCore;
        decision.recursion_depth = 2;
        decision.reason = "moderate task; core model with bounded recursion";
    } else {
        decision.target = RouteTarget::LocalDeep;
        decision.recursion_depth = 4;
        decision.reason = "high complexity or uncertainty; escalate reasoning budget";
    }

    return decision;
}

const char* to_string(RouteTarget target) noexcept {
    switch (target) {
    case RouteTarget::LocalTiny: return "LOCAL_TINY";
    case RouteTarget::LocalCore: return "LOCAL_CORE";
    case RouteTarget::LocalDeep: return "LOCAL_DEEP";
    case RouteTarget::DeterministicTool: return "DETERMINISTIC_TOOL";
    case RouteTarget::HumanReview: return "HUMAN_REVIEW";
    }
    return "UNKNOWN";
}

} // namespace guff
