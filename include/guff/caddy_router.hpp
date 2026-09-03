#pragma once

#include "guff/caddy.hpp"
#include "guff/model_registry.hpp"
#include "guff/route_trace.hpp"
#include "guff/scorecard.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class ModelRouteStatus : std::uint8_t {
    Selected,
    DeterministicPreferred,
    HumanReviewRequired,
    NoBenchmarkEvidence,
    NoEligibleModel
};

struct ModelRouteRequest {
    TaskSignal signal;
    TaskClass task{TaskClass::General};
    std::string profile_name;
    ScoreWeights weights{};
    double minimum_score{0.0};
    bool require_verified{true};
};

struct ModelCandidate {
    std::string model_id;
    std::string display_name;
    std::string benchmark_run_id;
    ScorecardScore score;
};

struct ModelRouteDecision {
    ModelRouteStatus status{ModelRouteStatus::NoBenchmarkEvidence};
    RouteDecision task_route;
    std::optional<std::string> selected_model_id;
    std::optional<ScorecardScore> selected_score;
    std::size_t recursion_depth{1};
    bool require_verification{true};
    std::vector<ModelCandidate> candidates;
    RouteTrace trace;
    std::string reason;

    [[nodiscard]] bool selected() const noexcept;
};

class CaddyRouter {
public:
    CaddyRouter(const ModelRegistry& registry, const Scorecard& scorecard) noexcept;

    [[nodiscard]] ModelRouteDecision select(const ModelRouteRequest& request,
                                            const HardwareProfile& hardware) const;

private:
    const ModelRegistry& registry_;
    const Scorecard& scorecard_;
};

[[nodiscard]] std::string_view to_string(ModelRouteStatus status) noexcept;

} // namespace guff
