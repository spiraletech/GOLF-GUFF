#pragma once

#include "guff/reality.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace guff {

enum class RouteTarget {
    LocalTiny,
    LocalCore,
    LocalDeep,
    DeterministicTool,
    HumanReview
};

struct TaskSignal {
    std::string intent;
    RealityLayer layer{RealityLayer::Semantic};
    double complexity{0.0};
    double uncertainty{0.0};
    bool requires_execution{false};
    bool destructive{false};
};

struct RouteDecision {
    RouteTarget target{RouteTarget::LocalCore};
    std::size_t recursion_depth{1};
    bool require_verification{true};
    std::string reason;
};

class Caddy {
public:
    [[nodiscard]] RouteDecision route(const TaskSignal& signal) const;
};

[[nodiscard]] const char* to_string(RouteTarget target) noexcept;

} // namespace guff
