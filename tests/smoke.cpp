#include "guff/caddy.hpp"
#include "guff/reality.hpp"
#include "guff/recursor.hpp"

#include <cassert>

int main() {
    guff::RealityStack stack;
    stack.observe({guff::RealityLayer::Project, "repo", "main", 0.8});
    stack.observe({guff::RealityLayer::Project, "repo", "main", 0.95});
    assert(stack.snapshot().size() == 1);
    assert(stack.best(guff::RealityLayer::Project)->confidence == 0.95);

    guff::Caddy caddy;
    const auto deterministic = caddy.route({
        .intent = "compile",
        .layer = guff::RealityLayer::Project,
        .complexity = 0.2,
        .uncertainty = 0.1,
        .requires_execution = true,
        .destructive = false,
    });
    assert(deterministic.target == guff::RouteTarget::DeterministicTool);

    const auto guarded = caddy.route({
        .intent = "delete",
        .layer = guff::RealityLayer::OperatingSystem,
        .complexity = 0.2,
        .uncertainty = 0.5,
        .requires_execution = true,
        .destructive = true,
    });
    assert(guarded.target == guff::RouteTarget::HumanReview);

    guff::Recursor recursor({.max_depth = 3, .max_steps = 5, .max_working_items = 8, .confidence_stop = 0.8});
    const auto result = recursor.run("seed", [](const guff::RecursionFrame& frame) {
        auto next = frame;
        next.depth = frame.depth + 1;
        next.confidence = frame.confidence + 0.45;
        next.state += ":step";
        next.produced_new_information = true;
        return next;
    });

    assert(result.steps == 2);
    assert(result.confidence >= 0.8);
    assert(!result.stopped_by_budget);

    return 0;
}
