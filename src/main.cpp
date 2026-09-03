#include "guff/caddy.hpp"
#include "guff/reality.hpp"
#include "guff/recursor.hpp"

#include <iostream>

int main() {
    guff::RealityStack reality;
    reality.observe({guff::RealityLayer::Project, "spiraletech/GOLF-GUFF", "ring", 1.0});
    reality.observe({guff::RealityLayer::Runtime, "native-cpp20", "guff-core", 1.0});
    reality.observe({guff::RealityLayer::Semantic, "bootstrap", "L0", 1.0});

    guff::Caddy caddy;
    const auto route = caddy.route({
        .intent = "bootstrap the ring",
        .layer = guff::RealityLayer::Project,
        .complexity = 0.45,
        .uncertainty = 0.15,
        .requires_execution = true,
        .destructive = false,
    });

    guff::Recursor recursor({
        .max_depth = route.recursion_depth,
        .max_steps = 8,
        .max_working_items = 24,
        .confidence_stop = 0.90,
    });

    const auto result = recursor.run("observe", [](const guff::RecursionFrame& frame) {
        guff::RecursionFrame next = frame;
        next.depth = frame.depth + 1;
        next.confidence = frame.confidence + 0.48;
        next.state = frame.state == "observe" ? "route" : "verify";
        next.produced_new_information = next.state != "verify" || next.confidence < 0.90;
        return next;
    });

    std::cout << "GOLF GUFF / RING L0\n";
    std::cout << "REALITY: " << reality.describe() << '\n';
    std::cout << "CADDY: " << guff::to_string(route.target)
              << " depth=" << route.recursion_depth
              << " verify=" << (route.require_verification ? "yes" : "no") << '\n';
    std::cout << "RECURSOR: steps=" << result.steps
              << " confidence=" << result.confidence
              << " state=" << result.state << '\n';

    return 0;
}
