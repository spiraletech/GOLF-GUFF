#include "guff/caddy_router.hpp"
#include "guff/hardware_profile.hpp"
#include "guff/model_registry.hpp"
#include "guff/reality.hpp"
#include "guff/scorecard.hpp"
#include "guff/scorecard_store.hpp"

#include <filesystem>
#include <iostream>

int main() {
    guff::RealityStack reality;
    reality.observe({guff::RealityLayer::Project, "spiraletech/GOLF-GUFF", "ring", 1.0});
    reality.observe({guff::RealityLayer::Runtime, "native-cpp20", "guff-core", 1.0});
    reality.observe({guff::RealityLayer::Semantic, "persistent-scorecard-route-trace", "L4", 1.0});

    const auto hardware = guff::detect_hardware_profile();
    guff::ModelRegistry registry;
    guff::Scorecard scorecard;
    guff::ScorecardStore store(std::filesystem::path("guff-scorecard.store"));
    guff::CaddyRouter router(registry, scorecard);

    guff::ModelRouteRequest request;
    request.signal = {
        .intent = "select the best verified coding club",
        .layer = guff::RealityLayer::Project,
        .complexity = 0.60,
        .uncertainty = 0.20,
        .requires_execution = true,
        .destructive = false,
    };
    request.task = guff::TaskClass::Coding;
    request.profile_name = "cpp-build-repair-v1";

    const auto decision = router.select(request, hardware);

    std::cout << "GOLF GUFF / RING L4\n";
    std::cout << "REALITY: " << reality.describe() << '\n';
    std::cout << "HARDWARE-ID: " << hardware.immutable_id() << '\n';
    std::cout << "SCORECARD-STORE: " << store.path().string() << " (lazy hydration)\n";
    std::cout << "CADDY-ROUTER: " << guff::to_string(decision.status)
              << " depth=" << decision.recursion_depth
              << " verify=" << (decision.require_verification ? "yes" : "no") << '\n';
    std::cout << "REASON: " << decision.reason << '\n';
    std::cout << "TRACE: " << decision.trace.describe() << '\n';

    if (decision.selected_model_id) {
        std::cout << "MODEL-ID: " << *decision.selected_model_id << '\n';
    } else {
        std::cout << "MODEL-ID: none (hydrate trusted benchmark evidence before selection)\n";
    }

    return 0;
}
