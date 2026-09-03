#include "guff/caddy.hpp"
#include "guff/hardware_profile.hpp"
#include "guff/model_manifest.hpp"
#include "guff/reality.hpp"
#include "guff/recursor.hpp"
#include "guff/sha256.hpp"

#include <iostream>

int main() {
    guff::RealityStack reality;
    reality.observe({guff::RealityLayer::Project, "spiraletech/GOLF-GUFF", "ring", 1.0});
    reality.observe({guff::RealityLayer::Runtime, "native-cpp20", "guff-core", 1.0});
    reality.observe({guff::RealityLayer::Semantic, "scorecard", "L2", 1.0});

    guff::Caddy caddy;
    const auto route = caddy.route({
        .intent = "benchmark a verified model on current hardware",
        .layer = guff::RealityLayer::Runtime,
        .complexity = 0.45,
        .uncertainty = 0.10,
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

    guff::ModelManifest manifest;
    manifest.display_name = "GOLF Reference Club";
    manifest.family = "reference";
    manifest.architecture = "placeholder";
    manifest.variant = "identity-demo";
    manifest.parameter_count = 1U;
    manifest.format = guff::ModelFormat::GGUF;
    manifest.quantization = guff::Quantization::Q4_K_M;
    manifest.file_name = "reference.gguf";
    manifest.file_size_bytes = 1U;
    manifest.sha256 = guff::sha256("reference");
    manifest.provenance = {
        .provider = "GOLF GUFF",
        .repository = "spiraletech/GOLF-GUFF",
        .revision = "L2",
        .source_filename = "reference-master",
        .source_sha256 = guff::sha256("reference-master"),
    };
    manifest.license = {
        .spdx_id = "MIT",
        .name = "MIT License",
        .commercial_use_allowed = true,
        .redistribution_allowed = true,
    };
    manifest.hardware = {
        .min_ram_mb = 1U,
        .min_vram_mb = 0U,
        .recommended_threads = 1U,
        .cpu_only_supported = true,
    };

    const auto hardware = guff::detect_hardware_profile();

    std::cout << "GOLF GUFF / RING L2\n";
    std::cout << "REALITY: " << reality.describe() << '\n';
    std::cout << "CADDY: " << guff::to_string(route.target)
              << " depth=" << route.recursion_depth
              << " verify=" << (route.require_verification ? "yes" : "no") << '\n';
    std::cout << "RECURSOR: steps=" << result.steps
              << " confidence=" << result.confidence
              << " state=" << result.state << '\n';
    std::cout << "MODEL-ID: " << manifest.immutable_id() << '\n';
    std::cout << "HARDWARE-ID: " << hardware.immutable_id() << '\n';
    std::cout << "HARDWARE: " << guff::to_string(hardware.platform)
              << '/' << guff::to_string(hardware.architecture)
              << " threads=" << hardware.logical_threads
              << " ram_mb=" << hardware.ram_mb << '\n';

    return 0;
}
