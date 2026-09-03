#include "guff/caddy_router.hpp"
#include "guff/model_manifest.hpp"
#include "guff/model_registry.hpp"
#include "guff/scorecard.hpp"
#include "guff/sha256.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

namespace {

std::filesystem::path write_fixture(std::string_view name, std::string_view payload) {
    const auto path = std::filesystem::temp_directory_path() / std::string(name);
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    assert(output);
    output.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    assert(output.good());
    return path;
}

guff::ModelManifest make_manifest(std::string name,
                                  std::string_view payload,
                                  std::uint64_t min_ram_mb,
                                  std::string capability) {
    guff::ModelManifest manifest;
    manifest.display_name = std::move(name);
    manifest.family = "golf-test-family";
    manifest.architecture = "test-transformer";
    manifest.variant = "router-fixture";
    manifest.parameter_count = 1'000'000U;
    manifest.format = guff::ModelFormat::GGUF;
    manifest.quantization = guff::Quantization::Q4_K_M;
    manifest.file_name = manifest.display_name + ".gguf";
    manifest.file_size_bytes = payload.size();
    manifest.sha256 = guff::sha256(payload);
    manifest.provenance = {
        .provider = "GOLF GUFF test",
        .repository = "spiraletech/GOLF-GUFF",
        .revision = "l3-router-fixture",
        .source_filename = "master.safetensors",
        .source_sha256 = guff::sha256(manifest.display_name + "-master"),
    };
    manifest.license = {
        .spdx_id = "MIT",
        .name = "MIT License",
        .commercial_use_allowed = true,
        .redistribution_allowed = true,
    };
    manifest.hardware = {
        .min_ram_mb = min_ram_mb,
        .min_vram_mb = 0U,
        .recommended_threads = 2U,
        .cpu_only_supported = true,
    };
    manifest.capabilities = {std::move(capability)};
    return manifest;
}

guff::BenchmarkRecord benchmark_for(const guff::HardwareProfile& hardware,
                                    std::string run_id,
                                    std::string model_id,
                                    double accuracy,
                                    double generation_tps,
                                    double ttft_ms,
                                    double ram_mb,
                                    std::uint32_t retries,
                                    std::string profile = "cpp-build-repair-v1") {
    guff::BenchmarkRecord record;
    record.run_id = std::move(run_id);
    record.model_id = std::move(model_id);
    record.hardware_id = hardware.immutable_id();
    record.task = guff::TaskClass::Coding;
    record.profile_name = std::move(profile);
    record.context_tokens = 4096U;
    record.output_tokens = 512U;
    record.metrics.prompt_tokens_per_second = generation_tps * 2.0;
    record.metrics.generation_tokens_per_second = generation_tps;
    record.metrics.time_to_first_token_ms = ttft_ms;
    record.metrics.wall_time_ms = 5000.0;
    record.metrics.peak_ram_mb = ram_mb;
    record.metrics.accuracy = accuracy;
    record.metrics.tool_success_rate = accuracy;
    record.metrics.verification_pass_rate = accuracy;
    record.metrics.energy_wh = 1.0;
    record.metrics.retries = retries;
    record.metrics.completed = true;
    return record;
}

} // namespace

int main() {
    guff::HardwareProfile hardware;
    hardware.platform = guff::Platform::Linux;
    hardware.architecture = guff::CpuArchitecture::X86_64;
    hardware.logical_threads = 12U;
    hardware.ram_mb = 16384U;
    hardware.cpu_name = "GOLF L3 TEST CPU";

    const std::string strong_payload = "strong verified club\n";
    const std::string weak_payload = "weak verified club\n";
    const std::string oversized_payload = "oversized verified club\n";

    const auto strong_path = write_fixture("guff-l3-strong.gguf", strong_payload);
    const auto weak_path = write_fixture("guff-l3-weak.gguf", weak_payload);
    const auto oversized_path = write_fixture("guff-l3-oversized.gguf", oversized_payload);

    auto strong = make_manifest("strong", strong_payload, 4096U, "coding");
    auto weak = make_manifest("weak", weak_payload, 2048U, "coding");
    auto oversized = make_manifest("oversized", oversized_payload, 32768U, "coding");
    auto shadow = make_manifest("shadow-unverified", "shadow", 1024U, "coding");

    guff::ModelRegistry registry;
    const auto strong_registration = registry.register_verified(strong, strong_path);
    const auto weak_registration = registry.register_verified(weak, weak_path);
    const auto oversized_registration = registry.register_verified(oversized, oversized_path);
    const auto shadow_registration = registry.register_manifest(shadow);

    assert(strong_registration.ok());
    assert(weak_registration.ok());
    assert(oversized_registration.ok());
    assert(shadow_registration.ok());
    assert(registry.is_verified(strong_registration.immutable_id));
    assert(!registry.is_verified(shadow_registration.immutable_id));
    assert(registry.verified_ids().size() == 3U);

    guff::Scorecard scorecard;
    std::vector<std::string> errors;
    assert(scorecard.add(benchmark_for(hardware, "shadow-best", shadow_registration.immutable_id,
                                       0.995, 120.0, 60.0, 1200.0, 0), &errors));
    assert(scorecard.add(benchmark_for(hardware, "oversized-fast", oversized_registration.immutable_id,
                                       0.99, 100.0, 70.0, 12000.0, 0), &errors));
    assert(scorecard.add(benchmark_for(hardware, "strong-good", strong_registration.immutable_id,
                                       0.94, 46.0, 170.0, 4200.0, 0), &errors));
    assert(scorecard.add(benchmark_for(hardware, "weak-ok", weak_registration.immutable_id,
                                       0.74, 22.0, 700.0, 6900.0, 2), &errors));
    assert(scorecard.add(benchmark_for(hardware, "strong-wrong-profile", strong_registration.immutable_id,
                                       0.99, 90.0, 80.0, 4300.0, 0, "python-edit-v1"), &errors));

    guff::CaddyRouter router(registry, scorecard);
    guff::ModelRouteRequest request;
    request.signal = {
        .intent = "repair a C++ build failure",
        .layer = guff::RealityLayer::Project,
        .complexity = 0.60,
        .uncertainty = 0.20,
        .requires_execution = true,
        .destructive = false,
    };
    request.task = guff::TaskClass::Coding;
    request.profile_name = "cpp-build-repair-v1";
    request.minimum_score = 40.0;

    const auto selected = router.select(request, hardware);
    assert(selected.selected());
    assert(selected.status == guff::ModelRouteStatus::Selected);
    assert(selected.selected_model_id == strong_registration.immutable_id);
    assert(selected.candidates.size() == 2U);
    assert(selected.candidates.front().model_id == strong_registration.immutable_id);
    assert(selected.require_verification);

    auto deterministic_request = request;
    deterministic_request.signal.complexity = 0.10;
    deterministic_request.signal.uncertainty = 0.05;
    const auto deterministic = router.select(deterministic_request, hardware);
    assert(deterministic.status == guff::ModelRouteStatus::DeterministicPreferred);
    assert(!deterministic.selected());

    auto human_request = request;
    human_request.signal.intent = "delete uncertain system state";
    human_request.signal.layer = guff::RealityLayer::OperatingSystem;
    human_request.signal.destructive = true;
    human_request.signal.uncertainty = 0.50;
    const auto human = router.select(human_request, hardware);
    assert(human.status == guff::ModelRouteStatus::HumanReviewRequired);
    assert(!human.selected());

    guff::Scorecard empty_scorecard;
    guff::CaddyRouter empty_router(registry, empty_scorecard);
    const auto no_evidence = empty_router.select(request, hardware);
    assert(no_evidence.status == guff::ModelRouteStatus::NoBenchmarkEvidence);

    std::error_code ec;
    std::filesystem::remove(strong_path, ec);
    std::filesystem::remove(weak_path, ec);
    std::filesystem::remove(oversized_path, ec);
    return 0;
}
