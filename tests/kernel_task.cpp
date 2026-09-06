#include "guff/artifact_vault.hpp"
#include "guff/caddy_router.hpp"
#include "guff/clubhouse.hpp"
#include "guff/gguf_inference.hpp"
#include "guff/kernel_task.hpp"
#include "guff/model_manifest.hpp"
#include "guff/model_registry.hpp"
#include "guff/native_process.hpp"
#include "guff/scorecard.hpp"
#include "guff/sha256.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>

namespace {

void write_u32_le(std::ofstream& out, std::uint32_t value) {
    for (unsigned shift = 0U; shift < 32U; shift += 8U) {
        out.put(static_cast<char>((value >> shift) & 0xffU));
    }
}

void write_u64_le(std::ofstream& out, std::uint64_t value) {
    for (unsigned shift = 0U; shift < 64U; shift += 8U) {
        out.put(static_cast<char>((value >> shift) & 0xffU));
    }
}

void write_stub_gguf(const std::filesystem::path& path) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    assert(out);
    out.write("GGUF", 4);
    write_u32_le(out, 3U);
    write_u64_le(out, 1U);
    write_u64_le(out, 1U);
    out.write("broly-kernel-payload", 20);
}

std::string argument_after(int argc, char** argv, std::string_view flag) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string_view(argv[i]) == flag) return argv[i + 1];
    }
    return {};
}

bool fake_llama_child(int argc, char** argv) {
    return std::any_of(argv + 1, argv + argc, [](const char* value) {
        return std::string_view(value) == "--model";
    });
}

guff::ModelManifest model_manifest(const std::filesystem::path& path) {
    const auto digest = guff::sha256_file(path);
    assert(digest.has_value());
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    assert(!ec);

    guff::ModelManifest manifest;
    manifest.display_name = "BROLY Code Kernel";
    manifest.family = "broly-guff";
    manifest.architecture = "test-transformer";
    manifest.variant = "kernel.code";
    manifest.parameter_count = 1U;
    manifest.format = guff::ModelFormat::GGUF;
    manifest.quantization = guff::Quantization::Q4_0;
    manifest.file_name = "broly-code.gguf";
    manifest.file_size_bytes = size;
    manifest.sha256 = *digest;
    manifest.provenance.provider = "huggingface";
    manifest.provenance.repository = "spiraletech/broly-code-test";
    manifest.provenance.revision = "deadbeefcafefeed";
    manifest.provenance.source_filename = manifest.file_name;
    manifest.provenance.source_sha256 = *digest;
    manifest.license.spdx_id = "MIT";
    manifest.license.name = "MIT License";
    manifest.license.commercial_use_allowed = true;
    manifest.license.redistribution_allowed = true;
    manifest.hardware.min_ram_mb = 1U;
    manifest.hardware.min_vram_mb = 0U;
    manifest.hardware.recommended_threads = 1U;
    manifest.hardware.cpu_only_supported = true;
    manifest.capabilities = {"coding"};
    manifest.tags = {"gguf", "kernel.code", "offline"};
    return manifest;
}

guff::SlotManifest model_slot() {
    guff::SlotManifest slot;
    slot.slot_name = "kernel.code.broly";
    slot.display_name = "BROLY Code Kernel";
    slot.version = "1.0.0";
    slot.kind = guff::SlotKind::Model;
    slot.transport = guff::SlotTransport::LocalProcess;
    slot.entrypoint = "llama.cpp://llama-cli";
    slot.capabilities = {guff::SlotCapability::ModelInfer};
    slot.allowed_layers = {guff::RealityLayer::Project};
    slot.required_permissions = {"model:infer", "device:execute"};
    slot.max_payload_bytes = 32U * 1024U;
    return slot;
}

guff::HardwareProfile test_hardware() {
    guff::HardwareProfile hardware;
    hardware.platform = guff::Platform::Linux;
    hardware.architecture = guff::CpuArchitecture::X86_64;
    hardware.logical_threads = 4U;
    hardware.ram_mb = 8192U;
    hardware.vram_mb = 0U;
    hardware.gpu_present = false;
    hardware.cpu_name = "guff-test-cpu";
    return hardware;
}

} // namespace

int main(int argc, char** argv) {
    if (fake_llama_child(argc, argv)) {
        const auto prompt = argument_after(argc, argv, "--prompt");
        if (prompt.find("Fix the parser") == std::string::npos) return 41;
        if (prompt.find("int value = 7;") == std::string::npos) return 42;
        std::cout << "BROLY_TASK_OK\n";
        return 0;
    }

    const auto executable = std::filesystem::absolute(argv[0]);
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-kernel-task-regression");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root / "upstream");

    const auto upstream = root / "upstream" / "broly-code.gguf";
    write_stub_gguf(upstream);
    const auto manifest = model_manifest(upstream);
    const auto model_id = manifest.immutable_id();

    guff::ModelRegistry models;
    assert(models.register_verified(manifest, upstream).ok());

    guff::ArtifactVault vault(std::filesystem::absolute(root / "vault"));
    std::size_t fetch_calls = 0U;
    const auto fetcher = [&](const guff::ArtifactSpec&,
                             const std::filesystem::path& destination,
                             std::string* error) {
        ++fetch_calls;
        std::error_code copy_ec;
        std::filesystem::copy_file(upstream, destination,
                                   std::filesystem::copy_options::overwrite_existing,
                                   copy_ec);
        if (copy_ec) {
            if (error) *error = "copy failed";
            return false;
        }
        return true;
    };

    const auto acquired = vault.resolve_model(
        manifest, guff::ArtifactResolveMode::AcquireIfMissing, fetcher);
    assert(acquired.ok());
    assert(fetch_calls == 1U);

    guff::ClubhouseRegistry clubhouse;
    const auto slot = model_slot();
    assert(clubhouse.register_slot(slot));

    guff::NativeProcessRegistry processes;
    guff::GgufInferenceBridge bridge(models, processes);
    guff::LlamaCppBindingConfig binding_config;
    binding_config.executable = executable;
    binding_config.working_root = acquired.local_path.parent_path();
    binding_config.profile.context_tokens = 2048U;
    binding_config.profile.max_output_tokens = 32U;
    binding_config.profile.threads = 1U;
    binding_config.profile.temperature = 0.0;
    binding_config.profile.top_p = 1.0;
    binding_config.profile.seed = 1337;
    binding_config.profile.max_prompt_bytes = 32U * 1024U;
    binding_config.profile.verification_mode = guff::GgufVerificationMode::EveryExecution;
    const auto bound = bridge.bind_llama_cpp(slot, model_id, acquired, binding_config);
    assert(bound.ok());

    const auto hardware = test_hardware();
    guff::Scorecard scorecard;
    guff::BenchmarkRecord benchmark;
    benchmark.run_id = "broly-code-course-001";
    benchmark.model_id = model_id;
    benchmark.hardware_id = hardware.immutable_id();
    benchmark.task = guff::TaskClass::Coding;
    benchmark.profile_name = "broly-code";
    benchmark.context_tokens = 512U;
    benchmark.output_tokens = 64U;
    benchmark.recorded_at_utc = "2026-09-06T00:00:00Z";
    benchmark.metrics.prompt_tokens_per_second = 120.0;
    benchmark.metrics.generation_tokens_per_second = 45.0;
    benchmark.metrics.time_to_first_token_ms = 90.0;
    benchmark.metrics.wall_time_ms = 300.0;
    benchmark.metrics.peak_ram_mb = 512.0;
    benchmark.metrics.accuracy = 0.96;
    benchmark.metrics.tool_success_rate = 0.95;
    benchmark.metrics.verification_pass_rate = 0.98;
    benchmark.metrics.completed = true;
    assert(scorecard.add(benchmark));

    guff::CaddyRouter router(models, scorecard);
    guff::KernelRoster roster;
    guff::KernelCartridge cartridge;
    cartridge.role = guff::KernelRole::Code;
    cartridge.model_id = model_id;
    cartridge.slot_name = slot.slot_name;
    cartridge.tags = {"broly", "coding", "offline"};
    assert(roster.install(cartridge));

    guff::KernelTaskRunner runner(models, router, clubhouse, roster, vault, bridge);

    std::filesystem::remove(upstream, ec);
    assert(!std::filesystem::exists(upstream));

    guff::KernelTaskRequest request;
    request.correlation_id = "broly-l28-task-001";
    request.instruction = "Fix the parser and return only the success marker.";
    request.route_request.signal.intent = "repair local parser";
    request.route_request.signal.layer = guff::RealityLayer::Project;
    request.route_request.signal.complexity = 0.55;
    request.route_request.signal.uncertainty = 0.20;
    request.route_request.signal.requires_execution = false;
    request.route_request.task = guff::TaskClass::Coding;
    request.route_request.profile_name = "broly-code";
    request.route_request.minimum_score = 40.0;
    request.route_request.require_verified = true;
    request.artifact_mode = guff::ArtifactResolveMode::CacheOnly;
    request.context_budget.max_slices = 2U;
    request.context_budget.max_total_bytes = 4096U;
    request.require_semantic_verification = true;
    request.forge_budget.max_wall_time_ms = 5000U;
    request.forge_budget.max_output_bytes = 4096U;

    guff::ContextSlice slice;
    slice.source_id = "guff:source:sha256:" + guff::sha256("parser.cpp");
    slice.kind = guff::SourceKind::RepoFile;
    slice.layer = guff::RealityLayer::Project;
    slice.locator = "src/parser.cpp";
    slice.content_sha256 = guff::sha256("int value = 7;");
    slice.data = "int value = 7;";
    request.context_slices.push_back(slice);

    const auto verifier = [](const guff::KernelTaskRequest&,
                             std::string_view answer) {
        guff::KernelVerification verification;
        verification.semantic_verified = answer == "BROLY_TASK_OK\n";
        verification.confidence = verification.semantic_verified ? 1.0 : 0.0;
        verification.reason = verification.semantic_verified
            ? "expected deterministic test marker observed"
            : "unexpected model response";
        return verification;
    };

    const auto result = runner.run(request, hardware, fetcher, verifier);
    assert(result.succeeded());
    assert(result.status == guff::KernelTaskStatus::Completed);
    assert(result.route.selected_model_id == model_id);
    assert(result.cartridge.has_value());
    assert(result.cartridge->role == guff::KernelRole::Code);
    assert(result.artifact.has_value());
    assert(result.artifact->from_cache);
    assert(!result.artifact->acquired);
    assert(fetch_calls == 1U);
    assert(result.answer == "BROLY_TASK_OK\n");
    assert(result.verification.transport_integrity);
    assert(result.verification.semantic_verified);
    assert(result.provenance.has_value());
    assert(result.provenance->model_id == model_id);
    assert(result.provenance->artifact_id == acquired.artifact_id);
    assert(result.provenance->source_uri.rfind("hf://", 0U) == 0U);
    assert(result.provenance->answer_sha256 == guff::sha256(result.answer));
    assert(result.provenance->immutable_id().rfind("guff:task-proof:sha256:", 0U) == 0U);

    auto no_verifier_request = request;
    no_verifier_request.correlation_id = "broly-l28-task-002";
    const auto no_verifier = runner.run(no_verifier_request, hardware, fetcher);
    assert(no_verifier.status == guff::KernelTaskStatus::VerificationFailed);
    assert(no_verifier.answer.empty());
    assert(no_verifier.provenance.has_value());

    auto overflow_request = request;
    overflow_request.correlation_id = "broly-l28-task-003";
    overflow_request.context_budget.max_total_bytes = 4U;
    const auto overflow = runner.run(overflow_request, hardware, fetcher, verifier);
    assert(overflow.status == guff::KernelTaskStatus::ContextRejected);

    std::filesystem::remove_all(root, ec);
    return 0;
}
