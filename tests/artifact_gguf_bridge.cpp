#include "guff/artifact_vault.hpp"
#include "guff/clubhouse.hpp"
#include "guff/forge.hpp"
#include "guff/gguf_inference.hpp"
#include "guff/model_registry.hpp"
#include "guff/native_process.hpp"
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
    out.write("artifact-bridge", 15);
}

guff::ModelManifest manifest_for(const std::filesystem::path& path) {
    const auto digest = guff::sha256_file(path);
    assert(digest.has_value());
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    assert(!ec);

    guff::ModelManifest manifest;
    manifest.display_name = "Artifact Bridge Stub";
    manifest.family = "guff-test";
    manifest.architecture = "test-transformer";
    manifest.variant = "artifact-bridge";
    manifest.parameter_count = 1U;
    manifest.format = guff::ModelFormat::GGUF;
    manifest.quantization = guff::Quantization::Q4_0;
    manifest.file_name = "model.gguf";
    manifest.file_size_bytes = size;
    manifest.sha256 = *digest;
    manifest.provenance.provider = "huggingface";
    manifest.provenance.repository = "spiraletech/artifact-bridge";
    manifest.provenance.revision = "rev-1";
    manifest.provenance.source_filename = "model.gguf";
    manifest.provenance.source_sha256 = *digest;
    manifest.license.spdx_id = "MIT";
    manifest.license.name = "MIT License";
    manifest.license.commercial_use_allowed = true;
    manifest.license.redistribution_allowed = true;
    manifest.hardware.min_ram_mb = 1U;
    manifest.hardware.recommended_threads = 1U;
    manifest.hardware.cpu_only_supported = true;
    manifest.capabilities = {"chat"};
    return manifest;
}

guff::SlotManifest slot_for() {
    guff::SlotManifest slot;
    slot.slot_name = "model.gguf.artifact-bridge";
    slot.display_name = "Artifact Bridge Slot";
    slot.version = "1.0.0";
    slot.kind = guff::SlotKind::Model;
    slot.transport = guff::SlotTransport::LocalProcess;
    slot.entrypoint = "llama.cpp://llama-cli";
    slot.capabilities = {guff::SlotCapability::ModelInfer};
    slot.allowed_layers = {guff::RealityLayer::Semantic};
    slot.required_permissions = {"model:infer", "device:execute"};
    slot.max_payload_bytes = 4096U;
    return slot;
}

std::string argument_after(int argc, char** argv, std::string_view flag) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string_view(argv[i]) == flag) return argv[i + 1];
    }
    return {};
}

bool is_fake_llama_child(int argc, char** argv) {
    return std::any_of(argv + 1, argv + argc, [](const char* value) {
        return std::string_view(value) == "--model";
    });
}

} // namespace

int main(int argc, char** argv) {
    if (is_fake_llama_child(argc, argv)) {
        const auto prompt = argument_after(argc, argv, "--prompt");
        if (prompt.empty()) return 8;
        std::cout << "VAULT_LLAMA:" << prompt << '\n';
        return 0;
    }

    const auto executable = std::filesystem::absolute(argv[0]);
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-artifact-bridge-regression");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root / "upstream");

    const auto upstream = root / "upstream" / "model.gguf";
    write_stub_gguf(upstream);
    const auto manifest = manifest_for(upstream);
    const auto model_id = manifest.immutable_id();

    guff::ArtifactVault vault(std::filesystem::absolute(root / "vault"));
    const auto artifact = vault.resolve_model(
        manifest,
        guff::ArtifactResolveMode::AcquireIfMissing,
        [&](const guff::ArtifactSpec&, const std::filesystem::path& destination, std::string*) {
            std::error_code copy_ec;
            std::filesystem::copy_file(upstream, destination,
                                       std::filesystem::copy_options::overwrite_existing,
                                       copy_ec);
            return !copy_ec;
        });
    assert(artifact.ok());
    assert(artifact.model_id == model_id);

    guff::ModelRegistry models;
    assert(models.register_verified(manifest, artifact.local_path).ok());
    assert(models.is_verified(model_id));

    guff::ClubhouseRegistry clubhouse;
    const auto slot = slot_for();
    assert(clubhouse.register_slot(slot));

    guff::NativeProcessRegistry processes;
    guff::GgufInferenceBridge bridge(models, processes);
    guff::LlamaCppBindingConfig config;
    config.executable = executable;
    config.working_root = artifact.local_path.parent_path();
    config.profile.context_tokens = 512U;
    config.profile.max_output_tokens = 16U;
    config.profile.threads = 1U;
    config.profile.temperature = 0.0;
    config.profile.top_p = 1.0;
    config.profile.seed = 27;
    config.profile.max_prompt_bytes = 4096U;
    config.profile.verification_mode = guff::GgufVerificationMode::EveryExecution;

    const auto bound = bridge.bind_llama_cpp(slot, model_id, artifact, config);
    assert(bound.ok());

    const std::string prompt = "airplane-mode-cartridge";
    guff::ForgeExecutionRequest request;
    request.invocation.invocation_id = "artifact-bridge-infer";
    request.invocation.slot_id = slot.slot_name;
    request.invocation.capability = guff::SlotCapability::ModelInfer;
    request.invocation.layer = guff::RealityLayer::Semantic;
    request.invocation.input_sha256 = guff::sha256(prompt);
    request.invocation.payload_bytes = prompt.size();
    request.invocation.permission_tokens = {"model:infer", "device:execute"};
    request.payload = prompt;
    request.budget.max_wall_time_ms = 5000U;
    request.budget.max_output_bytes = 4096U;

    guff::ForgeAdapter forge(clubhouse);
    const auto executed = forge.execute(request, bridge);
    assert(executed.succeeded());
    assert(guff::is_sha256(executed.captured_output_sha256));

    std::filesystem::remove_all(root, ec);
    return 0;
}
