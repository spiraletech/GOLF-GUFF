#include "guff/model_manifest.hpp"
#include "guff/model_registry.hpp"
#include "guff/sha256.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <string>

namespace {

guff::ModelManifest make_manifest(const std::string& digest) {
    guff::ModelManifest manifest;
    manifest.display_name = "GOLF Test Club";
    manifest.family = "test-family";
    manifest.architecture = "test-transformer";
    manifest.variant = "q4";
    manifest.parameter_count = 1'000'000U;
    manifest.format = guff::ModelFormat::GGUF;
    manifest.quantization = guff::Quantization::Q4_K_M;
    manifest.file_name = "golf-test.gguf";
    manifest.file_size_bytes = 10U;
    manifest.sha256 = digest;
    manifest.provenance = {
        .provider = "GOLF GUFF test",
        .repository = "spiraletech/GOLF-GUFF",
        .revision = "fixture-v1",
        .source_filename = "master.safetensors",
        .source_sha256 = guff::sha256("upstream-master"),
    };
    manifest.license = {
        .spdx_id = "MIT",
        .name = "MIT License",
        .commercial_use_allowed = true,
        .redistribution_allowed = true,
    };
    manifest.hardware = {
        .min_ram_mb = 512U,
        .min_vram_mb = 0U,
        .recommended_threads = 2U,
        .cpu_only_supported = true,
    };
    manifest.capabilities = {"coding", "reasoning", "coding"};
    manifest.tags = {"test", "local"};
    return manifest;
}

} // namespace

int main() {
    assert(guff::sha256("abc") ==
           "ba7816bf8f01cfea414140de5dae2223"
           "b00361a396177a9cb410ff61f20015ad");

    const std::string payload = "golf guff\n";
    const auto digest = guff::sha256(payload);
    assert(guff::is_sha256(digest));

    const auto temp_path =
        std::filesystem::temp_directory_path() / "guff-model-identity-test.gguf";
    {
        std::ofstream output(temp_path, std::ios::binary | std::ios::trunc);
        assert(output);
        output.write(payload.data(), static_cast<std::streamsize>(payload.size()));
        assert(output.good());
    }

    auto manifest = make_manifest(digest);
    assert(manifest.validate().empty());

    const auto first_id = manifest.immutable_id();
    assert(first_id.rfind("guff:model:sha256:", 0U) == 0U);

    auto reordered = manifest;
    reordered.capabilities = {"reasoning", "coding"};
    reordered.tags = {"local", "test"};
    assert(reordered.immutable_id() == first_id);

    const auto verification = manifest.verify_file(temp_path);
    assert(verification.ok());
    assert(verification.actual_sha256 == digest);
    assert(verification.actual_size_bytes == payload.size());

    auto tampered = manifest;
    tampered.sha256 = guff::sha256("wrong");
    const auto failed_verification = tampered.verify_file(temp_path);
    assert(!failed_verification.ok());
    assert(!failed_verification.hash_matches);

    guff::ModelRegistry registry;
    const auto registered = registry.register_verified(manifest, temp_path);
    assert(registered.ok());
    assert(registered.immutable_id == first_id);
    assert(registry.size() == 1U);

    const auto duplicate = registry.register_verified(manifest, temp_path);
    assert(duplicate.status == guff::RegisterStatus::Duplicate);
    assert(registry.size() == 1U);
    assert(registry.find(first_id).has_value());

    auto invalid = manifest;
    invalid.provenance.revision.clear();
    const auto rejected = registry.register_manifest(invalid);
    assert(rejected.status == guff::RegisterStatus::Invalid);
    assert(!rejected.errors.empty());

    std::error_code ec;
    std::filesystem::remove(temp_path, ec);
    return 0;
}
