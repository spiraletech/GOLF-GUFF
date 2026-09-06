#include "guff/artifact_vault.hpp"
#include "guff/model_manifest.hpp"
#include "guff/sha256.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <string>

namespace {

guff::ModelManifest manifest_for(const std::filesystem::path& path) {
    const auto digest = guff::sha256_file(path);
    assert(digest.has_value());
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    assert(!ec);

    guff::ModelManifest manifest;
    manifest.display_name = "Vault Test GGUF";
    manifest.family = "guff-test";
    manifest.architecture = "test-transformer";
    manifest.variant = "vault";
    manifest.parameter_count = 1U;
    manifest.format = guff::ModelFormat::GGUF;
    manifest.quantization = guff::Quantization::Q4_0;
    manifest.file_name = "model.gguf";
    manifest.file_size_bytes = size;
    manifest.sha256 = *digest;
    manifest.provenance.provider = "huggingface";
    manifest.provenance.repository = "spiraletech/test-model";
    manifest.provenance.revision = "0123456789abcdef";
    manifest.provenance.source_filename = "model.gguf";
    manifest.provenance.source_sha256 = *digest;
    manifest.license.spdx_id = "MIT";
    manifest.license.name = "MIT License";
    manifest.license.commercial_use_allowed = true;
    manifest.license.redistribution_allowed = true;
    manifest.hardware.min_ram_mb = 1U;
    manifest.hardware.min_vram_mb = 0U;
    manifest.hardware.recommended_threads = 1U;
    manifest.hardware.cpu_only_supported = true;
    manifest.capabilities = {"chat"};
    manifest.tags = {"gguf", "vault"};
    return manifest;
}

} // namespace

int main() {
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-artifact-vault-regression");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root / "upstream");

    const auto upstream = root / "upstream" / "model.gguf";
    {
        std::ofstream out(upstream, std::ios::binary | std::ios::trunc);
        assert(out);
        out << "GGUF-vault-payload";
    }

    const auto manifest = manifest_for(upstream);
    const auto spec = guff::artifact_spec_from_model(manifest);
    assert(spec.validate().empty());
    assert(spec.model_id == manifest.immutable_id());
    assert(spec.source.is_hugging_face());
    assert(spec.source.uri() == "hf://spiraletech/test-model@0123456789abcdef/model.gguf");
    assert(spec.immutable_id().rfind("guff:artifact:sha256:", 0U) == 0U);

    guff::ArtifactVault vault(std::filesystem::absolute(root / "vault"));
    std::size_t fetch_calls = 0U;
    const auto fetcher = [&](const guff::ArtifactSpec& requested,
                             const std::filesystem::path& destination,
                             std::string* error) {
        ++fetch_calls;
        if (requested.immutable_id() != spec.immutable_id()) {
            if (error) *error = "unexpected artifact request";
            return false;
        }
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

    const auto offline_miss = vault.resolve_model(
        manifest, guff::ArtifactResolveMode::CacheOnly, fetcher);
    assert(offline_miss.status == guff::ArtifactResolveStatus::CacheMiss);
    assert(!offline_miss.ok());
    assert(fetch_calls == 0U);

    const auto acquired = vault.resolve_model(
        manifest, guff::ArtifactResolveMode::AcquireIfMissing, fetcher);
    assert(acquired.ok());
    assert(acquired.acquired);
    assert(!acquired.from_cache);
    assert(fetch_calls == 1U);
    assert(std::filesystem::is_regular_file(acquired.local_path));
    assert(acquired.sha256 == manifest.sha256);
    assert(acquired.file_size_bytes == manifest.file_size_bytes);

    std::filesystem::remove(upstream, ec);
    const auto airplane = vault.resolve_model(
        manifest, guff::ArtifactResolveMode::CacheOnly, fetcher);
    assert(airplane.ok());
    assert(airplane.from_cache);
    assert(!airplane.acquired);
    assert(fetch_calls == 1U);
    assert(airplane.local_path == acquired.local_path);

    {
        std::ofstream tamper(acquired.local_path, std::ios::binary | std::ios::app);
        tamper.put('x');
    }
    const auto tampered = vault.resolve_model(
        manifest, guff::ArtifactResolveMode::CacheOnly, fetcher);
    assert(tampered.status == guff::ArtifactResolveStatus::VerificationFailed);
    assert(!tampered.ok());
    assert(fetch_calls == 1U);

    const auto other_root = std::filesystem::absolute(root / "empty-vault");
    guff::ArtifactVault no_fetch_vault(other_root);
    const auto no_fetcher = no_fetch_vault.resolve_model(
        manifest, guff::ArtifactResolveMode::AcquireIfMissing);
    assert(no_fetcher.status == guff::ArtifactResolveStatus::FetchUnavailable);

    std::filesystem::remove_all(root, ec);
    return 0;
}
