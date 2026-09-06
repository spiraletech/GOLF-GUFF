#pragma once

#include "guff/model_manifest.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class ArtifactResolveMode : std::uint8_t {
    CacheOnly,
    AcquireIfMissing
};

enum class ArtifactResolveStatus : std::uint8_t {
    Resolved,
    InvalidSpec,
    CacheMiss,
    FetchUnavailable,
    FetchFailed,
    VerificationFailed,
    StorageFailed
};

struct ArtifactSourceRef {
    std::string provider;
    std::string repository;
    std::string revision;
    std::string filename;

    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] std::string canonical_payload() const;
    [[nodiscard]] std::string immutable_id() const;
    [[nodiscard]] std::string uri() const;
    [[nodiscard]] bool is_hugging_face() const noexcept;
};

struct ArtifactSpec {
    std::uint32_t schema_version{1U};
    std::string model_id;
    ArtifactSourceRef source;
    std::uint64_t file_size_bytes{0U};
    std::string sha256;

    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] std::string canonical_payload() const;
    [[nodiscard]] std::string immutable_id() const;
};

[[nodiscard]] ArtifactSpec artifact_spec_from_model(const ModelManifest& manifest);

struct ResolvedArtifact {
    ArtifactResolveStatus status{ArtifactResolveStatus::InvalidSpec};
    std::string artifact_id;
    std::string model_id;
    ArtifactSourceRef source;
    std::filesystem::path local_path;
    std::uint64_t file_size_bytes{0U};
    std::string sha256;
    bool from_cache{false};
    bool acquired{false};
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

class ArtifactVault {
public:
    using FetchFunction = std::function<bool(
        const ArtifactSpec& spec,
        const std::filesystem::path& destination,
        std::string* error)>;

    explicit ArtifactVault(std::filesystem::path root);

    [[nodiscard]] const std::filesystem::path& root() const noexcept;
    [[nodiscard]] std::filesystem::path cache_path(const ArtifactSpec& spec) const;

    [[nodiscard]] ResolvedArtifact resolve(
        const ArtifactSpec& spec,
        ArtifactResolveMode mode = ArtifactResolveMode::CacheOnly,
        const FetchFunction& fetcher = {}) const;

    [[nodiscard]] ResolvedArtifact resolve_model(
        const ModelManifest& manifest,
        ArtifactResolveMode mode = ArtifactResolveMode::CacheOnly,
        const FetchFunction& fetcher = {}) const;

private:
    std::filesystem::path root_;
};

[[nodiscard]] std::string_view to_string(ArtifactResolveMode mode) noexcept;
[[nodiscard]] std::string_view to_string(ArtifactResolveStatus status) noexcept;

} // namespace guff
