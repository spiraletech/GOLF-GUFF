#include "guff/artifact_vault.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <system_error>

namespace guff {
namespace {

constexpr std::string_view kModelPrefix = "guff:model:sha256:";

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool equal_ascii_ci(std::string_view lhs, std::string_view rhs) noexcept {
    if (lhs.size() != rhs.size()) return false;
    for (std::size_t i = 0U; i < lhs.size(); ++i) {
        const auto a = static_cast<unsigned char>(lhs[i]);
        const auto b = static_cast<unsigned char>(rhs[i]);
        if (std::tolower(a) != std::tolower(b)) return false;
    }
    return true;
}

void append_field(std::ostringstream& out,
                  std::string_view key,
                  std::string_view value) {
    out << key.size() << ':' << key
        << '=' << value.size() << ':' << value
        << ';';
}

template <typename T>
void append_number(std::ostringstream& out,
                   std::string_view key,
                   T value) {
    append_field(out, key, std::to_string(value));
}

bool canonical_model_id(std::string_view value) noexcept {
    return value.starts_with(kModelPrefix) && is_sha256(value.substr(kModelPrefix.size()));
}

bool safe_relative_filename(std::string_view value) {
    if (value.empty() || value.size() > 4096U) return false;
    const std::filesystem::path path(value);
    if (path.is_absolute()) return false;
    for (const auto& part : path) {
        if (part == "..") return false;
    }
    return !path.filename().empty();
}

bool simple_source_field(std::string_view value, std::size_t max_bytes) noexcept {
    if (value.empty() || value.size() > max_bytes || value.find('\0') != std::string_view::npos) {
        return false;
    }
    return true;
}

bool verify_artifact_file(const ArtifactSpec& spec,
                          const std::filesystem::path& path,
                          std::vector<std::string>* errors) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec) {
        if (errors) errors->emplace_back("artifact is missing or is not a regular file");
        return false;
    }

    const auto size = std::filesystem::file_size(path, ec);
    if (ec) {
        if (errors) errors->emplace_back("unable to read artifact file size");
        return false;
    }
    if (size != spec.file_size_bytes) {
        if (errors) errors->emplace_back("artifact file size does not match specification");
        return false;
    }

    const auto digest = sha256_file(path);
    if (!digest) {
        if (errors) errors->emplace_back("unable to hash artifact file");
        return false;
    }
    if (lower_ascii(*digest) != lower_ascii(spec.sha256)) {
        if (errors) errors->emplace_back("artifact SHA-256 does not match specification");
        return false;
    }
    return true;
}

ResolvedArtifact base_result(const ArtifactSpec& spec) {
    ResolvedArtifact result;
    result.artifact_id = spec.immutable_id();
    result.model_id = spec.model_id;
    result.source = spec.source;
    result.file_size_bytes = spec.file_size_bytes;
    result.sha256 = lower_ascii(spec.sha256);
    return result;
}

} // namespace

std::vector<std::string> ArtifactSourceRef::validate() const {
    std::vector<std::string> errors;
    if (!simple_source_field(provider, 128U)) errors.emplace_back("artifact provider is required and must be <=128 bytes");
    if (!simple_source_field(repository, 1024U)) errors.emplace_back("artifact repository is required and must be <=1024 bytes");
    if (!simple_source_field(revision, 256U)) errors.emplace_back("artifact revision is required and must be <=256 bytes");
    if (!safe_relative_filename(filename)) errors.emplace_back("artifact filename must be a safe relative path");
    return errors;
}

std::string ArtifactSourceRef::canonical_payload() const {
    std::ostringstream out;
    append_field(out, "provider", lower_ascii(provider));
    append_field(out, "repository", repository);
    append_field(out, "revision", revision);
    append_field(out, "filename", std::filesystem::path(filename).generic_string());
    return out.str();
}

std::string ArtifactSourceRef::immutable_id() const {
    return "guff:artifact-source:sha256:" + sha256(canonical_payload());
}

bool ArtifactSourceRef::is_hugging_face() const noexcept {
    return equal_ascii_ci(provider, "huggingface") ||
           equal_ascii_ci(provider, "hugging-face") ||
           equal_ascii_ci(provider, "hf");
}

std::string ArtifactSourceRef::uri() const {
    const auto scheme = is_hugging_face() ? std::string("hf") : lower_ascii(provider);
    return scheme + "://" + repository + "@" + revision + "/" +
           std::filesystem::path(filename).generic_string();
}

std::vector<std::string> ArtifactSpec::validate() const {
    std::vector<std::string> errors;
    if (schema_version != 1U) errors.emplace_back("unsupported artifact specification schema version");
    if (!canonical_model_id(model_id)) errors.emplace_back("artifact model_id must be a canonical GUFF model identity");
    auto source_errors = source.validate();
    errors.insert(errors.end(), source_errors.begin(), source_errors.end());
    if (file_size_bytes == 0U) errors.emplace_back("artifact file_size_bytes must be non-zero");
    if (!is_sha256(sha256)) errors.emplace_back("artifact sha256 must be a SHA-256 digest");
    return errors;
}

std::string ArtifactSpec::canonical_payload() const {
    std::ostringstream out;
    append_number(out, "schema_version", schema_version);
    append_field(out, "model_id", model_id);
    append_field(out, "source_id", source.immutable_id());
    append_number(out, "file_size_bytes", file_size_bytes);
    append_field(out, "sha256", lower_ascii(sha256));
    return out.str();
}

std::string ArtifactSpec::immutable_id() const {
    return "guff:artifact:sha256:" + guff::sha256(canonical_payload());
}

ArtifactSpec artifact_spec_from_model(const ModelManifest& manifest) {
    ArtifactSpec spec;
    spec.model_id = manifest.immutable_id();
    spec.source.provider = manifest.provenance.provider;
    spec.source.repository = manifest.provenance.repository;
    spec.source.revision = manifest.provenance.revision;
    spec.source.filename = manifest.file_name;
    spec.file_size_bytes = manifest.file_size_bytes;
    spec.sha256 = manifest.sha256;
    return spec;
}

bool ResolvedArtifact::ok() const noexcept {
    return status == ArtifactResolveStatus::Resolved &&
           !artifact_id.empty() && !model_id.empty() &&
           !local_path.empty() && errors.empty();
}

ArtifactVault::ArtifactVault(std::filesystem::path root)
    : root_(std::move(root)) {}

const std::filesystem::path& ArtifactVault::root() const noexcept {
    return root_;
}

std::filesystem::path ArtifactVault::cache_path(const ArtifactSpec& spec) const {
    const auto digest = lower_ascii(spec.sha256);
    const auto shard = digest.size() >= 2U ? digest.substr(0U, 2U) : std::string("invalid");
    auto leaf = std::filesystem::path(spec.source.filename).filename();
    if (leaf.empty()) leaf = "artifact.bin";
    return root_ / "sha256" / shard / digest / leaf;
}

ResolvedArtifact ArtifactVault::resolve(const ArtifactSpec& spec,
                                         ArtifactResolveMode mode,
                                         const FetchFunction& fetcher) const {
    auto result = base_result(spec);
    const auto validation = spec.validate();
    if (!validation.empty() || root_.empty() || !root_.is_absolute()) {
        result.status = ArtifactResolveStatus::InvalidSpec;
        result.errors = validation;
        if (root_.empty() || !root_.is_absolute()) {
            result.errors.emplace_back("artifact vault root must be an absolute path");
        }
        return result;
    }

    result.local_path = cache_path(spec);
    std::error_code ec;
    const bool exists = std::filesystem::exists(result.local_path, ec);
    if (ec) {
        result.status = ArtifactResolveStatus::StorageFailed;
        result.errors.emplace_back("unable to inspect artifact vault path");
        return result;
    }
    if (exists) {
        if (!verify_artifact_file(spec, result.local_path, &result.errors)) {
            result.status = ArtifactResolveStatus::VerificationFailed;
            return result;
        }
        result.status = ArtifactResolveStatus::Resolved;
        result.from_cache = true;
        return result;
    }

    if (mode == ArtifactResolveMode::CacheOnly) {
        result.status = ArtifactResolveStatus::CacheMiss;
        result.errors.emplace_back("artifact is not present in the local vault and acquisition is disabled");
        return result;
    }
    if (!fetcher) {
        result.status = ArtifactResolveStatus::FetchUnavailable;
        result.errors.emplace_back("artifact acquisition requested but no provider fetcher was supplied");
        return result;
    }

    const auto parent = result.local_path.parent_path();
    std::filesystem::create_directories(parent, ec);
    if (ec) {
        result.status = ArtifactResolveStatus::StorageFailed;
        result.errors.emplace_back("unable to create artifact vault directory");
        return result;
    }

    const auto partial = parent / (result.local_path.filename().string() + ".partial");
    std::filesystem::remove(partial, ec);
    ec.clear();

    std::string fetch_error;
    bool fetched = false;
    try {
        fetched = fetcher(spec, partial, &fetch_error);
    } catch (...) {
        fetch_error = "artifact fetcher threw an exception";
        fetched = false;
    }
    if (!fetched) {
        std::filesystem::remove(partial, ec);
        result.status = ArtifactResolveStatus::FetchFailed;
        result.errors.emplace_back(fetch_error.empty() ? "artifact fetcher failed" : fetch_error);
        return result;
    }

    if (!verify_artifact_file(spec, partial, &result.errors)) {
        std::filesystem::remove(partial, ec);
        result.status = ArtifactResolveStatus::VerificationFailed;
        return result;
    }

    std::filesystem::rename(partial, result.local_path, ec);
    if (ec) {
        std::filesystem::remove(partial, ec);
        result.status = ArtifactResolveStatus::StorageFailed;
        result.errors.emplace_back("unable to atomically commit verified artifact into the vault");
        return result;
    }

    result.status = ArtifactResolveStatus::Resolved;
    result.acquired = true;
    result.from_cache = false;
    return result;
}

ResolvedArtifact ArtifactVault::resolve_model(const ModelManifest& manifest,
                                               ArtifactResolveMode mode,
                                               const FetchFunction& fetcher) const {
    const auto manifest_errors = manifest.validate();
    if (!manifest_errors.empty()) {
        auto result = base_result(artifact_spec_from_model(manifest));
        result.status = ArtifactResolveStatus::InvalidSpec;
        result.errors = manifest_errors;
        return result;
    }
    return resolve(artifact_spec_from_model(manifest), mode, fetcher);
}

std::string_view to_string(ArtifactResolveMode mode) noexcept {
    switch (mode) {
    case ArtifactResolveMode::CacheOnly: return "CACHE_ONLY";
    case ArtifactResolveMode::AcquireIfMissing: return "ACQUIRE_IF_MISSING";
    }
    return "CACHE_ONLY";
}

std::string_view to_string(ArtifactResolveStatus status) noexcept {
    switch (status) {
    case ArtifactResolveStatus::Resolved: return "RESOLVED";
    case ArtifactResolveStatus::InvalidSpec: return "INVALID_SPEC";
    case ArtifactResolveStatus::CacheMiss: return "CACHE_MISS";
    case ArtifactResolveStatus::FetchUnavailable: return "FETCH_UNAVAILABLE";
    case ArtifactResolveStatus::FetchFailed: return "FETCH_FAILED";
    case ArtifactResolveStatus::VerificationFailed: return "VERIFICATION_FAILED";
    case ArtifactResolveStatus::StorageFailed: return "STORAGE_FAILED";
    }
    return "INVALID_SPEC";
}

} // namespace guff
