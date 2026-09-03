#include "guff/data_leech.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <system_error>

namespace guff {
namespace {

bool file_kind(SourceKind kind) noexcept {
    return kind == SourceKind::File || kind == SourceKind::RepoFile;
}

std::string canonical_string(const std::filesystem::path& path) {
    return path.generic_string();
}

bool path_component_equal(const std::filesystem::path& lhs,
                          const std::filesystem::path& rhs) {
#if defined(_WIN32)
    auto a = lhs.string();
    auto b = rhs.string();
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
#else
    return lhs == rhs;
#endif
}

bool path_equal(const std::filesystem::path& lhs,
                const std::filesystem::path& rhs) {
    auto lhs_it = lhs.begin();
    auto rhs_it = rhs.begin();
    for (; lhs_it != lhs.end() && rhs_it != rhs.end(); ++lhs_it, ++rhs_it) {
        if (!path_component_equal(*lhs_it, *rhs_it)) return false;
    }
    return lhs_it == lhs.end() && rhs_it == rhs.end();
}

bool has_path_prefix(const std::filesystem::path& root,
                     const std::filesystem::path& target) {
    auto root_it = root.begin();
    auto target_it = target.begin();
    for (; root_it != root.end(); ++root_it, ++target_it) {
        if (target_it == target.end() || !path_component_equal(*root_it, *target_it)) return false;
    }
    return true;
}

bool resolve_allowed_file(const SourceGrant& grant,
                          const std::filesystem::path& path,
                          std::filesystem::path* resolved,
                          std::string* error) {
    if (!file_kind(grant.kind)) {
        if (error) *error = "grant kind does not permit file access";
        return false;
    }
    if (!grant.validate().empty()) {
        if (error) *error = "source grant is invalid";
        return false;
    }

    std::error_code ec;
    const auto root = std::filesystem::weakly_canonical(grant.root, ec);
    if (ec) {
        if (error) *error = "unable to resolve grant root";
        return false;
    }
    const auto target = std::filesystem::weakly_canonical(path, ec);
    if (ec) {
        if (error) *error = "unable to resolve requested path";
        return false;
    }

    const bool allowed = grant.recursive ? has_path_prefix(root, target) : path_equal(root, target);
    if (!allowed) {
        if (error) *error = "requested path is outside the granted source scope";
        return false;
    }
    if (resolved) *resolved = target;
    return true;
}

bool allowed_text_locator(const SourceGrant& grant,
                          std::string_view locator,
                          std::string* error) {
    if (grant.kind != SourceKind::ToolOutput) {
        if (error) *error = "grant kind does not permit tool-output access";
        return false;
    }
    if (!grant.validate().empty()) {
        if (error) *error = "source grant is invalid";
        return false;
    }
    if (!locator.starts_with(grant.locator_prefix)) {
        if (error) *error = "tool-output locator is outside the granted prefix";
        return false;
    }
    return true;
}

std::string source_id(const SourceGrant& grant, std::string_view locator) {
    return "guff:source:sha256:" + sha256(grant.grant_id + "\n" + std::string(locator));
}

DeltaState compare_observation(const SourceObservation& current,
                               const std::optional<SourceObservation>& previous) noexcept {
    if (!previous || previous->source_id != current.source_id || previous->locator != current.locator) {
        return DeltaState::FirstSeen;
    }
    return previous->content_sha256 == current.content_sha256 &&
           previous->size_bytes == current.size_bytes
        ? DeltaState::Unchanged
        : DeltaState::Modified;
}

std::size_t bounded_request(const SourceGrant& grant, std::size_t requested) noexcept {
    return std::min(requested, grant.max_slice_bytes);
}

void set_error(std::string* error, std::string value) {
    if (error) *error = std::move(value);
}

} // namespace

std::vector<std::string> SourceGrant::validate() const {
    std::vector<std::string> errors;
    if (grant_id.empty()) errors.emplace_back("grant_id is required");
    if (max_source_bytes == 0) errors.emplace_back("max_source_bytes must be non-zero");
    if (max_slice_bytes == 0) errors.emplace_back("max_slice_bytes must be non-zero");
    if (file_kind(kind)) {
        if (root.empty()) errors.emplace_back("file grants require root");
    } else if (kind == SourceKind::ToolOutput) {
        if (locator_prefix.empty()) errors.emplace_back("tool-output grants require locator_prefix");
    }
    return errors;
}

bool SourceDelta::readable() const noexcept {
    return state == DeltaState::FirstSeen || state == DeltaState::Unchanged || state == DeltaState::Modified;
}

bool SourceDelta::changed() const noexcept {
    return state == DeltaState::FirstSeen || state == DeltaState::Modified;
}

ContextArena::ContextArena(ContextBudget budget) : budget_(budget) {
    budget_.max_slices = std::max<std::size_t>(1U, budget_.max_slices);
    budget_.max_total_bytes = std::max<std::size_t>(1U, budget_.max_total_bytes);
    slices_.reserve(budget_.max_slices);
}

bool ContextArena::add(ContextSlice slice) {
    const auto duplicate = std::any_of(slices_.begin(), slices_.end(), [&](const ContextSlice& existing) {
        return existing.source_id == slice.source_id &&
               existing.content_sha256 == slice.content_sha256 &&
               existing.offset == slice.offset &&
               existing.data.size() == slice.data.size();
    });
    if (duplicate || slices_.size() >= budget_.max_slices ||
        slice.data.size() > (budget_.max_total_bytes - std::min(used_bytes_, budget_.max_total_bytes))) {
        ++rejected_;
        return false;
    }
    used_bytes_ += slice.data.size();
    slices_.push_back(std::move(slice));
    return true;
}

const std::vector<ContextSlice>& ContextArena::slices() const noexcept { return slices_; }
std::size_t ContextArena::used_bytes() const noexcept { return used_bytes_; }
std::size_t ContextArena::rejected() const noexcept { return rejected_; }

void ContextArena::clear() noexcept {
    slices_.clear();
    used_bytes_ = 0;
    rejected_ = 0;
}

SourceDelta DataLeech::observe_file(const SourceGrant& grant,
                                    const std::filesystem::path& path,
                                    const std::optional<SourceObservation>& previous) const {
    SourceDelta delta;
    if (previous) delta.previous_sha256 = previous->content_sha256;

    std::filesystem::path resolved;
    std::string permission_error;
    if (!resolve_allowed_file(grant, path, &resolved, &permission_error)) {
        delta.state = DeltaState::PermissionDenied;
        delta.detail = std::move(permission_error);
        return delta;
    }

    std::error_code ec;
    if (!std::filesystem::is_regular_file(resolved, ec) || ec) {
        delta.state = DeltaState::Missing;
        delta.detail = "requested source is missing or is not a regular file";
        return delta;
    }
    const auto size = std::filesystem::file_size(resolved, ec);
    if (ec) {
        delta.state = DeltaState::ReadError;
        delta.detail = "unable to read source size";
        return delta;
    }
    if (size > grant.max_source_bytes) {
        delta.state = DeltaState::TooLarge;
        delta.detail = "source exceeds granted max_source_bytes";
        return delta;
    }

    const auto digest = sha256_file(resolved);
    if (!digest) {
        delta.state = DeltaState::ReadError;
        delta.detail = "unable to hash source";
        return delta;
    }

    SourceObservation observation;
    observation.kind = grant.kind;
    observation.layer = grant.layer;
    observation.locator = canonical_string(resolved);
    observation.source_id = source_id(grant, observation.locator);
    observation.size_bytes = size;
    observation.content_sha256 = *digest;

    delta.state = compare_observation(observation, previous);
    delta.current = std::move(observation);
    delta.detail = delta.state == DeltaState::Unchanged ? "source content unchanged" : "source content observed";
    return delta;
}

std::optional<ContextSlice> DataLeech::slice_file(const SourceGrant& grant,
                                                  const std::filesystem::path& path,
                                                  std::uint64_t offset,
                                                  std::size_t requested_bytes,
                                                  std::string* error) const {
    if (requested_bytes == 0) {
        set_error(error, "requested_bytes must be non-zero");
        return std::nullopt;
    }

    const auto observed = observe_file(grant, path);
    if (!observed.readable() || !observed.current) {
        set_error(error, observed.detail);
        return std::nullopt;
    }
    const auto& observation = *observed.current;
    if (offset > observation.size_bytes) {
        set_error(error, "offset exceeds source size");
        return std::nullopt;
    }

    const auto remaining = observation.size_bytes - offset;
    const auto amount = static_cast<std::size_t>(std::min<std::uint64_t>(
        static_cast<std::uint64_t>(bounded_request(grant, requested_bytes)), remaining));

    std::ifstream input(std::filesystem::path(observation.locator), std::ios::binary);
    if (!input) {
        set_error(error, "unable to open source for slicing");
        return std::nullopt;
    }
    input.seekg(static_cast<std::streamoff>(offset));
    if (!input) {
        set_error(error, "unable to seek source");
        return std::nullopt;
    }

    std::string data(amount, '\0');
    input.read(data.data(), static_cast<std::streamsize>(amount));
    data.resize(static_cast<std::size_t>(input.gcount()));
    if (data.size() != amount) {
        set_error(error, "unable to read requested source slice");
        return std::nullopt;
    }

    if (error) error->clear();
    return ContextSlice{
        .source_id = observation.source_id,
        .kind = observation.kind,
        .layer = observation.layer,
        .locator = observation.locator,
        .content_sha256 = observation.content_sha256,
        .offset = offset,
        .data = std::move(data),
        .truncated = remaining > amount,
    };
}

SourceDelta DataLeech::observe_text(const SourceGrant& grant,
                                    std::string_view locator,
                                    std::string_view content,
                                    const std::optional<SourceObservation>& previous) const {
    SourceDelta delta;
    if (previous) delta.previous_sha256 = previous->content_sha256;

    std::string permission_error;
    if (!allowed_text_locator(grant, locator, &permission_error)) {
        delta.state = DeltaState::PermissionDenied;
        delta.detail = std::move(permission_error);
        return delta;
    }
    if (content.size() > grant.max_source_bytes) {
        delta.state = DeltaState::TooLarge;
        delta.detail = "tool output exceeds granted max_source_bytes";
        return delta;
    }

    SourceObservation observation;
    observation.source_id = source_id(grant, locator);
    observation.kind = grant.kind;
    observation.layer = grant.layer;
    observation.locator = std::string(locator);
    observation.size_bytes = content.size();
    observation.content_sha256 = sha256(content);

    delta.state = compare_observation(observation, previous);
    delta.current = std::move(observation);
    delta.detail = delta.state == DeltaState::Unchanged ? "source content unchanged" : "source content observed";
    return delta;
}

std::optional<ContextSlice> DataLeech::slice_text(const SourceGrant& grant,
                                                  std::string_view locator,
                                                  std::string_view content,
                                                  std::uint64_t offset,
                                                  std::size_t requested_bytes,
                                                  std::string* error) const {
    if (requested_bytes == 0) {
        set_error(error, "requested_bytes must be non-zero");
        return std::nullopt;
    }
    const auto observed = observe_text(grant, locator, content);
    if (!observed.readable() || !observed.current) {
        set_error(error, observed.detail);
        return std::nullopt;
    }
    if (offset > content.size()) {
        set_error(error, "offset exceeds source size");
        return std::nullopt;
    }

    const auto remaining = content.size() - static_cast<std::size_t>(offset);
    const auto amount = std::min(bounded_request(grant, requested_bytes), remaining);
    if (error) error->clear();
    return ContextSlice{
        .source_id = observed.current->source_id,
        .kind = observed.current->kind,
        .layer = observed.current->layer,
        .locator = observed.current->locator,
        .content_sha256 = observed.current->content_sha256,
        .offset = offset,
        .data = std::string(content.substr(static_cast<std::size_t>(offset), amount)),
        .truncated = remaining > amount,
    };
}

std::string_view to_string(SourceKind kind) noexcept {
    switch (kind) {
    case SourceKind::File: return "file";
    case SourceKind::RepoFile: return "repo-file";
    case SourceKind::ToolOutput: return "tool-output";
    }
    return "file";
}

std::string_view to_string(GrantScope scope) noexcept {
    switch (scope) {
    case GrantScope::Session: return "session";
    case GrantScope::Project: return "project";
    case GrantScope::DeviceLocal: return "device-local";
    }
    return "session";
}

std::string_view to_string(DeltaState state) noexcept {
    switch (state) {
    case DeltaState::FirstSeen: return "FIRST_SEEN";
    case DeltaState::Unchanged: return "UNCHANGED";
    case DeltaState::Modified: return "MODIFIED";
    case DeltaState::Missing: return "MISSING";
    case DeltaState::PermissionDenied: return "PERMISSION_DENIED";
    case DeltaState::TooLarge: return "TOO_LARGE";
    case DeltaState::ReadError: return "READ_ERROR";
    }
    return "READ_ERROR";
}

} // namespace guff
