#pragma once

#include "guff/reality.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace guff {

enum class SourceKind : std::uint8_t {
    File,
    RepoFile,
    ToolOutput
};

enum class GrantScope : std::uint8_t {
    Session,
    Project,
    DeviceLocal
};

enum class DeltaState : std::uint8_t {
    FirstSeen,
    Unchanged,
    Modified,
    Missing,
    PermissionDenied,
    TooLarge,
    ReadError
};

struct SourceGrant {
    std::string grant_id;
    SourceKind kind{SourceKind::File};
    GrantScope scope{GrantScope::Session};
    RealityLayer layer{RealityLayer::Project};
    std::filesystem::path root;
    std::string locator_prefix;
    bool recursive{false};
    std::uint64_t max_source_bytes{64U * 1024U * 1024U};
    std::size_t max_slice_bytes{16U * 1024U};

    [[nodiscard]] std::vector<std::string> validate() const;
};

struct SourceObservation {
    std::string source_id;
    SourceKind kind{SourceKind::File};
    RealityLayer layer{RealityLayer::Project};
    std::string locator;
    std::uint64_t size_bytes{0};
    std::string content_sha256;
};

struct SourceDelta {
    DeltaState state{DeltaState::ReadError};
    std::optional<SourceObservation> current;
    std::string previous_sha256;
    std::string detail;

    [[nodiscard]] bool readable() const noexcept;
    [[nodiscard]] bool changed() const noexcept;
};

struct ContextSlice {
    std::string source_id;
    SourceKind kind{SourceKind::File};
    RealityLayer layer{RealityLayer::Project};
    std::string locator;
    std::string content_sha256;
    std::uint64_t offset{0};
    std::string data;
    bool truncated{false};
};

struct ContextBudget {
    std::size_t max_slices{8U};
    std::size_t max_total_bytes{64U * 1024U};
};

class ContextArena {
public:
    explicit ContextArena(ContextBudget budget = {});

    [[nodiscard]] bool add(ContextSlice slice);
    [[nodiscard]] const std::vector<ContextSlice>& slices() const noexcept;
    [[nodiscard]] std::size_t used_bytes() const noexcept;
    [[nodiscard]] std::size_t rejected() const noexcept;
    void clear() noexcept;

private:
    ContextBudget budget_;
    std::vector<ContextSlice> slices_;
    std::size_t used_bytes_{0};
    std::size_t rejected_{0};
};

class DataLeech {
public:
    [[nodiscard]] SourceDelta observe_file(
        const SourceGrant& grant,
        const std::filesystem::path& path,
        const std::optional<SourceObservation>& previous = std::nullopt) const;

    [[nodiscard]] std::optional<ContextSlice> slice_file(
        const SourceGrant& grant,
        const std::filesystem::path& path,
        std::uint64_t offset,
        std::size_t requested_bytes,
        std::string* error = nullptr) const;

    [[nodiscard]] SourceDelta observe_text(
        const SourceGrant& grant,
        std::string_view locator,
        std::string_view content,
        const std::optional<SourceObservation>& previous = std::nullopt) const;

    [[nodiscard]] std::optional<ContextSlice> slice_text(
        const SourceGrant& grant,
        std::string_view locator,
        std::string_view content,
        std::uint64_t offset,
        std::size_t requested_bytes,
        std::string* error = nullptr) const;
};

[[nodiscard]] std::string_view to_string(SourceKind kind) noexcept;
[[nodiscard]] std::string_view to_string(GrantScope scope) noexcept;
[[nodiscard]] std::string_view to_string(DeltaState state) noexcept;

} // namespace guff
