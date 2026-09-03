#pragma once

#include "guff/data_leech.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace guff {

enum class GrantState : std::uint8_t {
    Active,
    Pending,
    Revoked,
    Expired,
    Missing
};

enum class LedgerStatus : std::uint8_t {
    Ok,
    Duplicate,
    Invalid,
    NotFound,
    Inactive,
    Denied,
    StorageError
};

struct RetentionPolicy {
    bool persist_grant{false};
    bool persist_observation_stamps{false};
    bool allow_memory_promotion{false};
    std::size_t max_promotion_bytes{2048U};
    std::size_t max_observation_stamps{256U};
};

struct SymbiosisGrant {
    SourceGrant source;
    RetentionPolicy retention;
    std::uint64_t issued_at_unix_ms{0};
    std::uint64_t expires_at_unix_ms{0};

    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] bool expired(std::uint64_t now_unix_ms) const noexcept;
};

struct ObservationStamp {
    std::string grant_id;
    std::string source_id;
    std::string content_sha256;
    std::uint64_t size_bytes{0};
    RealityLayer layer{RealityLayer::Project};
    std::uint64_t observed_at_unix_ms{0};
};

struct MemoryPromotion {
    std::string promotion_id;
    std::string grant_id;
    std::string source_id;
    std::string content_sha256;
    RealityLayer layer{RealityLayer::Memory};
    std::string summary;
    std::uint64_t promoted_at_unix_ms{0};
    bool forgotten{false};
};

struct LedgerResult {
    LedgerStatus status{LedgerStatus::Invalid};
    std::string id;
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

class SymbiosisLedger {
public:
    explicit SymbiosisLedger(std::filesystem::path journal_path = {});

    [[nodiscard]] LedgerResult create_grant(SymbiosisGrant grant);
    [[nodiscard]] LedgerResult revoke_grant(std::string_view grant_id,
                                            std::uint64_t now_unix_ms,
                                            std::string reason = {});

    [[nodiscard]] GrantState grant_state(std::string_view grant_id,
                                         std::uint64_t now_unix_ms) const noexcept;
    [[nodiscard]] std::optional<SymbiosisGrant> find_grant(std::string_view grant_id) const;

    [[nodiscard]] LedgerResult stamp_observation(std::string_view grant_id,
                                                 const SourceObservation& observation,
                                                 std::uint64_t now_unix_ms);

    [[nodiscard]] LedgerResult promote_memory(std::string_view grant_id,
                                              const SourceObservation& observation,
                                              std::string summary,
                                              std::uint64_t now_unix_ms);

    [[nodiscard]] LedgerResult forget_promotion(std::string_view promotion_id,
                                                std::uint64_t now_unix_ms);

    [[nodiscard]] std::vector<ObservationStamp> observation_stamps(
        std::string_view grant_id) const;
    [[nodiscard]] std::vector<MemoryPromotion> promotions(
        bool include_forgotten = false) const;

    [[nodiscard]] bool replay(std::vector<std::string>* errors = nullptr);

    [[nodiscard]] std::size_t grant_count() const noexcept;
    [[nodiscard]] std::size_t stamp_count() const noexcept;
    [[nodiscard]] std::size_t promotion_count() const noexcept;
    [[nodiscard]] const std::filesystem::path& journal_path() const noexcept;

private:
    struct GrantRecord {
        SymbiosisGrant grant;
        std::optional<std::uint64_t> revoked_at_unix_ms;
        std::string revocation_reason;
    };

    [[nodiscard]] bool append_line(std::string_view line, std::string* error) const;
    [[nodiscard]] bool observation_matches_grant(const SymbiosisGrant& grant,
                                                 const SourceObservation& observation,
                                                 std::string* error) const;
    void retain_stamp(ObservationStamp stamp, std::size_t max_stamps);

    std::filesystem::path journal_path_;
    std::unordered_map<std::string, GrantRecord> grants_;
    std::vector<ObservationStamp> stamps_;
    std::vector<MemoryPromotion> promotions_;
};

[[nodiscard]] std::string_view to_string(GrantState state) noexcept;
[[nodiscard]] std::string_view to_string(LedgerStatus status) noexcept;

} // namespace guff
