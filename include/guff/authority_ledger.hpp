#pragma once

#include "guff/authority_receipt.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace guff {

enum class AuthorityLedgerStatus : std::uint8_t {
    Allowed,
    Invalid,
    Duplicate,
    NotFound,
    SignerUnknown,
    KeyInactive,
    ReceiptExpired,
    ReceiptRevoked,
    NonceReplay,
    UseLimitReached,
    StorageError,
    Corrupt
};

struct TrustedSignerKey {
    std::string signer_id;
    std::string key_id;
    std::string algorithm;
    std::uint64_t valid_from_unix_ms{0U};
    std::uint64_t valid_until_unix_ms{0U};
    std::uint64_t revoked_at_unix_ms{0U};
};

struct AuthorityLedgerResult {
    AuthorityLedgerStatus status{AuthorityLedgerStatus::Invalid};
    std::string receipt_id;
    std::size_t use_count{0U};
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

struct AuthorityLedgerInspection {
    bool healthy{true};
    std::size_t records{0U};
    std::size_t trusted_keys{0U};
    std::size_t consumed_receipts{0U};
    std::size_t revoked_receipts{0U};
    std::vector<std::string> errors;
};

class AuthorityLedger {
public:
    using Clock = std::function<std::uint64_t()>;

    AuthorityLedger(std::filesystem::path journal_path,
                    const AuthorityVerifier& verifier,
                    Clock clock = {});

    [[nodiscard]] AuthorityLedgerResult trust_key(TrustedSignerKey key);
    [[nodiscard]] AuthorityLedgerResult retire_key(std::string_view signer_id,
                                                   std::string_view key_id,
                                                   std::uint64_t retired_at_unix_ms);
    [[nodiscard]] AuthorityLedgerResult revoke_key(std::string_view signer_id,
                                                   std::string_view key_id,
                                                   std::uint64_t revoked_at_unix_ms);
    [[nodiscard]] AuthorityLedgerResult revoke_receipt(std::string_view receipt_id,
                                                       std::uint64_t revoked_at_unix_ms);

    [[nodiscard]] AuthorityLedgerResult authorize_and_consume(
        const AuthorityReceipt& receipt,
        AuthorityPurpose expected_purpose,
        std::string_view expected_subject_id,
        std::string_view expected_scope_sha256);

    [[nodiscard]] bool replay(std::vector<std::string>* errors = nullptr);
    [[nodiscard]] AuthorityLedgerInspection inspect() const;
    [[nodiscard]] std::size_t use_count(std::string_view receipt_id) const noexcept;
    [[nodiscard]] bool receipt_revoked(std::string_view receipt_id) const noexcept;
    [[nodiscard]] const std::filesystem::path& journal_path() const noexcept;

private:
    struct KeyState {
        TrustedSignerKey key;
    };

    [[nodiscard]] std::string key_map_id(std::string_view signer_id,
                                         std::string_view key_id) const;
    [[nodiscard]] bool append_event(std::string_view body, std::string* error);
    [[nodiscard]] std::optional<TrustedSignerKey> find_key(
        std::string_view signer_id,
        std::string_view key_id) const;
    [[nodiscard]] std::uint64_t now_ms() const;

    std::filesystem::path journal_path_;
    const AuthorityVerifier& verifier_;
    Clock clock_;
    std::unordered_map<std::string, KeyState> keys_;
    std::unordered_map<std::string, std::size_t> receipt_uses_;
    std::unordered_map<std::string, std::uint64_t> revoked_receipts_;
    std::unordered_map<std::string, std::string> nonce_receipts_;
    std::size_t sequence_{0U};
    std::string last_record_sha256_;
    bool healthy_{true};
    std::vector<std::string> errors_;
};

[[nodiscard]] std::string_view to_string(AuthorityLedgerStatus status) noexcept;

} // namespace guff
