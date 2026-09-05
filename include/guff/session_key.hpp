#pragma once

#include "guff/authority_delegation.hpp"
#include "guff/authority_gate.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace guff {

class SessionKeySigner {
public:
    virtual ~SessionKeySigner() = default;
    [[nodiscard]] virtual std::string signer_id() const = 0;
    [[nodiscard]] virtual std::string key_id() const = 0;
    [[nodiscard]] virtual std::string algorithm() const = 0;
    [[nodiscard]] virtual std::string key_fingerprint_sha256() const = 0;
    [[nodiscard]] virtual std::optional<std::string> sign(
        std::string_view canonical) const = 0;
};

class SessionKeyVerifier {
public:
    virtual ~SessionKeyVerifier() = default;
    [[nodiscard]] virtual bool knows_key(std::string_view signer_id,
                                         std::string_view key_id,
                                         std::string_view algorithm) const = 0;
    [[nodiscard]] virtual std::optional<std::string> key_fingerprint_sha256(
        std::string_view signer_id,
        std::string_view key_id,
        std::string_view algorithm) const = 0;
    [[nodiscard]] virtual bool verify_key(std::string_view signer_id,
                                          std::string_view key_id,
                                          std::string_view algorithm,
                                          std::string_view canonical,
                                          std::string_view signature) const = 0;
};

struct SessionKeyCertificate {
    std::uint32_t schema_version{1U};
    std::string voucher_receipt_id;
    std::string parent_signer_id;
    std::string parent_key_id;
    std::string parent_algorithm;
    std::string child_signer_id;
    std::string child_key_id;
    std::string child_algorithm;
    std::string child_key_fingerprint_sha256;
    AuthorityPurpose purpose{AuthorityPurpose::CapabilityGrant};
    std::string subject_id;
    std::string scope_path;
    std::string scope_sha256;
    std::vector<std::string> capabilities;
    std::uint64_t issued_at_unix_ms{0U};
    std::uint64_t expires_at_unix_ms{0U};
    std::uint32_t max_uses{0U};
    std::string nonce;
    std::string canonical_sha256;
    std::string parent_signature;
    std::string certificate_id;
};

struct SessionKeyReceipt {
    std::uint32_t schema_version{1U};
    std::string certificate_id;
    std::string voucher_receipt_id;
    std::string signer_id;
    std::string key_id;
    std::string algorithm;
    std::string key_fingerprint_sha256;
    AuthorityPurpose purpose{AuthorityPurpose::CapabilityGrant};
    std::string subject_id;
    std::string scope_path;
    std::string scope_sha256;
    std::vector<std::string> capabilities;
    std::uint64_t issued_at_unix_ms{0U};
    std::uint64_t expires_at_unix_ms{0U};
    std::uint32_t max_uses{0U};
    std::string nonce;
    std::string canonical_sha256;
    std::string signature;
    std::string receipt_id;
};

struct SessionKeyBundle {
    AuthorityReceipt voucher;
    SessionKeyCertificate certificate;
    SessionKeyReceipt receipt;
};

enum class SessionKeyStatus : std::uint8_t {
    Allowed,
    Invalid,
    VoucherRejected,
    KeyUnknown,
    FingerprintMismatch,
    CertificateRejected,
    ReceiptRejected,
    NotRegistered,
    KeyRevoked,
    ReceiptRevoked,
    ReceiptExpired,
    CapabilityMismatch,
    ScopeMismatch,
    UseLimitReached,
    StorageError,
    Corrupt
};

struct SessionKeyResult {
    SessionKeyStatus status{SessionKeyStatus::Invalid};
    AuthorityGateStatus backing_gate_status{AuthorityGateStatus::ReceiptRejected};
    AuthorityLedgerStatus backing_ledger_status{AuthorityLedgerStatus::Invalid};
    std::string receipt_id;
    std::size_t use_count{0U};
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

struct SessionKeyLedgerInspection {
    bool healthy{true};
    std::size_t records{0U};
    std::size_t registered_handoffs{0U};
    std::size_t consumed_receipts{0U};
    std::size_t revoked_keys{0U};
    std::size_t revoked_receipts{0U};
    std::vector<std::string> errors;
};

class SessionKeyLedger {
public:
    explicit SessionKeyLedger(std::filesystem::path journal_path);

    [[nodiscard]] SessionKeyResult register_bundle(const SessionKeyBundle& bundle);
    [[nodiscard]] SessionKeyResult preflight(
        const SessionKeyBundle& bundle,
        const AuthorityVerifier& parent_verifier,
        const SessionKeyVerifier& key_verifier,
        AuthorityPurpose expected_purpose,
        std::string_view expected_subject_id,
        std::string_view expected_scope_sha256,
        std::string_view expected_capability) const;
    [[nodiscard]] SessionKeyResult consume(const SessionKeyReceipt& receipt);
    [[nodiscard]] SessionKeyResult revoke_key(std::string_view signer_id,
                                              std::string_view key_id,
                                              std::uint64_t revoked_at_unix_ms);
    [[nodiscard]] SessionKeyResult revoke_receipt(std::string_view receipt_id,
                                                  std::uint64_t revoked_at_unix_ms);

    [[nodiscard]] bool replay(std::vector<std::string>* errors = nullptr);
    [[nodiscard]] SessionKeyLedgerInspection inspect() const;
    [[nodiscard]] std::size_t use_count(std::string_view receipt_id) const noexcept;
    [[nodiscard]] bool bundle_registered(std::string_view receipt_id) const noexcept;
    [[nodiscard]] const std::filesystem::path& journal_path() const noexcept;

private:
    struct Registration {
        std::string voucher_receipt_id;
        std::string certificate_id;
        std::string receipt_id;
        std::string signer_id;
        std::string key_id;
        std::string algorithm;
        std::string key_fingerprint_sha256;
        std::uint64_t expires_at_unix_ms{0U};
        std::uint32_t max_uses{0U};
    };

    [[nodiscard]] bool append_event(std::string_view body, std::string* error);
    [[nodiscard]] std::string key_map_id(std::string_view signer_id,
                                         std::string_view key_id) const;

    std::filesystem::path journal_path_;
    std::unordered_map<std::string, Registration> registrations_;
    std::unordered_map<std::string, std::size_t> receipt_uses_;
    std::unordered_map<std::string, std::uint64_t> revoked_keys_;
    std::unordered_map<std::string, std::uint64_t> revoked_receipts_;
    std::size_t sequence_{0U};
    std::string last_record_sha256_;
    bool healthy_{true};
    std::vector<std::string> errors_;
};

struct SessionKeyHandoffRequest {
    AuthorityReceipt parent;
    std::string actor_reference;
    std::string issued_at_utc;
    std::string voucher_nonce;
    std::string certificate_nonce;
    std::string receipt_nonce;
    std::string scope_path;
    std::vector<std::string> capabilities;
    std::uint64_t issued_at_unix_ms{0U};
    std::uint64_t expires_at_unix_ms{0U};
    std::uint32_t max_uses{1U};
    std::uint32_t max_delegation_depth{0U};
};

enum class SessionKeyHandoffStatus : std::uint8_t {
    Issued,
    Invalid,
    SameKey,
    VoucherRejected,
    KeyUnknown,
    FingerprintMismatch,
    CertificateSigningFailed,
    ReceiptSigningFailed,
    StoreRejected
};

struct SessionKeyHandoffResult {
    SessionKeyHandoffStatus status{SessionKeyHandoffStatus::Invalid};
    std::optional<SessionKeyBundle> bundle;
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

class AuthoritySessionKeyHandoff {
public:
    AuthoritySessionKeyHandoff(AuthorityDelegator& delegator,
                               SessionKeyLedger& session_ledger,
                               const AuthorityVerifier& parent_verifier,
                               const SessionKeyVerifier& key_verifier) noexcept;

    [[nodiscard]] SessionKeyHandoffResult issue(
        const SessionKeyHandoffRequest& request,
        const AuthoritySigner& parent_signer,
        const SessionKeySigner& child_signer) const;

private:
    AuthorityDelegator& delegator_;
    SessionKeyLedger& session_ledger_;
    const AuthorityVerifier& parent_verifier_;
    const SessionKeyVerifier& key_verifier_;
};

class SessionKeyAuthorityGate {
public:
    SessionKeyAuthorityGate(SessionKeyLedger& session_ledger,
                            const AuthorityVerifier& parent_verifier,
                            const SessionKeyVerifier& key_verifier,
                            const AuthorityGate& backing_gate) noexcept;

    [[nodiscard]] SessionKeyResult authorize(
        const SessionKeyBundle& bundle,
        AuthorityPurpose purpose,
        std::string_view subject_id,
        std::string_view scope_sha256,
        std::string_view capability) const;

private:
    SessionKeyLedger& session_ledger_;
    const AuthorityVerifier& parent_verifier_;
    const SessionKeyVerifier& key_verifier_;
    const AuthorityGate& backing_gate_;
};

[[nodiscard]] std::string canonical_session_key_certificate(
    const SessionKeyCertificate& certificate);
[[nodiscard]] std::string canonical_session_key_receipt(
    const SessionKeyReceipt& receipt);
[[nodiscard]] std::string session_key_certificate_id(
    const SessionKeyCertificate& certificate,
    std::string_view parent_signature);
[[nodiscard]] std::string session_key_receipt_id(
    const SessionKeyReceipt& receipt,
    std::string_view signature);
[[nodiscard]] std::string_view to_string(SessionKeyStatus status) noexcept;
[[nodiscard]] std::string_view to_string(SessionKeyHandoffStatus status) noexcept;

} // namespace guff
