#pragma once

#include "guff/reality.hpp"
#include "guff/session_key.hpp"

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

struct RuntimeBinding {
    std::string device_id;
    std::string executable_sha256;
    std::string process_instance_sha256;
    std::string slot_id;
    std::string session_id;
    RealityLayer layer{RealityLayer::Runtime};
};

struct RuntimeCapabilityLease {
    std::uint32_t schema_version{1U};
    std::string session_key_receipt_id;
    std::string certificate_id;
    std::string signer_id;
    std::string key_id;
    std::string algorithm;
    std::string key_fingerprint_sha256;
    AuthorityPurpose purpose{AuthorityPurpose::CapabilityGrant};
    std::string subject_id;
    std::string scope_path;
    std::string scope_sha256;
    std::string capability;
    RuntimeBinding binding;
    std::uint64_t issued_at_unix_ms{0U};
    std::uint64_t expires_at_unix_ms{0U};
    std::uint32_t max_uses{0U};
    std::string nonce;
    std::string canonical_sha256;
    std::string signature;
    std::string lease_id;
};

enum class RuntimeLeaseStatus : std::uint8_t {
    Allowed,
    Invalid,
    NotRegistered,
    SignatureRejected,
    KeyMismatch,
    SessionKeyMismatch,
    DeviceMismatch,
    ExecutableMismatch,
    ProcessMismatch,
    SlotMismatch,
    SessionMismatch,
    LayerMismatch,
    CapabilityMismatch,
    ScopeMismatch,
    LeaseExpired,
    UseLimitReached,
    LeaseRevoked,
    SessionKeyRejected,
    StorageError,
    Corrupt
};

struct RuntimeLeaseResult {
    RuntimeLeaseStatus status{RuntimeLeaseStatus::Invalid};
    SessionKeyStatus session_key_status{SessionKeyStatus::Invalid};
    AuthorityLedgerStatus backing_ledger_status{AuthorityLedgerStatus::Invalid};
    std::string lease_id;
    std::size_t use_count{0U};
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

struct RuntimeLeaseInspection {
    bool healthy{true};
    std::size_t records{0U};
    std::size_t registered_leases{0U};
    std::size_t consumed_leases{0U};
    std::size_t revoked_leases{0U};
    std::vector<std::string> errors;
};

struct RuntimeLeaseIssueRequest {
    RuntimeBinding binding;
    std::string capability;
    std::uint64_t issued_at_unix_ms{0U};
    std::uint64_t expires_at_unix_ms{0U};
    std::uint32_t max_uses{1U};
    std::string nonce;
};

class RuntimeLeaseIssuer {
public:
    [[nodiscard]] static std::optional<RuntimeCapabilityLease> issue(
        const SessionKeyBundle& bundle,
        const RuntimeLeaseIssueRequest& request,
        const SessionKeySigner& signer,
        std::vector<std::string>* errors = nullptr);
};

class RuntimeLeaseLedger {
public:
    using Clock = std::function<std::uint64_t()>;

    RuntimeLeaseLedger(std::filesystem::path journal_path, Clock clock = {});

    [[nodiscard]] RuntimeLeaseResult register_lease(
        const RuntimeCapabilityLease& lease,
        const SessionKeyBundle& bundle,
        const SessionKeyVerifier& key_verifier);
    [[nodiscard]] RuntimeLeaseResult preflight(
        const RuntimeCapabilityLease& lease,
        const SessionKeyBundle& bundle,
        const SessionKeyVerifier& key_verifier,
        const RuntimeBinding& observed_binding) const;
    [[nodiscard]] RuntimeLeaseResult consume(const RuntimeCapabilityLease& lease);
    [[nodiscard]] RuntimeLeaseResult revoke_lease(std::string_view lease_id,
                                                  std::uint64_t revoked_at_unix_ms);

    [[nodiscard]] bool replay(std::vector<std::string>* errors = nullptr);
    [[nodiscard]] RuntimeLeaseInspection inspect() const;
    [[nodiscard]] std::size_t use_count(std::string_view lease_id) const noexcept;
    [[nodiscard]] bool lease_registered(std::string_view lease_id) const noexcept;
    [[nodiscard]] bool lease_revoked(std::string_view lease_id) const noexcept;
    [[nodiscard]] const std::filesystem::path& journal_path() const noexcept;

private:
    struct Registration {
        std::string session_key_receipt_id;
        std::string certificate_id;
        std::string signer_id;
        std::string key_id;
        std::string key_fingerprint_sha256;
        std::string binding_sha256;
        std::uint64_t expires_at_unix_ms{0U};
        std::uint32_t max_uses{0U};
    };

    [[nodiscard]] bool append_event(std::string_view body, std::string* error);
    [[nodiscard]] std::uint64_t now_ms() const;

    std::filesystem::path journal_path_;
    Clock clock_;
    std::unordered_map<std::string, Registration> registrations_;
    std::unordered_map<std::string, std::size_t> lease_uses_;
    std::unordered_map<std::string, std::uint64_t> revoked_leases_;
    std::size_t sequence_{0U};
    std::string last_record_sha256_;
    bool healthy_{true};
    std::vector<std::string> errors_;
};

class RuntimeLeaseAuthorityGate {
public:
    RuntimeLeaseAuthorityGate(RuntimeLeaseLedger& lease_ledger,
                              const SessionKeyVerifier& key_verifier,
                              const SessionKeyAuthorityGate& session_key_gate) noexcept;

    [[nodiscard]] RuntimeLeaseResult authorize(
        const RuntimeCapabilityLease& lease,
        const SessionKeyBundle& bundle,
        const RuntimeBinding& observed_binding) const;

private:
    RuntimeLeaseLedger& lease_ledger_;
    const SessionKeyVerifier& key_verifier_;
    const SessionKeyAuthorityGate& session_key_gate_;
};

[[nodiscard]] std::string canonical_runtime_binding(const RuntimeBinding& binding);
[[nodiscard]] std::string runtime_binding_sha256(const RuntimeBinding& binding);
[[nodiscard]] std::string canonical_runtime_capability_lease(
    const RuntimeCapabilityLease& lease);
[[nodiscard]] std::string runtime_capability_lease_id(
    const RuntimeCapabilityLease& lease,
    std::string_view signature);
[[nodiscard]] std::string runtime_process_instance_sha256(
    std::string_view device_id,
    std::string_view executable_sha256,
    std::uint64_t process_id,
    std::uint64_t process_started_unix_ms,
    std::string_view runtime_nonce);
[[nodiscard]] std::string_view to_string(RuntimeLeaseStatus status) noexcept;

} // namespace guff
