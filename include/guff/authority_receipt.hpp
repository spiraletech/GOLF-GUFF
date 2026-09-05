#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class AuthorityPurpose : std::uint8_t {
    Recovery,
    DestructiveExecution,
    PersistentSymbiosis,
    CapabilityGrant
};

enum class AuthorityReceiptStatus : std::uint8_t {
    Valid,
    Invalid,
    SignerUnknown,
    SignatureRejected,
    PurposeMismatch,
    SubjectMismatch
};

struct AuthorityEnvelope {
    std::uint32_t schema_version{1U};
    AuthorityPurpose purpose{AuthorityPurpose::CapabilityGrant};
    std::string subject_id;
    std::string actor_reference;
    std::string signer_id;
    std::string issued_at_utc;
    std::string nonce;
    std::string scope_sha256;
};

struct AuthorityReceipt {
    AuthorityEnvelope envelope;
    std::string algorithm;
    std::string envelope_sha256;
    std::string signature;
    std::string receipt_id;
};

class AuthoritySigner {
public:
    virtual ~AuthoritySigner() = default;
    [[nodiscard]] virtual std::string signer_id() const = 0;
    [[nodiscard]] virtual std::string algorithm() const = 0;
    [[nodiscard]] virtual std::optional<std::string> sign(std::string_view canonical_envelope) const = 0;
};

class AuthorityVerifier {
public:
    virtual ~AuthorityVerifier() = default;
    [[nodiscard]] virtual bool knows(std::string_view signer_id,
                                     std::string_view algorithm) const = 0;
    [[nodiscard]] virtual bool verify(std::string_view signer_id,
                                      std::string_view algorithm,
                                      std::string_view canonical_envelope,
                                      std::string_view signature) const = 0;
};

struct AuthorityVerificationResult {
    AuthorityReceiptStatus status{AuthorityReceiptStatus::Invalid};
    std::vector<std::string> errors;
    [[nodiscard]] bool ok() const noexcept;
};

[[nodiscard]] std::string canonical_authority_envelope(const AuthorityEnvelope& envelope);
[[nodiscard]] std::string authority_envelope_sha256(const AuthorityEnvelope& envelope);
[[nodiscard]] std::string authority_receipt_id(const AuthorityEnvelope& envelope,
                                               std::string_view algorithm,
                                               std::string_view signature);
[[nodiscard]] std::optional<AuthorityReceipt> issue_authority_receipt(
    const AuthorityEnvelope& envelope,
    const AuthoritySigner& signer,
    std::vector<std::string>* errors = nullptr);
[[nodiscard]] AuthorityVerificationResult verify_authority_receipt(
    const AuthorityReceipt& receipt,
    const AuthorityVerifier& verifier,
    AuthorityPurpose expected_purpose,
    std::string_view expected_subject_id);

[[nodiscard]] std::string_view to_string(AuthorityPurpose purpose) noexcept;
[[nodiscard]] std::string_view to_string(AuthorityReceiptStatus status) noexcept;

} // namespace guff
