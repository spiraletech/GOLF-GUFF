#pragma once

#include "guff/authority_ledger.hpp"
#include "guff/authority_receipt.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class DelegationStatus : std::uint8_t {
    Issued,
    InvalidParent,
    ParentUnavailable,
    ScopeAmplification,
    CapabilityAmplification,
    LifetimeAmplification,
    UseAmplification,
    PurposeAmplification,
    SubjectAmplification,
    DepthExceeded,
    SignerMismatch,
    NoAttenuation,
    SigningFailed,
    LedgerRejected
};

struct DelegationRequest {
    AuthorityReceipt parent;
    std::string actor_reference;
    std::string nonce;
    std::string scope_path;
    std::vector<std::string> capabilities;
    std::uint64_t issued_at_unix_ms{0U};
    std::uint64_t expires_at_unix_ms{0U};
    std::uint32_t max_uses{1U};
    std::uint32_t max_delegation_depth{0U};
};

struct DelegationResult {
    DelegationStatus status{DelegationStatus::InvalidParent};
    std::optional<AuthorityReceipt> child;
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

class AuthorityDelegator {
public:
    AuthorityDelegator(AuthorityLedger& ledger,
                       const AuthorityVerifier& verifier) noexcept;

    [[nodiscard]] DelegationResult delegate(
        const DelegationRequest& request,
        const AuthoritySigner& signer) const;

private:
    AuthorityLedger& ledger_;
    const AuthorityVerifier& verifier_;
};

[[nodiscard]] std::string_view to_string(DelegationStatus status) noexcept;

} // namespace guff
