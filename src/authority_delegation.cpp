#include "guff/authority_delegation.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <utility>

namespace guff {
namespace {

bool strictly_attenuated(const AuthorityEnvelope& parent,
                         const AuthorityEnvelope& child) {
    return child.scope_path != parent.scope_path ||
           child.capabilities.size() < parent.capabilities.size() ||
           child.expires_at_unix_ms < parent.expires_at_unix_ms ||
           child.max_uses < parent.max_uses ||
           child.max_delegation_depth < parent.max_delegation_depth;
}

} // namespace

bool DelegationResult::ok() const noexcept {
    return status == DelegationStatus::Issued && child.has_value();
}

AuthorityDelegator::AuthorityDelegator(AuthorityLedger& ledger,
                                       const AuthorityVerifier& verifier) noexcept
    : ledger_(ledger), verifier_(verifier) {}

DelegationResult AuthorityDelegator::delegate(
    const DelegationRequest& request,
    const AuthoritySigner& signer) const {
    DelegationResult result;
    const auto& parent = request.parent;

    if (parent.envelope.schema_version != 3U ||
        parent.envelope.parent_receipt_id.size() > 96U) {
        result.status = DelegationStatus::InvalidParent;
        result.errors.emplace_back("delegation requires a valid schema v3 parent receipt");
        return result;
    }

    const auto parent_verified = verify_authority_receipt(
        parent, verifier_, parent.envelope.purpose, parent.envelope.subject_id);
    if (!parent_verified.ok()) {
        result.status = DelegationStatus::InvalidParent;
        result.errors = parent_verified.errors;
        return result;
    }
    if (signer.signer_id() != parent.envelope.signer_id ||
        signer.algorithm() != parent.algorithm) {
        result.status = DelegationStatus::SignerMismatch;
        result.errors.emplace_back("delegation child must be signed by the same trusted signer identity and algorithm as its parent");
        return result;
    }
    if (parent.envelope.delegation_depth >= parent.envelope.max_delegation_depth) {
        result.status = DelegationStatus::DepthExceeded;
        result.errors.emplace_back("parent receipt has no remaining delegation depth");
        return result;
    }
    if (!authority_scope_contains(parent.envelope.scope_path, request.scope_path)) {
        result.status = DelegationStatus::ScopeAmplification;
        result.errors.emplace_back("child scope_path escapes the signed parent scope");
        return result;
    }
    if (!authority_capabilities_contain(parent.envelope.capabilities,
                                        request.capabilities)) {
        result.status = DelegationStatus::CapabilityAmplification;
        result.errors.emplace_back("child capability set is not a subset of the parent capability set");
        return result;
    }
    if (request.issued_at_unix_ms < parent.envelope.issued_at_unix_ms ||
        request.expires_at_unix_ms > parent.envelope.expires_at_unix_ms ||
        request.expires_at_unix_ms <= request.issued_at_unix_ms) {
        result.status = DelegationStatus::LifetimeAmplification;
        result.errors.emplace_back("child lifetime must fit entirely inside the parent lifetime");
        return result;
    }
    if (request.max_uses == 0U || request.max_uses > parent.envelope.max_uses) {
        result.status = DelegationStatus::UseAmplification;
        result.errors.emplace_back("child max_uses must be non-zero and no greater than the parent budget");
        return result;
    }
    const std::uint32_t child_depth = parent.envelope.delegation_depth + 1U;
    const std::uint32_t child_max_depth = request.max_delegation_depth == 0U
        ? parent.envelope.max_delegation_depth
        : request.max_delegation_depth;
    if (child_max_depth < child_depth ||
        child_max_depth > parent.envelope.max_delegation_depth) {
        result.status = DelegationStatus::DepthExceeded;
        result.errors.emplace_back("child delegation ceiling must stay within the parent ceiling");
        return result;
    }
    if (request.actor_reference.empty() || request.actor_reference.size() > 256U ||
        request.issued_at_utc.empty() || request.issued_at_utc.size() > 128U ||
        request.nonce.empty() || request.nonce.size() > 128U) {
        result.status = DelegationStatus::InvalidParent;
        result.errors.emplace_back("delegation actor/time/nonce metadata is invalid");
        return result;
    }

    AuthorityEnvelope child_envelope;
    child_envelope.schema_version = 3U;
    child_envelope.purpose = parent.envelope.purpose;
    child_envelope.subject_id = parent.envelope.subject_id;
    child_envelope.actor_reference = request.actor_reference;
    child_envelope.signer_id = parent.envelope.signer_id;
    child_envelope.signer_key_id = parent.envelope.signer_key_id;
    child_envelope.issued_at_utc = request.issued_at_utc;
    child_envelope.issued_at_unix_ms = request.issued_at_unix_ms;
    child_envelope.expires_at_unix_ms = request.expires_at_unix_ms;
    child_envelope.max_uses = request.max_uses;
    child_envelope.nonce = request.nonce;
    child_envelope.scope_path = request.scope_path;
    child_envelope.scope_sha256 = sha256(child_envelope.scope_path);
    child_envelope.parent_receipt_id = parent.receipt_id;
    child_envelope.delegation_depth = child_depth;
    child_envelope.max_delegation_depth = child_max_depth;
    child_envelope.capabilities = request.capabilities;

    if (!strictly_attenuated(parent.envelope, child_envelope)) {
        result.status = DelegationStatus::NoAttenuation;
        result.errors.emplace_back("delegation must make at least one authority dimension strictly narrower");
        return result;
    }

    std::vector<std::string> signing_errors;
    auto child = issue_authority_receipt(child_envelope, signer, &signing_errors);
    if (!child) {
        result.status = DelegationStatus::SigningFailed;
        result.errors = std::move(signing_errors);
        return result;
    }

    const auto registration = ledger_.register_delegation(parent, *child);
    if (!registration.ok()) {
        result.status = DelegationStatus::LedgerRejected;
        result.errors = registration.errors;
        return result;
    }

    result.status = DelegationStatus::Issued;
    result.child = std::move(child);
    return result;
}

std::string_view to_string(DelegationStatus status) noexcept {
    switch (status) {
    case DelegationStatus::Issued: return "ISSUED";
    case DelegationStatus::InvalidParent: return "INVALID_PARENT";
    case DelegationStatus::ParentUnavailable: return "PARENT_UNAVAILABLE";
    case DelegationStatus::ScopeAmplification: return "SCOPE_AMPLIFICATION";
    case DelegationStatus::CapabilityAmplification: return "CAPABILITY_AMPLIFICATION";
    case DelegationStatus::LifetimeAmplification: return "LIFETIME_AMPLIFICATION";
    case DelegationStatus::UseAmplification: return "USE_AMPLIFICATION";
    case DelegationStatus::PurposeAmplification: return "PURPOSE_AMPLIFICATION";
    case DelegationStatus::SubjectAmplification: return "SUBJECT_AMPLIFICATION";
    case DelegationStatus::DepthExceeded: return "DEPTH_EXCEEDED";
    case DelegationStatus::SignerMismatch: return "SIGNER_MISMATCH";
    case DelegationStatus::NoAttenuation: return "NO_ATTENUATION";
    case DelegationStatus::SigningFailed: return "SIGNING_FAILED";
    case DelegationStatus::LedgerRejected: return "LEDGER_REJECTED";
    }
    return "INVALID_PARENT";
}

} // namespace guff
