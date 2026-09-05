#include "guff/authority_receipt.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <sstream>
#include <utility>

namespace guff {
namespace {

constexpr std::string_view kReceiptPrefix = "guff:authority:sha256:";

bool valid_token(std::string_view value, std::size_t max_bytes = 128U) noexcept {
    if (value.empty() || value.size() > max_bytes) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' ||
               ch == '.' || ch == ':' || ch == '/';
    });
}

bool valid_receipt_id(std::string_view value) noexcept {
    return value.starts_with(kReceiptPrefix) &&
           is_sha256(value.substr(kReceiptPrefix.size()));
}

std::vector<std::string> canonical_capabilities(
    const std::vector<std::string>& capabilities) {
    auto copy = capabilities;
    std::sort(copy.begin(), copy.end());
    return copy;
}

std::vector<std::string> validate_envelope(const AuthorityEnvelope& envelope) {
    std::vector<std::string> errors;
    if (envelope.schema_version != 1U &&
        envelope.schema_version != 2U &&
        envelope.schema_version != 3U) {
        errors.emplace_back("unsupported authority envelope schema");
    }
    if (!valid_token(envelope.subject_id, 256U))
        errors.emplace_back("subject_id must be a bounded token");
    if (envelope.actor_reference.empty() || envelope.actor_reference.size() > 256U)
        errors.emplace_back("actor_reference must be 1-256 bytes");
    if (!valid_token(envelope.signer_id, 128U))
        errors.emplace_back("signer_id must be a bounded token");
    if (envelope.issued_at_utc.empty() || envelope.issued_at_utc.size() > 128U)
        errors.emplace_back("issued_at_utc must be 1-128 bytes");
    if (!valid_token(envelope.nonce, 128U))
        errors.emplace_back("nonce must be a bounded token");
    if (!is_sha256(envelope.scope_sha256))
        errors.emplace_back("scope_sha256 must be SHA-256");

    if (envelope.schema_version >= 2U) {
        if (!valid_token(envelope.signer_key_id, 128U))
            errors.emplace_back("schema v2+ signer_key_id must be a bounded token");
        if (envelope.issued_at_unix_ms == 0U)
            errors.emplace_back("schema v2+ issued_at_unix_ms must be non-zero");
        if (envelope.expires_at_unix_ms <= envelope.issued_at_unix_ms)
            errors.emplace_back("schema v2+ expiry must be later than issue time");
        if (envelope.max_uses == 0U || envelope.max_uses > 1024U)
            errors.emplace_back("schema v2+ max_uses must be in [1,1024]");
    }

    if (envelope.schema_version == 3U) {
        if (!valid_token(envelope.scope_path, 512U))
            errors.emplace_back("schema v3 scope_path must be a bounded hierarchical token");
        if (envelope.scope_sha256 != sha256(envelope.scope_path))
            errors.emplace_back("schema v3 scope_sha256 must equal SHA-256(scope_path)");
        if (envelope.capabilities.empty() || envelope.capabilities.size() > 32U)
            errors.emplace_back("schema v3 capabilities must contain 1-32 entries");
        for (const auto& capability : envelope.capabilities) {
            if (!valid_token(capability, 128U)) {
                errors.emplace_back("schema v3 capability must be a bounded token");
                break;
            }
        }
        const auto canonical = canonical_capabilities(envelope.capabilities);
        if (std::adjacent_find(canonical.begin(), canonical.end()) != canonical.end())
            errors.emplace_back("schema v3 capabilities must be unique");
        if (envelope.max_delegation_depth > 8U)
            errors.emplace_back("schema v3 max_delegation_depth must be <= 8");
        if (envelope.delegation_depth > envelope.max_delegation_depth)
            errors.emplace_back("schema v3 delegation depth exceeds signed maximum");
        if (envelope.delegation_depth == 0U) {
            if (!envelope.parent_receipt_id.empty())
                errors.emplace_back("schema v3 root receipt cannot name a parent receipt");
        } else if (!valid_receipt_id(envelope.parent_receipt_id)) {
            errors.emplace_back("schema v3 delegated receipt requires a canonical parent receipt id");
        }
    }
    return errors;
}

} // namespace

bool AuthorityVerificationResult::ok() const noexcept {
    return status == AuthorityReceiptStatus::Valid;
}

bool authority_scope_contains(std::string_view parent_scope_path,
                              std::string_view child_scope_path) noexcept {
    if (parent_scope_path.empty() || child_scope_path.empty()) return false;
    if (parent_scope_path == child_scope_path) return true;
    if (!child_scope_path.starts_with(parent_scope_path)) return false;
    if (child_scope_path.size() <= parent_scope_path.size()) return false;
    if (parent_scope_path.back() == '/') return true;
    return child_scope_path[parent_scope_path.size()] == '/';
}

bool authority_capabilities_contain(
    const std::vector<std::string>& parent,
    const std::vector<std::string>& child) {
    if (parent.empty() || child.empty()) return false;
    const auto parent_sorted = canonical_capabilities(parent);
    const auto child_sorted = canonical_capabilities(child);
    return std::includes(parent_sorted.begin(), parent_sorted.end(),
                         child_sorted.begin(), child_sorted.end());
}

std::string canonical_authority_envelope(const AuthorityEnvelope& envelope) {
    std::ostringstream out;
    out << envelope.schema_version << '\n'
        << static_cast<unsigned>(envelope.purpose) << '\n'
        << envelope.subject_id << '\n'
        << envelope.actor_reference << '\n'
        << envelope.signer_id << '\n';
    if (envelope.schema_version >= 2U) {
        out << envelope.signer_key_id << '\n';
    }
    out << envelope.issued_at_utc << '\n';
    if (envelope.schema_version >= 2U) {
        out << envelope.issued_at_unix_ms << '\n'
            << envelope.expires_at_unix_ms << '\n'
            << envelope.max_uses << '\n';
    }
    out << envelope.nonce << '\n'
        << envelope.scope_sha256;
    if (envelope.schema_version == 3U) {
        out << '\n' << envelope.parent_receipt_id
            << '\n' << envelope.delegation_depth
            << '\n' << envelope.max_delegation_depth
            << '\n' << envelope.scope_path;
        const auto capabilities = canonical_capabilities(envelope.capabilities);
        out << '\n' << capabilities.size();
        for (const auto& capability : capabilities) {
            out << '\n' << capability;
        }
    }
    return out.str();
}

std::string authority_envelope_sha256(const AuthorityEnvelope& envelope) {
    return sha256(canonical_authority_envelope(envelope));
}

std::string authority_receipt_id(const AuthorityEnvelope& envelope,
                                 std::string_view algorithm,
                                 std::string_view signature) {
    std::ostringstream canonical;
    canonical << authority_envelope_sha256(envelope) << '\n'
              << algorithm << '\n'
              << signature;
    return std::string(kReceiptPrefix) + sha256(canonical.str());
}

std::optional<AuthorityReceipt> issue_authority_receipt(
    const AuthorityEnvelope& envelope,
    const AuthoritySigner& signer,
    std::vector<std::string>* errors) {
    auto validation = validate_envelope(envelope);
    if (signer.signer_id() != envelope.signer_id)
        validation.emplace_back("signer_id does not match signer implementation");
    const auto algorithm = signer.algorithm();
    if (!valid_token(algorithm, 64U))
        validation.emplace_back("signer algorithm must be a bounded token");
    if (!validation.empty()) {
        if (errors) *errors = std::move(validation);
        return std::nullopt;
    }

    const auto canonical = canonical_authority_envelope(envelope);
    auto signature = signer.sign(canonical);
    if (!signature || signature->empty() || signature->size() > 2048U) {
        if (errors) errors->emplace_back("signer failed to produce a bounded signature");
        return std::nullopt;
    }

    AuthorityReceipt receipt;
    receipt.envelope = envelope;
    receipt.algorithm = algorithm;
    receipt.envelope_sha256 = sha256(canonical);
    receipt.signature = *signature;
    receipt.receipt_id = authority_receipt_id(envelope, receipt.algorithm, receipt.signature);
    return receipt;
}

AuthorityVerificationResult verify_authority_receipt(
    const AuthorityReceipt& receipt,
    const AuthorityVerifier& verifier,
    AuthorityPurpose expected_purpose,
    std::string_view expected_subject_id) {
    AuthorityVerificationResult result;
    result.errors = validate_envelope(receipt.envelope);
    if (!result.errors.empty()) {
        result.status = AuthorityReceiptStatus::Invalid;
        return result;
    }
    if (receipt.envelope.purpose != expected_purpose) {
        result.status = AuthorityReceiptStatus::PurposeMismatch;
        result.errors.emplace_back("authority purpose does not match requested operation");
        return result;
    }
    if (receipt.envelope.subject_id != expected_subject_id) {
        result.status = AuthorityReceiptStatus::SubjectMismatch;
        result.errors.emplace_back("authority subject does not match requested operation");
        return result;
    }
    if (!valid_token(receipt.algorithm, 64U) ||
        receipt.signature.empty() || receipt.signature.size() > 2048U) {
        result.status = AuthorityReceiptStatus::Invalid;
        result.errors.emplace_back("authority receipt algorithm/signature is malformed");
        return result;
    }

    const auto canonical = canonical_authority_envelope(receipt.envelope);
    if (receipt.envelope_sha256 != sha256(canonical) ||
        receipt.receipt_id != authority_receipt_id(receipt.envelope, receipt.algorithm, receipt.signature)) {
        result.status = AuthorityReceiptStatus::Invalid;
        result.errors.emplace_back("authority receipt content identity mismatch");
        return result;
    }
    if (!verifier.knows(receipt.envelope.signer_id, receipt.algorithm)) {
        result.status = AuthorityReceiptStatus::SignerUnknown;
        result.errors.emplace_back("authority signer is not trusted by verifier");
        return result;
    }
    if (!verifier.verify(receipt.envelope.signer_id,
                         receipt.algorithm,
                         canonical,
                         receipt.signature)) {
        result.status = AuthorityReceiptStatus::SignatureRejected;
        result.errors.emplace_back("authority receipt signature rejected");
        return result;
    }
    result.status = AuthorityReceiptStatus::Valid;
    return result;
}

std::string_view to_string(AuthorityPurpose purpose) noexcept {
    switch (purpose) {
    case AuthorityPurpose::Recovery: return "RECOVERY";
    case AuthorityPurpose::DestructiveExecution: return "DESTRUCTIVE_EXECUTION";
    case AuthorityPurpose::PersistentSymbiosis: return "PERSISTENT_SYMBIOSIS";
    case AuthorityPurpose::CapabilityGrant: return "CAPABILITY_GRANT";
    }
    return "CAPABILITY_GRANT";
}

std::string_view to_string(AuthorityReceiptStatus status) noexcept {
    switch (status) {
    case AuthorityReceiptStatus::Valid: return "VALID";
    case AuthorityReceiptStatus::Invalid: return "INVALID";
    case AuthorityReceiptStatus::SignerUnknown: return "SIGNER_UNKNOWN";
    case AuthorityReceiptStatus::SignatureRejected: return "SIGNATURE_REJECTED";
    case AuthorityReceiptStatus::PurposeMismatch: return "PURPOSE_MISMATCH";
    case AuthorityReceiptStatus::SubjectMismatch: return "SUBJECT_MISMATCH";
    }
    return "INVALID";
}

} // namespace guff
