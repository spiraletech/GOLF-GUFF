#include "guff/recovery_protocol.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <sstream>
#include <utility>

namespace guff {
namespace {

constexpr std::string_view kSessionPrefix = "guff:session:sha256:";
constexpr std::string_view kAuthorizationPrefix = "guff:recovery-auth:sha256:";

bool canonical_session_id(std::string_view value) noexcept {
    return value.starts_with(kSessionPrefix) && is_sha256(value.substr(kSessionPrefix.size()));
}

bool valid_token(std::string_view value) noexcept {
    if (value.empty() || value.size() > 96U) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' ||
               ch == '.' || ch == ':';
    });
}

std::vector<std::string> validate_authorization(
    const RecoveryAuthorization& authorization) {
    std::vector<std::string> errors;
    if (!canonical_session_id(authorization.parent_session_id))
        errors.emplace_back("parent_session_id must be canonical");
    if (!is_sha256(authorization.parent_begin_record_sha256))
        errors.emplace_back("parent_begin_record_sha256 must be SHA-256");

    if (authorization.decision == RecoveryDecision::Dismiss) {
        if (!authorization.child_correlation_id.empty())
            errors.emplace_back("DISMISS cannot contain a child correlation id");
        if (authorization.child_retry_authority != RetryAuthority::None)
            errors.emplace_back("DISMISS cannot grant child retry authority");
    } else if (!valid_token(authorization.child_correlation_id)) {
        errors.emplace_back("RETRY_AS_NEW_SESSION requires a fresh child correlation id");
    }
    return errors;
}

} // namespace

bool RecoveryDecisionResult::ok() const noexcept {
    return status == RecoveryDecisionStatus::Dismissed ||
           status == RecoveryDecisionStatus::RetryPrepared;
}

RecoveryDecisionProtocol::RecoveryDecisionProtocol(
    SessionJournal& journal,
    const AuthorityGate& authority_gate) noexcept
    : journal_(journal), authority_gate_(authority_gate) {}

std::string recovery_authority_scope_sha256(
    const RecoveryAuthorization& authorization) {
    std::ostringstream canonical;
    canonical << static_cast<unsigned>(authorization.decision) << '\n'
              << authorization.parent_session_id << '\n'
              << authorization.parent_begin_record_sha256 << '\n'
              << authorization.child_correlation_id << '\n'
              << static_cast<unsigned>(authorization.child_retry_authority);
    return sha256(canonical.str());
}

std::string recovery_authorization_sha256(
    const RecoveryAuthorization& authorization) {
    std::ostringstream canonical;
    canonical << recovery_authority_scope_sha256(authorization) << '\n';
    if (authorization.authority_receipt) {
        canonical << authorization.authority_receipt->receipt_id;
    }
    return sha256(canonical.str());
}

std::string recovery_authorization_id(
    const RecoveryAuthorization& authorization) {
    return std::string(kAuthorizationPrefix) + recovery_authorization_sha256(authorization);
}

RecoveryDecisionResult RecoveryDecisionProtocol::decide(
    const RecoveryAuthorization& authorization,
    const std::optional<ExecutionSessionRequest>& child_template) const {
    RecoveryDecisionResult result;
    result.errors = validate_authorization(authorization);
    if (!result.errors.empty()) {
        result.status = RecoveryDecisionStatus::Invalid;
        return result;
    }

    const auto inspection = journal_.inspect();
    if (!inspection.healthy) {
        result.status = RecoveryDecisionStatus::JournalError;
        result.errors = inspection.errors;
        return result;
    }

    const auto interrupted = std::find_if(
        inspection.interrupted.begin(), inspection.interrupted.end(),
        [&](const InterruptedSession& item) {
            return item.session_id == authorization.parent_session_id &&
                   item.begin_record_sha256 == authorization.parent_begin_record_sha256;
        });
    if (interrupted == inspection.interrupted.end()) {
        result.status = RecoveryDecisionStatus::ParentNotInterrupted;
        result.errors.emplace_back("parent session is not currently interrupted with the authorized BEGIN identity");
        return result;
    }

    if (authorization.decision == RecoveryDecision::RetryAsNewSession &&
        authorization.child_correlation_id == interrupted->correlation_id) {
        result.status = RecoveryDecisionStatus::IdentityReuse;
        result.errors.emplace_back("recovery child must use a fresh correlation identity");
        return result;
    }
    if (authorization.decision == RecoveryDecision::RetryAsNewSession && !child_template) {
        result.status = RecoveryDecisionStatus::Invalid;
        result.errors.emplace_back("RETRY_AS_NEW_SESSION requires a fresh child request template");
        return result;
    }

    const auto gate = authority_gate_.authorize(
        authorization.authority_receipt,
        AuthorityPurpose::Recovery,
        authorization.parent_session_id,
        recovery_authority_scope_sha256(authorization));
    if (!gate.ok()) {
        result.status = RecoveryDecisionStatus::AuthorizationRequired;
        result.errors = gate.errors;
        return result;
    }

    result.authorization_sha256 = recovery_authorization_sha256(authorization);
    result.authorization_id = recovery_authorization_id(authorization);
    const auto recorded_at = authorization.authority_receipt->envelope.issued_at_utc;

    const auto journal_result = journal_.recover({
        .kind = authorization.decision == RecoveryDecision::Dismiss
            ? JournalRecordKind::RecoveryDismiss
            : JournalRecordKind::RecoveryRetry,
        .session_id = interrupted->session_id,
        .correlation_id = interrupted->correlation_id,
        .request_sha256 = interrupted->request_sha256,
        .begin_record_sha256 = interrupted->begin_record_sha256,
        .authorization_sha256 = result.authorization_sha256,
        .child_correlation_id = authorization.child_correlation_id,
        .recorded_at_utc = recorded_at,
    });
    if (!journal_result.ok()) {
        result.status = journal_result.status == JournalStatus::RecoveryNotAuthorized
            ? RecoveryDecisionStatus::AuthorizationRequired
            : RecoveryDecisionStatus::JournalError;
        result.errors = journal_result.errors;
        return result;
    }

    if (authorization.decision == RecoveryDecision::Dismiss) {
        result.status = RecoveryDecisionStatus::Dismissed;
        return result;
    }

    auto child = *child_template;
    child.correlation_id = authorization.child_correlation_id;
    child.forge_request.invocation.invocation_id =
        authorization.child_correlation_id + ":attempt:0";
    child.zenkai_policy.retry_authority = authorization.child_retry_authority;
    child.parent_session_id = authorization.parent_session_id;
    child.recovery_authorization_sha256 = result.authorization_sha256;
    child.dojo_tags.push_back("recovery-decision:retry-as-new-session");
    child.dojo_tags.push_back("authority-receipt:" + gate.receipt_id);
    result.child_request = std::move(child);
    result.status = RecoveryDecisionStatus::RetryPrepared;
    return result;
}

std::string_view to_string(RecoveryDecision decision) noexcept {
    switch (decision) {
    case RecoveryDecision::Dismiss: return "DISMISS";
    case RecoveryDecision::RetryAsNewSession: return "RETRY_AS_NEW_SESSION";
    }
    return "DISMISS";
}

std::string_view to_string(RecoveryDecisionStatus status) noexcept {
    switch (status) {
    case RecoveryDecisionStatus::Dismissed: return "DISMISSED";
    case RecoveryDecisionStatus::RetryPrepared: return "RETRY_PREPARED";
    case RecoveryDecisionStatus::AuthorizationRequired: return "AUTHORIZATION_REQUIRED";
    case RecoveryDecisionStatus::ParentNotInterrupted: return "PARENT_NOT_INTERRUPTED";
    case RecoveryDecisionStatus::IdentityReuse: return "IDENTITY_REUSE";
    case RecoveryDecisionStatus::Invalid: return "INVALID";
    case RecoveryDecisionStatus::JournalError: return "JOURNAL_ERROR";
    }
    return "INVALID";
}

} // namespace guff
