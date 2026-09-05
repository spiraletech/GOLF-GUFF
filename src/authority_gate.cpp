#include "guff/authority_gate.hpp"

#include "guff/hardware_profile.hpp"
#include "guff/sha256.hpp"

#include <sstream>
#include <utility>

namespace guff {

bool AuthorityGateResult::ok() const noexcept {
    return status == AuthorityGateStatus::Allowed;
}

AuthorityGate::AuthorityGate(const AuthorityVerifier& verifier) noexcept
    : verifier_(verifier) {}

AuthorityGateResult AuthorityGate::authorize(
    const std::optional<AuthorityReceipt>& receipt,
    AuthorityPurpose purpose,
    std::string_view subject_id,
    std::string_view scope_sha256) const {
    AuthorityGateResult result;
    if (!receipt) {
        result.status = AuthorityGateStatus::ReceiptMissing;
        result.errors.emplace_back("privileged operation requires an authority receipt");
        return result;
    }
    result.receipt_id = receipt->receipt_id;
    const auto verified = verify_authority_receipt(
        *receipt, verifier_, purpose, subject_id);
    if (!verified.ok()) {
        result.status = AuthorityGateStatus::ReceiptRejected;
        result.errors = verified.errors;
        return result;
    }
    if (receipt->envelope.scope_sha256 != scope_sha256) {
        result.status = AuthorityGateStatus::ScopeMismatch;
        result.errors.emplace_back("authority receipt scope does not match privileged operation");
        return result;
    }
    result.status = AuthorityGateStatus::Allowed;
    return result;
}

std::string destructive_execution_scope_sha256(
    const ExecutionSessionRequest& request,
    const HardwareProfile& hardware) {
    std::ostringstream canonical;
    canonical << execution_session_id(request, hardware) << '\n'
              << execution_request_sha256(request, hardware) << '\n'
              << request.forge_request.invocation.slot_id << '\n'
              << static_cast<unsigned>(request.forge_request.invocation.capability) << '\n'
              << static_cast<unsigned>(request.forge_request.invocation.layer) << '\n'
              << request.forge_request.invocation.input_sha256 << '\n'
              << request.forge_request.invocation.payload_bytes;
    return sha256(canonical.str());
}

std::string persistent_symbiosis_scope_sha256(const SymbiosisGrant& grant) {
    std::ostringstream canonical;
    canonical << grant.source.grant_id << '\n'
              << static_cast<unsigned>(grant.source.kind) << '\n'
              << static_cast<unsigned>(grant.source.scope) << '\n'
              << static_cast<unsigned>(grant.source.layer) << '\n'
              << grant.source.root.generic_string() << '\n'
              << grant.source.locator_prefix << '\n'
              << (grant.source.recursive ? 1 : 0) << '\n'
              << grant.source.max_source_bytes << '\n'
              << grant.source.max_slice_bytes << '\n'
              << (grant.retention.persist_grant ? 1 : 0) << '\n'
              << (grant.retention.persist_observation_stamps ? 1 : 0) << '\n'
              << (grant.retention.allow_memory_promotion ? 1 : 0) << '\n'
              << grant.retention.max_promotion_bytes << '\n'
              << grant.retention.max_observation_stamps << '\n'
              << grant.issued_at_unix_ms << '\n'
              << grant.expires_at_unix_ms;
    return sha256(canonical.str());
}

bool GatedExecutionResult::executed() const noexcept {
    return session.has_value();
}

AuthorityGatedExecutionSession::AuthorityGatedExecutionSession(
    const AuthorityGate& gate,
    const ExecutionSessionOrchestrator& orchestrator) noexcept
    : gate_(gate), orchestrator_(orchestrator) {}

GatedExecutionResult AuthorityGatedExecutionSession::run(
    const ExecutionSessionRequest& request,
    const HardwareProfile& hardware,
    const std::optional<AuthorityReceipt>& receipt,
    const ForgeAdapter::ExecutorFunction& executor) const {
    GatedExecutionResult result;
    if (request.route_request.signal.destructive) {
        result.authority = gate_.authorize(
            receipt,
            AuthorityPurpose::DestructiveExecution,
            execution_session_id(request, hardware),
            destructive_execution_scope_sha256(request, hardware));
        if (!result.authority.ok()) return result;
    } else {
        result.authority.status = AuthorityGateStatus::Allowed;
    }
    result.session = orchestrator_.run(request, hardware, executor);
    return result;
}

AuthorityGatedSymbiosis::AuthorityGatedSymbiosis(
    const AuthorityGate& gate,
    SymbiosisLedger& ledger) noexcept
    : gate_(gate), ledger_(ledger) {}

LedgerResult AuthorityGatedSymbiosis::create_grant(
    SymbiosisGrant grant,
    const std::optional<AuthorityReceipt>& receipt) const {
    const bool persistent = grant.retention.persist_grant ||
                            grant.retention.persist_observation_stamps ||
                            grant.retention.allow_memory_promotion;
    if (persistent) {
        const auto authorization = gate_.authorize(
            receipt,
            AuthorityPurpose::PersistentSymbiosis,
            grant.source.grant_id,
            persistent_symbiosis_scope_sha256(grant));
        if (!authorization.ok()) {
            LedgerResult denied;
            denied.status = LedgerStatus::Denied;
            denied.id = grant.source.grant_id;
            denied.errors = authorization.errors;
            return denied;
        }
    }
    return ledger_.create_grant(std::move(grant));
}

std::string_view to_string(AuthorityGateStatus status) noexcept {
    switch (status) {
    case AuthorityGateStatus::Allowed: return "ALLOWED";
    case AuthorityGateStatus::ReceiptMissing: return "RECEIPT_MISSING";
    case AuthorityGateStatus::ReceiptRejected: return "RECEIPT_REJECTED";
    case AuthorityGateStatus::ScopeMismatch: return "SCOPE_MISMATCH";
    }
    return "RECEIPT_REJECTED";
}

} // namespace guff
