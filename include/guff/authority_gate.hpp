#pragma once

#include "guff/authority_receipt.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

struct ExecutionSessionRequest;
struct HardwareProfile;
struct SymbiosisGrant;
class ExecutionSessionOrchestrator;
class SymbiosisLedger;
struct ExecutionSessionResult;
struct LedgerResult;
class SlotManifest;
class ForgeOutputSink;
struct ForgeExecutionRequest;
struct ForgeExecutorReport;

enum class AuthorityGateStatus : std::uint8_t {
    Allowed,
    ReceiptMissing,
    ReceiptRejected,
    ScopeMismatch
};

struct AuthorityGateResult {
    AuthorityGateStatus status{AuthorityGateStatus::ReceiptMissing};
    std::string receipt_id;
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

class AuthorityGate {
public:
    explicit AuthorityGate(const AuthorityVerifier& verifier) noexcept;

    [[nodiscard]] AuthorityGateResult authorize(
        const std::optional<AuthorityReceipt>& receipt,
        AuthorityPurpose purpose,
        std::string_view subject_id,
        std::string_view scope_sha256) const;

private:
    const AuthorityVerifier& verifier_;
};

[[nodiscard]] std::string destructive_execution_scope_sha256(
    const ExecutionSessionRequest& request,
    const HardwareProfile& hardware);

[[nodiscard]] std::string persistent_symbiosis_scope_sha256(
    const SymbiosisGrant& grant);

struct GatedExecutionResult {
    AuthorityGateResult authority;
    std::optional<ExecutionSessionResult> session;

    [[nodiscard]] bool executed() const noexcept;
};

class AuthorityGatedExecutionSession {
public:
    AuthorityGatedExecutionSession(const AuthorityGate& gate,
                                   const ExecutionSessionOrchestrator& orchestrator) noexcept;

    [[nodiscard]] GatedExecutionResult run(
        const ExecutionSessionRequest& request,
        const HardwareProfile& hardware,
        const std::optional<AuthorityReceipt>& receipt,
        const std::function<ForgeExecutorReport(
            const SlotManifest&,
            const ForgeExecutionRequest&,
            ForgeOutputSink&)>& executor) const;

private:
    const AuthorityGate& gate_;
    const ExecutionSessionOrchestrator& orchestrator_;
};

class AuthorityGatedSymbiosis {
public:
    AuthorityGatedSymbiosis(const AuthorityGate& gate,
                            SymbiosisLedger& ledger) noexcept;

    [[nodiscard]] LedgerResult create_grant(
        SymbiosisGrant grant,
        const std::optional<AuthorityReceipt>& receipt = std::nullopt) const;

private:
    const AuthorityGate& gate_;
    SymbiosisLedger& ledger_;
};

[[nodiscard]] std::string_view to_string(AuthorityGateStatus status) noexcept;

} // namespace guff
