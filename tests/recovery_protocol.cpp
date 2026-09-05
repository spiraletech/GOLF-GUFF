#include "guff/authority_gate.hpp"
#include "guff/caddy_router.hpp"
#include "guff/clubhouse.hpp"
#include "guff/dojo.hpp"
#include "guff/execution_session.hpp"
#include "guff/forge.hpp"
#include "guff/hardware_profile.hpp"
#include "guff/model_registry.hpp"
#include "guff/recovery_protocol.hpp"
#include "guff/scorecard.hpp"
#include "guff/session_journal.hpp"
#include "guff/sha256.hpp"

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

#define CHECK(expression)                                                                     \
    do {                                                                                      \
        if (!(expression)) {                                                                  \
            std::cerr << "CHECK failed: " #expression << " @ " << __FILE__ << ':'          \
                      << __LINE__ << '\n';                                                    \
            return 1;                                                                         \
        }                                                                                     \
    } while (false)

namespace {

class TestSigner final : public guff::AuthoritySigner, public guff::AuthorityVerifier {
public:
    std::string signer_id() const override { return "local:l16-recovery-signer"; }
    std::string algorithm() const override { return "TEST-SHA256"; }
    std::optional<std::string> sign(std::string_view canonical) const override {
        return guff::sha256(std::string("l16-recovery-secret\n") + std::string(canonical));
    }
    bool knows(std::string_view signer, std::string_view algorithm_name) const override {
        return signer == signer_id() && algorithm_name == algorithm();
    }
    bool verify(std::string_view signer,
                std::string_view algorithm_name,
                std::string_view canonical,
                std::string_view signature) const override {
        if (!knows(signer, algorithm_name)) return false;
        const auto expected = sign(canonical);
        return expected && *expected == signature;
    }
};

std::string session_id(std::string_view seed) {
    return "guff:session:sha256:" + guff::sha256(seed);
}

guff::SlotManifest compiler_slot() {
    guff::SlotManifest slot;
    slot.slot_name = "forge.recovery.compiler";
    slot.display_name = "Recovery Compiler";
    slot.version = "1.0.0";
    slot.kind = guff::SlotKind::Compiler;
    slot.transport = guff::SlotTransport::LocalProcess;
    slot.entrypoint = "native://recovery-test";
    slot.capabilities = {guff::SlotCapability::CodeBuild};
    slot.allowed_layers = {guff::RealityLayer::Project};
    slot.required_permissions = {"code:build", "device:execute"};
    slot.max_payload_bytes = 4096U;
    return slot;
}

guff::ExecutionSessionRequest child_template(std::string payload) {
    guff::ExecutionSessionRequest request;
    request.correlation_id = "template-correlation";
    request.route_request.signal = {
        .intent = "retry interrupted build as a fresh transaction",
        .layer = guff::RealityLayer::Project,
        .complexity = 0.20,
        .uncertainty = 0.10,
        .requires_execution = true,
        .destructive = false,
    };
    request.route_request.task = guff::TaskClass::Coding;
    request.route_request.profile_name = "recovery-protocol-v2";
    request.forge_request.invocation.invocation_id = "template-correlation:attempt:0";
    request.forge_request.invocation.slot_id = "forge.recovery.compiler";
    request.forge_request.invocation.capability = guff::SlotCapability::CodeBuild;
    request.forge_request.invocation.layer = guff::RealityLayer::Project;
    request.forge_request.invocation.input_sha256 = guff::sha256(payload);
    request.forge_request.invocation.payload_bytes = payload.size();
    request.forge_request.invocation.permission_tokens = {"code:build", "device:execute"};
    request.forge_request.payload = std::move(payload);
    request.forge_request.budget.max_wall_time_ms = 1000U;
    request.forge_request.budget.max_output_bytes = 1024U;
    request.zenkai_budget.max_attempts = 3U;
    request.zenkai_policy.retry_authority = guff::RetryAuthority::Bounded;
    request.session_budget.max_events = 32U;
    request.session_budget.max_event_detail_bytes = 256U;
    request.summary = "fresh recovery child";
    request.recorded_at_utc = "2026-09-05T02:10:00Z";
    request.dojo_tags = {"l16"};
    return request;
}

void sign_recovery(guff::RecoveryAuthorization& auth,
                   const TestSigner& signer,
                   std::string nonce,
                   std::string issued_at = "2026-09-05T02:11:00Z") {
    guff::AuthorityEnvelope envelope;
    envelope.purpose = guff::AuthorityPurpose::Recovery;
    envelope.subject_id = auth.parent_session_id;
    envelope.actor_reference = "human:l16-recovery";
    envelope.signer_id = signer.signer_id();
    envelope.issued_at_utc = std::move(issued_at);
    envelope.nonce = std::move(nonce);
    envelope.scope_sha256 = guff::recovery_authority_scope_sha256(auth);
    auth.authority_receipt = guff::issue_authority_receipt(envelope, signer);
}

} // namespace

int main() {
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-recovery-protocol-regression");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);

    TestSigner signer;
    guff::AuthorityGate authority_gate(signer);
    guff::SessionJournal journal(root / "session.journal");
    guff::RecoveryDecisionProtocol protocol(journal, authority_gate);

    const auto parent = session_id("l16-parent-1");
    const auto parent_begin = journal.begin({
        .session_id = parent,
        .correlation_id = "crashed-parent-001",
        .request_sha256 = guff::sha256("parent-request-1"),
        .recorded_at_utc = "2026-09-05T02:00:00Z",
    });
    CHECK(parent_begin.ok());

    guff::RecoveryAuthorization auth;
    auth.decision = guff::RecoveryDecision::RetryAsNewSession;
    auth.parent_session_id = parent;
    auth.parent_begin_record_sha256 = parent_begin.record_sha256;
    auth.child_correlation_id = "recovery-child-001";
    auth.child_retry_authority = guff::RetryAuthority::None;

    const auto missing_receipt = protocol.decide(auth, child_template("fresh-build"));
    CHECK(missing_receipt.status == guff::RecoveryDecisionStatus::AuthorizationRequired);
    CHECK(journal.inspect().interrupted.size() == 1U);

    auth.child_correlation_id = "crashed-parent-001";
    sign_recovery(auth, signer, "identity-reuse");
    const auto reused = protocol.decide(auth, child_template("fresh-build"));
    CHECK(reused.status == guff::RecoveryDecisionStatus::IdentityReuse);

    auth.child_correlation_id = "recovery-child-001";
    sign_recovery(auth, signer, "fresh-child");
    auto template_request = child_template("fresh-build");
    const auto prepared = protocol.decide(auth, template_request);
    CHECK(prepared.status == guff::RecoveryDecisionStatus::RetryPrepared);
    CHECK(prepared.child_request.has_value());
    CHECK(guff::is_sha256(prepared.authorization_sha256));
    CHECK(prepared.authorization_id.starts_with("guff:recovery-auth:sha256:"));
    CHECK(prepared.child_request->correlation_id == "recovery-child-001");
    CHECK(prepared.child_request->parent_session_id == parent);
    CHECK(prepared.child_request->recovery_authorization_sha256 == prepared.authorization_sha256);
    CHECK(prepared.child_request->zenkai_policy.retry_authority == guff::RetryAuthority::None);

    const auto bypass = journal.begin({
        .session_id = session_id("bypass-child"),
        .correlation_id = "recovery-child-001",
        .request_sha256 = guff::sha256("bypass"),
        .recorded_at_utc = "2026-09-05T02:12:00Z",
    });
    CHECK(bypass.status == guff::JournalStatus::RecoveryNotAuthorized);

    guff::ClubhouseRegistry clubhouse;
    CHECK(clubhouse.register_slot(compiler_slot()));
    guff::ForgeAdapter forge(clubhouse);
    guff::ModelRegistry models;
    guff::Scorecard scorecard;
    guff::CaddyRouter router(models, scorecard);
    guff::DojoStore dojo(root / "dojo.store");
    guff::ExecutionSessionOrchestrator orchestrator(router, clubhouse, forge, dojo, &journal);
    const auto hardware = guff::detect_hardware_profile();

    std::size_t executor_calls = 0U;
    const auto child_result = orchestrator.run(
        *prepared.child_request,
        hardware,
        [&](const guff::SlotManifest&,
            const guff::ForgeExecutionRequest&,
            guff::ForgeOutputSink& output) {
            ++executor_calls;
            static_cast<void>(output.write("fresh child execution passed"));
            return guff::ForgeExecutorReport{true, 0, 5U};
        });
    CHECK(child_result.succeeded());
    CHECK(executor_calls == 1U);
    CHECK(child_result.session_id != parent);

    const auto replayed = orchestrator.run(
        *prepared.child_request,
        hardware,
        [&](const guff::SlotManifest&,
            const guff::ForgeExecutionRequest&,
            guff::ForgeOutputSink&) {
            ++executor_calls;
            return guff::ForgeExecutorReport{true, 0, 1U};
        });
    CHECK(replayed.status == guff::SessionStatus::JournalStoreFailed);
    CHECK(executor_calls == 1U);

    const auto parent_two = session_id("l16-parent-2");
    const auto begin_two = journal.begin({
        .session_id = parent_two,
        .correlation_id = "crashed-parent-002",
        .request_sha256 = guff::sha256("parent-request-2"),
        .recorded_at_utc = "2026-09-05T02:20:00Z",
    });
    CHECK(begin_two.ok());
    guff::RecoveryAuthorization dismiss;
    dismiss.decision = guff::RecoveryDecision::Dismiss;
    dismiss.parent_session_id = parent_two;
    dismiss.parent_begin_record_sha256 = begin_two.record_sha256;
    dismiss.child_retry_authority = guff::RetryAuthority::None;
    sign_recovery(dismiss, signer, "dismiss", "2026-09-05T02:21:00Z");
    const auto dismissed = protocol.decide(dismiss);
    CHECK(dismissed.status == guff::RecoveryDecisionStatus::Dismissed);

    auto tampered = auth;
    CHECK(tampered.authority_receipt.has_value());
    tampered.authority_receipt->envelope.scope_sha256 = guff::sha256("tampered-scope");
    const auto rejected_tamper = protocol.decide(tampered, child_template("fresh-build"));
    CHECK(rejected_tamper.status == guff::RecoveryDecisionStatus::AuthorizationRequired);

    const auto inspection = journal.inspect();
    CHECK(inspection.healthy);
    const auto still_parent_two = std::find_if(
        inspection.interrupted.begin(), inspection.interrupted.end(),
        [&](const guff::InterruptedSession& item) { return item.session_id == parent_two; });
    CHECK(still_parent_two == inspection.interrupted.end());

    std::filesystem::remove_all(root, ec);
    return 0;
}
