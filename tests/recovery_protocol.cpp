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

#include <filesystem>
#include <iostream>
#include <string>

#define CHECK(expression)                                                                     \
    do {                                                                                      \
        if (!(expression)) {                                                                  \
            std::cerr << "CHECK failed: " #expression << " @ " << __FILE__ << ':'          \
                      << __LINE__ << '\n';                                                    \
            return 1;                                                                         \
        }                                                                                     \
    } while (false)

namespace {

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
    request.route_request.profile_name = "recovery-protocol-v1";
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
    request.zenkai_budget.max_tool_events = 4U;
    request.zenkai_budget.max_evidence_items = 8U;
    request.zenkai_budget.max_evidence_bytes = 4096U;
    request.zenkai_budget.max_trace_entries = 16U;
    request.zenkai_budget.acceptance_confidence = 0.90;
    request.zenkai_budget.max_detail_bytes = 512U;
    request.zenkai_policy.retry_authority = guff::RetryAuthority::Bounded;
    request.session_budget.max_events = 32U;
    request.session_budget.max_event_detail_bytes = 256U;
    request.summary = "fresh recovery child";
    request.recorded_at_utc = "2026-09-04T17:30:00-07:00";
    request.dojo_tags = {"l14"};
    return request;
}

} // namespace

int main() {
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-recovery-protocol-regression");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root);

    guff::SessionJournal journal(root / "session.journal");
    guff::RecoveryDecisionProtocol protocol(journal);

    const auto parent = session_id("l14-parent-1");
    const auto parent_request = guff::sha256("parent-request-1");
    const auto parent_begin = journal.begin({
        .session_id = parent,
        .correlation_id = "crashed-parent-001",
        .request_sha256 = parent_request,
        .recorded_at_utc = "2026-09-04T17:00:00-07:00",
    });
    CHECK(parent_begin.ok());

    guff::RecoveryAuthorization auth;
    auth.approved = false;
    auth.decision = guff::RecoveryDecision::RetryAsNewSession;
    auth.parent_session_id = parent;
    auth.parent_begin_record_sha256 = parent_begin.record_sha256;
    auth.actor_reference = "human:test-operator";
    auth.issued_at_utc = "2026-09-04T17:31:00-07:00";
    auth.child_correlation_id = "recovery-child-001";
    auth.child_retry_authority = guff::RetryAuthority::None;

    const auto denied = protocol.decide(auth, child_template("fresh-build"));
    CHECK(denied.status == guff::RecoveryDecisionStatus::AuthorizationRequired);
    CHECK(journal.inspect().interrupted.size() == 1U);

    auth.approved = true;
    auth.child_correlation_id = "crashed-parent-001";
    const auto reused = protocol.decide(auth, child_template("fresh-build"));
    CHECK(reused.status == guff::RecoveryDecisionStatus::IdentityReuse);
    CHECK(journal.inspect().interrupted.size() == 1U);

    auth.child_correlation_id = "recovery-child-001";
    auto template_request = child_template("fresh-build");
    CHECK(template_request.zenkai_policy.retry_authority == guff::RetryAuthority::Bounded);
    const auto prepared = protocol.decide(auth, template_request);
    CHECK(prepared.status == guff::RecoveryDecisionStatus::RetryPrepared);
    CHECK(prepared.child_request.has_value());
    CHECK(guff::is_sha256(prepared.authorization_sha256));
    CHECK(prepared.authorization_id.starts_with("guff:recovery-auth:sha256:"));
    CHECK(prepared.child_request->correlation_id == "recovery-child-001");
    CHECK(prepared.child_request->parent_session_id == parent);
    CHECK(prepared.child_request->recovery_authorization_sha256 == prepared.authorization_sha256);
    CHECK(prepared.child_request->zenkai_policy.retry_authority == guff::RetryAuthority::None);
    CHECK(prepared.child_request->forge_request.invocation.invocation_id ==
          "recovery-child-001:attempt:0");

    auto inspection = journal.inspect();
    CHECK(inspection.healthy);
    CHECK(inspection.interrupted.empty());
    CHECK(inspection.recovery_lineage.size() == 1U);
    CHECK(!inspection.recovery_lineage.front().child_started);
    CHECK(inspection.recovery_lineage.front().parent_session_id == parent);
    CHECK(inspection.recovery_lineage.front().authorization_sha256 == prepared.authorization_sha256);

    const auto bypass = journal.begin({
        .session_id = session_id("bypass-child"),
        .correlation_id = "recovery-child-001",
        .request_sha256 = guff::sha256("bypass"),
        .recorded_at_utc = "2026-09-04T17:32:00-07:00",
    });
    CHECK(bypass.status == guff::JournalStatus::RecoveryNotAuthorized);

    guff::ClubhouseRegistry clubhouse;
    const auto slot = compiler_slot();
    CHECK(clubhouse.register_slot(slot));
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
    CHECK(child_result.correlation_id == "recovery-child-001");
    CHECK(child_result.session_id != parent);
    CHECK(child_result.zenkai.attempts == 1U);

    inspection = journal.inspect();
    CHECK(inspection.healthy);
    CHECK(inspection.recovery_lineage.size() == 1U);
    CHECK(inspection.recovery_lineage.front().child_started);
    CHECK(inspection.recovery_lineage.front().child_session_id == child_result.session_id);

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

    const auto episodes = dojo.replay();
    CHECK(episodes.size() == 1U);
    bool saw_parent = false;
    bool saw_authorization = false;
    for (const auto& tag : episodes.front().tags) {
        if (tag == "recovery-parent:" + parent) saw_parent = true;
        if (tag == "recovery-authorization:" + prepared.authorization_sha256)
            saw_authorization = true;
    }
    CHECK(saw_parent);
    CHECK(saw_authorization);

    const auto parent_two = session_id("l14-parent-2");
    const auto begin_two = journal.begin({
        .session_id = parent_two,
        .correlation_id = "crashed-parent-002",
        .request_sha256 = guff::sha256("parent-request-2"),
        .recorded_at_utc = "2026-09-04T17:40:00-07:00",
    });
    CHECK(begin_two.ok());
    guff::RecoveryAuthorization auth_two{
        .approved = true,
        .decision = guff::RecoveryDecision::RetryAsNewSession,
        .parent_session_id = parent_two,
        .parent_begin_record_sha256 = begin_two.record_sha256,
        .actor_reference = "human:test-operator",
        .issued_at_utc = "2026-09-04T17:41:00-07:00",
        .child_correlation_id = "recovery-child-002",
        .child_retry_authority = guff::RetryAuthority::None,
    };
    auto prepared_two = protocol.decide(auth_two, child_template("second-build"));
    CHECK(prepared_two.ok());
    CHECK(prepared_two.child_request.has_value());
    prepared_two.child_request->recovery_authorization_sha256 = guff::sha256("tampered-auth");
    const auto tampered = orchestrator.run(
        *prepared_two.child_request,
        hardware,
        [&](const guff::SlotManifest&,
            const guff::ForgeExecutionRequest&,
            guff::ForgeOutputSink&) {
            ++executor_calls;
            return guff::ForgeExecutorReport{true, 0, 1U};
        });
    CHECK(tampered.status == guff::SessionStatus::JournalStoreFailed);
    CHECK(executor_calls == 1U);

    const auto parent_three = session_id("l14-parent-3");
    const auto begin_three = journal.begin({
        .session_id = parent_three,
        .correlation_id = "crashed-parent-003",
        .request_sha256 = guff::sha256("parent-request-3"),
        .recorded_at_utc = "2026-09-04T17:50:00-07:00",
    });
    CHECK(begin_three.ok());
    guff::RecoveryAuthorization dismiss{
        .approved = true,
        .decision = guff::RecoveryDecision::Dismiss,
        .parent_session_id = parent_three,
        .parent_begin_record_sha256 = begin_three.record_sha256,
        .actor_reference = "human:test-operator",
        .issued_at_utc = "2026-09-04T17:51:00-07:00",
        .child_correlation_id = {},
        .child_retry_authority = guff::RetryAuthority::None,
    };
    const auto dismissed = protocol.decide(dismiss);
    CHECK(dismissed.status == guff::RecoveryDecisionStatus::Dismissed);
    inspection = journal.inspect();
    CHECK(inspection.healthy);
    const auto still_interrupted = std::find_if(
        inspection.interrupted.begin(), inspection.interrupted.end(),
        [&](const guff::InterruptedSession& item) {
            return item.session_id == parent_three;
        });
    CHECK(still_interrupted == inspection.interrupted.end());

    std::filesystem::remove_all(root, ec);
    return 0;
}
