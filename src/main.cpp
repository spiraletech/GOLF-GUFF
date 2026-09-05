#include "guff/authority_gate.hpp"
#include "guff/caddy_router.hpp"
#include "guff/clubhouse.hpp"
#include "guff/data_leech.hpp"
#include "guff/forge.hpp"
#include "guff/hardware_profile.hpp"
#include "guff/model_registry.hpp"
#include "guff/native_process.hpp"
#include "guff/reality.hpp"
#include "guff/scorecard.hpp"
#include "guff/scorecard_store.hpp"
#include "guff/session_journal.hpp"
#include "guff/sha256.hpp"
#include "guff/symbiosis_ledger.hpp"
#include "guff/zenkai.hpp"

#include <filesystem>
#include <iostream>
#include <utility>

int main() {
    guff::RealityStack reality;
    reality.observe({guff::RealityLayer::Project, "spiraletech/GOLF-GUFF", "ring", 1.0});
    reality.observe({guff::RealityLayer::Runtime, "native-cpp20", "guff-core", 1.0});
    reality.observe({guff::RealityLayer::Semantic, "authority-ledger", "L17", 1.0});

    const auto hardware = guff::detect_hardware_profile();
    guff::ModelRegistry registry;
    guff::Scorecard scorecard;
    guff::ScorecardStore store(std::filesystem::path("guff-scorecard.store"));
    guff::SessionJournal transaction_journal(std::filesystem::path("guff-transactions.journal"));
    const auto recovery = transaction_journal.inspect();
    guff::CaddyRouter router(registry, scorecard);

    guff::SourceGrant tool_grant;
    tool_grant.grant_id = "ring-bootstrap-tool-output";
    tool_grant.kind = guff::SourceKind::ToolOutput;
    tool_grant.scope = guff::GrantScope::Session;
    tool_grant.layer = guff::RealityLayer::Runtime;
    tool_grant.locator_prefix = "tool://guff/";
    tool_grant.max_source_bytes = 4096U;
    tool_grant.max_slice_bytes = 1024U;

    guff::SymbiosisGrant symbiosis_grant;
    symbiosis_grant.source = tool_grant;
    symbiosis_grant.retention.persist_grant = false;
    symbiosis_grant.retention.persist_observation_stamps = false;
    symbiosis_grant.retention.allow_memory_promotion = false;
    symbiosis_grant.retention.max_observation_stamps = 8U;
    symbiosis_grant.issued_at_unix_ms = 1U;

    guff::SymbiosisLedger symbiosis;
    const auto grant_result = symbiosis.create_grant(symbiosis_grant);

    guff::DataLeech leech;
    const auto delta = leech.observe_text(
        tool_grant,
        "tool://guff/bootstrap",
        "L17 authority ledger online");

    if (delta.current) {
        static_cast<void>(symbiosis.stamp_observation(
            tool_grant.grant_id, *delta.current, 2U));
    }

    guff::ContextArena context({.max_slices = 4U, .max_total_bytes = 4096U});
    if (auto slice = leech.slice_text(
            tool_grant,
            "tool://guff/bootstrap",
            "L17 authority ledger online",
            0U,
            1024U)) {
        static_cast<void>(context.add(std::move(*slice)));
    }

    guff::ModelRouteRequest request;
    request.signal = {
        .intent = "select the best verified coding club",
        .layer = guff::RealityLayer::Project,
        .complexity = 0.60,
        .uncertainty = 0.20,
        .requires_execution = true,
        .destructive = false,
    };
    request.task = guff::TaskClass::Coding;
    request.profile_name = "cpp-build-repair-v1";
    const auto decision = router.select(request, hardware);

    guff::ZenkaiLoop zenkai({.max_attempts = 2U,
                             .max_tool_events = 4U,
                             .max_evidence_items = 8U,
                             .max_evidence_bytes = 4096U,
                             .max_trace_entries = 16U,
                             .acceptance_confidence = 0.90,
                             .max_detail_bytes = 1024U});
    const auto zenkai_result = zenkai.run(
        "bootstrap-candidate",
        {.retry_authority = guff::RetryAuthority::Bounded},
        [](std::size_t attempt, std::string_view previous) {
            guff::ZenkaiAttempt result;
            if (attempt == 0U) {
                result.candidate_state = "bootstrap-candidate-v1";
                result.evidence = {{guff::EvidenceKind::Build, "bootstrap-build", false, "synthetic first-pass failure"}};
                result.verification = {false, 0.55, "first pass not verified"};
                return result;
            }
            result.candidate_state = std::string(previous) + "+verified";
            result.evidence = {
                {guff::EvidenceKind::Build, "bootstrap-build", true, "synthetic build pass"},
                {guff::EvidenceKind::Test, "bootstrap-test", true, "synthetic test pass"},
            };
            result.verification = {true, 0.98, "bootstrap evidence verified"};
            return result;
        });

    guff::ClubhouseRegistry clubhouse;
    guff::NativeProcessRegistry native_processes;

    guff::SlotManifest compiler;
    compiler.slot_name = "forge.compiler";
    compiler.display_name = "FORGE Compiler Adapter";
    compiler.version = "1.0.0";
    compiler.kind = guff::SlotKind::Compiler;
    compiler.transport = guff::SlotTransport::LocalProcess;
    compiler.entrypoint = "forge://compiler";
    compiler.capabilities = {guff::SlotCapability::CodeBuild, guff::SlotCapability::CodeTest};
    compiler.allowed_layers = {guff::RealityLayer::Project, guff::RealityLayer::Runtime};
    compiler.required_permissions = {"code:build", "device:execute"};
    compiler.max_payload_bytes = 4096U;
    static_cast<void>(clubhouse.register_slot(compiler));

    const std::string forge_payload = "build target guff_core";
    guff::ForgeExecutionRequest forge_request;
    forge_request.invocation.invocation_id = "bootstrap-forge-build";
    forge_request.invocation.slot_id = "forge.compiler";
    forge_request.invocation.capability = guff::SlotCapability::CodeBuild;
    forge_request.invocation.layer = guff::RealityLayer::Project;
    forge_request.invocation.input_sha256 = guff::sha256(forge_payload);
    forge_request.invocation.payload_bytes = forge_payload.size();
    forge_request.invocation.permission_tokens = {"code:build", "device:execute"};
    forge_request.payload = forge_payload;
    forge_request.budget.max_wall_time_ms = 1000U;
    forge_request.budget.max_output_bytes = 1024U;

    guff::ForgeAdapter forge(clubhouse);
    const auto forge_result = forge.execute(
        forge_request,
        [](const guff::SlotManifest&, const guff::ForgeExecutionRequest&, guff::ForgeOutputSink& output) {
            static_cast<void>(output.write("synthetic compiler execution passed"));
            return guff::ForgeExecutorReport{true, 0, 5U};
        });

    std::cout << "GOLF GUFF / RING L17\n";
    std::cout << "REALITY: " << reality.describe() << '\n';
    std::cout << "HARDWARE-ID: " << hardware.immutable_id() << '\n';
    std::cout << "SCORECARD-STORE: " << store.path().string() << " (lazy hydration)\n";
    std::cout << "DATA-LEECH: " << guff::to_string(delta.state)
              << " scope=" << guff::to_string(tool_grant.scope)
              << " hot_slices=" << context.slices().size()
              << " hot_bytes=" << context.used_bytes() << '\n';
    std::cout << "SYMBIOSIS: " << guff::to_string(grant_result.status)
              << " state=" << guff::to_string(symbiosis.grant_state(tool_grant.grant_id, 2U))
              << " stamps=" << symbiosis.stamp_count()
              << " promotions=" << symbiosis.promotion_count() << '\n';
    std::cout << "ZENKAI: " << guff::to_string(zenkai_result.stop_reason)
              << " attempts=" << zenkai_result.attempts
              << " verified=" << (zenkai_result.verified ? "yes" : "no") << '\n';
    std::cout << "CLUBHOUSE: slots=" << clubhouse.size() << '\n';
    std::cout << "FORGE: " << guff::to_string(forge_result.status)
              << " invocation=" << guff::to_string(forge_result.invocation_status)
              << " evidence=" << forge_result.evidence.size()
              << " output_bytes=" << forge_result.observed_output_bytes << '\n';
    std::cout << "NATIVE-PROCESS: bindings=" << native_processes.size()
              << " shell=disabled argv=direct\n";
    std::cout << "TRANSACTION-JOURNAL: healthy=" << (recovery.healthy ? "yes" : "no")
              << " records=" << recovery.records
              << " interrupted=" << recovery.interrupted.size()
              << " lineage=" << recovery.recovery_lineage.size() << '\n';
    std::cout << "AUTHORITY-GATE: recovery=receipt destructive=receipt persistent-symbiosis=receipt"
              << " barcode=transport-only\n";
    std::cout << "AUTHORITY-LEDGER: schema=v2 expiry=on replay-defense=on revocation=on"
              << " use-budget=signed key-rotation=on\n";
    std::cout << "CADDY-ROUTER: " << guff::to_string(decision.status)
              << " depth=" << decision.recursion_depth
              << " verify=" << (decision.require_verification ? "yes" : "no") << '\n';
    std::cout << "REASON: " << decision.reason << '\n';

    return 0;
}
