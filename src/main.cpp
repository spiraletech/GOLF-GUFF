#include "guff/caddy_router.hpp"
#include "guff/clubhouse.hpp"
#include "guff/data_leech.hpp"
#include "guff/hardware_profile.hpp"
#include "guff/model_registry.hpp"
#include "guff/reality.hpp"
#include "guff/scorecard.hpp"
#include "guff/scorecard_store.hpp"
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
    reality.observe({guff::RealityLayer::Semantic, "clubhouse-slot-capability-bus", "L9", 1.0});

    const auto hardware = guff::detect_hardware_profile();
    guff::ModelRegistry registry;
    guff::Scorecard scorecard;
    guff::ScorecardStore store(std::filesystem::path("guff-scorecard.store"));
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
        "L9 CLUBHOUSE capability bus online");

    if (delta.current) {
        static_cast<void>(symbiosis.stamp_observation(
            tool_grant.grant_id, *delta.current, 2U));
    }

    guff::ContextArena context({.max_slices = 4U, .max_total_bytes = 4096U});
    if (auto slice = leech.slice_text(
            tool_grant,
            "tool://guff/bootstrap",
            "L9 CLUBHOUSE capability bus online",
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
    guff::SlotManifest xenon;
    xenon.slot_name = "xenon";
    xenon.display_name = "XENON Music Trinity";
    xenon.version = "1.0.0";
    xenon.kind = guff::SlotKind::Audio;
    xenon.transport = guff::SlotTransport::LocalProcess;
    xenon.entrypoint = "xenon://native";
    xenon.capabilities = {guff::SlotCapability::AudioAnalyze, guff::SlotCapability::AudioGenerate};
    xenon.allowed_layers = {guff::RealityLayer::Application, guff::RealityLayer::Representation};
    xenon.required_permissions = {"audio:generate", "device:execute"};
    xenon.max_payload_bytes = 4096U;
    static_cast<void>(clubhouse.register_slot(xenon));

    guff::SlotInvocation slot_invocation;
    slot_invocation.invocation_id = "bootstrap-xenon";
    slot_invocation.slot_id = "xenon";
    slot_invocation.capability = guff::SlotCapability::AudioGenerate;
    slot_invocation.layer = guff::RealityLayer::Application;
    slot_invocation.input_sha256 = guff::sha256("bootstrap four-bar generation request");
    slot_invocation.payload_bytes = 128U;
    slot_invocation.permission_tokens = {"audio:generate", "device:execute"};
    const auto slot_resolution = clubhouse.resolve(slot_invocation);

    std::cout << "GOLF GUFF / RING L9\n";
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
    std::cout << "CLUBHOUSE: slots=" << clubhouse.size()
              << " xenon=" << guff::to_string(slot_resolution.status)
              << " capability=" << guff::to_string(slot_invocation.capability) << '\n';
    std::cout << "CADDY-ROUTER: " << guff::to_string(decision.status)
              << " depth=" << decision.recursion_depth
              << " verify=" << (decision.require_verification ? "yes" : "no") << '\n';
    std::cout << "REASON: " << decision.reason << '\n';

    return 0;
}
