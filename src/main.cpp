#include "guff/caddy_router.hpp"
#include "guff/data_leech.hpp"
#include "guff/hardware_profile.hpp"
#include "guff/model_registry.hpp"
#include "guff/reality.hpp"
#include "guff/scorecard.hpp"
#include "guff/scorecard_store.hpp"
#include "guff/symbiosis_ledger.hpp"
#include "guff/zenkai.hpp"

#include <filesystem>
#include <iostream>
#include <utility>

int main() {
    guff::RealityStack reality;
    reality.observe({guff::RealityLayer::Project, "spiraletech/GOLF-GUFF", "ring", 1.0});
    reality.observe({guff::RealityLayer::Runtime, "native-cpp20", "guff-core", 1.0});
    reality.observe({guff::RealityLayer::Semantic, "zenkai-verification-loop", "L7", 1.0});

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
        "L7 bounded verification source online");

    if (delta.current) {
        static_cast<void>(symbiosis.stamp_observation(
            tool_grant.grant_id, *delta.current, 2U));
    }

    guff::ContextArena context({.max_slices = 4U, .max_total_bytes = 4096U});
    if (auto slice = leech.slice_text(
            tool_grant,
            "tool://guff/bootstrap",
            "L7 bounded verification source online",
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

    guff::ZenkaiBudget zenkai_budget;
    zenkai_budget.max_attempts = 2U;
    zenkai_budget.max_tool_events = 4U;
    zenkai_budget.max_evidence_items = 8U;
    zenkai_budget.max_evidence_bytes = 4096U;
    zenkai_budget.acceptance_confidence = 0.90;
    guff::ZenkaiLoop zenkai(zenkai_budget);

    const auto zenkai_result = zenkai.run(
        "bootstrap-candidate",
        {.retry_authority = guff::RetryAuthority::Bounded},
        [](std::size_t attempt, std::string_view previous) {
            guff::ZenkaiAttempt result;
            if (attempt == 0U) {
                result.candidate_state = "bootstrap-candidate-v1";
                result.evidence = {
                    {guff::EvidenceKind::Build, "bootstrap-build", false, "synthetic first-pass failure"},
                };
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

    std::cout << "GOLF GUFF / RING L7\n";
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
              << " evidence=" << zenkai_result.evidence_items
              << " tool_events=" << zenkai_result.tool_events
              << " verified=" << (zenkai_result.verified ? "yes" : "no") << '\n';
    std::cout << "CADDY-ROUTER: " << guff::to_string(decision.status)
              << " depth=" << decision.recursion_depth
              << " verify=" << (decision.require_verification ? "yes" : "no") << '\n';
    std::cout << "REASON: " << decision.reason << '\n';
    std::cout << "TRACE: " << decision.trace.describe() << '\n';

    if (decision.selected_model_id) {
        std::cout << "MODEL-ID: " << *decision.selected_model_id << '\n';
    } else {
        std::cout << "MODEL-ID: none (hydrate trusted benchmark evidence before selection)\n";
    }

    return 0;
}
