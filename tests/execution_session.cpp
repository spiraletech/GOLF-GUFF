#include "guff/caddy_router.hpp"
#include "guff/clubhouse.hpp"
#include "guff/dojo.hpp"
#include "guff/execution_session.hpp"
#include "guff/forge.hpp"
#include "guff/hardware_profile.hpp"
#include "guff/model_registry.hpp"
#include "guff/native_process.hpp"
#include "guff/scorecard.hpp"
#include "guff/sha256.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <thread>
#include <utility>

#define CHECK(expression)                                                                     \
    do {                                                                                      \
        if (!(expression)) {                                                                  \
            std::cerr << "CHECK failed: " #expression << " @ " << __FILE__ << ':'          \
                      << __LINE__ << '\n';                                                    \
            return 1;                                                                         \
        }                                                                                     \
    } while (false)

namespace {

guff::SlotManifest compiler_slot() {
    guff::SlotManifest slot;
    slot.slot_name = "forge.session.compiler";
    slot.display_name = "Execution Session Compiler";
    slot.version = "1.0.0";
    slot.kind = guff::SlotKind::Compiler;
    slot.transport = guff::SlotTransport::LocalProcess;
    slot.entrypoint = "native://execution-session-test";
    slot.capabilities = {guff::SlotCapability::CodeBuild};
    slot.allowed_layers = {guff::RealityLayer::Project};
    slot.required_permissions = {"code:build", "device:execute"};
    slot.max_payload_bytes = 16U * 1024U;
    return slot;
}

guff::NativeProcessBinding binding_for(const std::filesystem::path& executable,
                                       const std::filesystem::path& root) {
    guff::NativeProcessBinding binding;
    binding.executable = executable;
    binding.arguments = {"--guff-session-child"};
    binding.payload_mode = guff::NativePayloadMode::SingleArgument;
    binding.working_root = root;
    binding.working_directory = root / "work";
    binding.environment = {{"GUFF_SESSION_ENV", "transaction"}};
    binding.limits.max_arguments = 8U;
    binding.limits.max_argument_bytes = 16U * 1024U;
    binding.limits.max_environment_entries = 8U;
    binding.limits.max_environment_bytes = 4096U;
    return binding;
}

guff::ForgeExecutionRequest forge_request(std::string correlation,
                                          std::string invocation_suffix,
                                          std::string payload,
                                          bool include_device_permission = true) {
    guff::ForgeExecutionRequest request;
    request.invocation.invocation_id = correlation + ":" + invocation_suffix;
    request.invocation.slot_id = "forge.session.compiler";
    request.invocation.capability = guff::SlotCapability::CodeBuild;
    request.invocation.layer = guff::RealityLayer::Project;
    request.invocation.input_sha256 = guff::sha256(payload);
    request.invocation.payload_bytes = payload.size();
    request.invocation.permission_tokens = {"code:build"};
    if (include_device_permission) request.invocation.permission_tokens.push_back("device:execute");
    request.payload = std::move(payload);
    request.budget.max_wall_time_ms = 1000U;
    request.budget.max_output_bytes = 4096U;
    return request;
}

guff::ExecutionSessionRequest session_request(std::string correlation,
                                               std::string payload) {
    guff::ExecutionSessionRequest request;
    request.correlation_id = correlation;
    request.route_request.signal = {
        .intent = "build the current C++ target",
        .layer = guff::RealityLayer::Project,
        .complexity = 0.20,
        .uncertainty = 0.10,
        .requires_execution = true,
        .destructive = false,
    };
    request.route_request.task = guff::TaskClass::Coding;
    request.route_request.profile_name = "execution-session-regression-v1";
    request.forge_request = forge_request(correlation, "attempt:0", std::move(payload));
    request.zenkai_budget.max_attempts = 2U;
    request.zenkai_budget.max_tool_events = 4U;
    request.zenkai_budget.max_evidence_items = 8U;
    request.zenkai_budget.max_evidence_bytes = 4096U;
    request.zenkai_budget.max_trace_entries = 16U;
    request.zenkai_budget.acceptance_confidence = 0.90;
    request.zenkai_budget.max_detail_bytes = 1024U;
    request.zenkai_policy.retry_authority = guff::RetryAuthority::Bounded;
    request.session_budget.max_events = 32U;
    request.session_budget.max_event_detail_bytes = 256U;
    request.session_budget.max_artifacts = 1U;
    request.session_budget.max_artifact_bytes = 1024U;
    request.summary = "L12 correlated native execution regression";
    request.recorded_at_utc = "2026-09-04T17:07:00-07:00";
    request.dojo_tags = {"l12", "native-process"};
    return request;
}

} // namespace

int main(int argc, char** argv) {
    if (argc >= 2 && std::string(argv[1]) == "--guff-session-child") {
        const std::string payload = argc >= 3 ? argv[2] : "";
        const char* environment = std::getenv("GUFF_SESSION_ENV");
        std::cout << "PAYLOAD:" << payload << '\n';
        std::cout << "ENV:" << (environment ? environment : "missing") << '\n';
        std::cout << "CWD:" << std::filesystem::current_path().string() << '\n';
        if (payload == "fail-first") {
            std::cerr << "first attempt failed" << '\n';
            return 7;
        }
        std::cerr << "session-child-stderr" << '\n';
        return 0;
    }

    const auto executable = std::filesystem::absolute(argv[0]);
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-execution-session-regression");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root / "work");

    guff::ClubhouseRegistry clubhouse;
    const auto slot = compiler_slot();
    CHECK(clubhouse.register_slot(slot));

    guff::NativeProcessRegistry processes;
    CHECK(processes.bind(slot, binding_for(executable, root)));
    guff::NativeLocalProcessExecutor native(processes);
    guff::ForgeAdapter forge(clubhouse);

    guff::ModelRegistry models;
    guff::Scorecard scorecard;
    guff::CaddyRouter router(models, scorecard);
    guff::DojoStore dojo(root / "dojo.store");
    guff::ExecutionSessionOrchestrator orchestrator(router, clubhouse, forge, dojo);
    const auto hardware = guff::detect_hardware_profile();

    const std::string literal_payload = "literal & | < > ^ % ! \"quoted\" \\ tail";
    auto request = session_request("corr-l12-001", literal_payload);
    const auto success = orchestrator.run(
        request,
        hardware,
        native,
        {},
        {},
        [](const guff::ForgeExecutionResult&) {
            return std::vector<guff::SessionArtifactCandidate>{
                {"object-file", "artifact://build/object.o", guff::sha256("object-file"), 512U},
                {"too-many", "artifact://build/extra.o", guff::sha256("extra-file"), 128U},
            };
        });

    CHECK(success.succeeded());
    CHECK(success.status == guff::SessionStatus::Completed);
    CHECK(success.route.status == guff::ModelRouteStatus::DeterministicPreferred);
    CHECK(success.slot_resolution.status == guff::InvocationStatus::Ready);
    CHECK(success.zenkai.verified);
    CHECK(success.zenkai.stop_reason == guff::ZenkaiStopReason::Verified);
    CHECK(success.last_execution.has_value());
    CHECK(success.last_execution->succeeded());
    CHECK(success.last_execution->captured_output_sha256.size() == 64U);
    CHECK(success.artifacts.size() == 1U);
    CHECK(success.rejected_artifacts == 1U);
    CHECK(success.promoted_artifact_bytes == 512U);
    CHECK(success.dojo_episode_id.has_value());
    CHECK(guff::is_sha256(success.audit_sha256));
    CHECK(success.session_id.starts_with("guff:session:sha256:"));
    CHECK(!success.events.empty());
    CHECK(!success.events_truncated);

    guff::DojoQuery query;
    query.task = guff::TaskClass::Coding;
    const auto episodes = dojo.replay(query);
    CHECK(episodes.size() == 1U);
    CHECK(success.dojo_episode_id.has_value());
    CHECK(episodes.front().episode_id == *success.dojo_episode_id);
    CHECK(episodes.front().verified);
    bool saw_correlation = false;
    bool saw_session = false;
    for (const auto& tag : episodes.front().tags) {
        if (tag == "correlation:corr-l12-001") saw_correlation = true;
        if (tag == "session:" + success.session_id) saw_session = true;
    }
    CHECK(saw_correlation);
    CHECK(saw_session);

    std::ifstream journal(root / "dojo.store");
    CHECK(journal.good());
    const std::string journal_text((std::istreambuf_iterator<char>(journal)),
                                   std::istreambuf_iterator<char>());
    CHECK(journal_text.find(literal_payload) == std::string::npos);
    journal.close();

    auto retry_request = session_request("corr-l12-002", "fail-first");
    retry_request.session_budget.max_artifacts = 0U;
    const auto retried = orchestrator.run(
        retry_request,
        hardware,
        native,
        [](std::size_t attempt, std::string_view) -> std::optional<guff::ForgeExecutionRequest> {
            if (attempt != 1U) return std::nullopt;
            return forge_request("corr-l12-002", "attempt:1", "retry-ok");
        });
    CHECK(retried.succeeded());
    CHECK(retried.zenkai.attempts == 2U);
    CHECK(retried.last_execution.has_value());
    CHECK(retried.last_execution->exit_code == 0);

    auto bad_correlation = session_request("corr-l12-003", "ok");
    bad_correlation.forge_request.invocation.invocation_id = "different:attempt:0";
    const auto invalid = orchestrator.run(bad_correlation, hardware, native);
    CHECK(invalid.status == guff::SessionStatus::InvalidRequest);
    CHECK(!invalid.dojo_episode_id.has_value());

    auto denied = session_request("corr-l12-004", "ok");
    denied.forge_request = forge_request("corr-l12-004", "attempt:0", "ok", false);
    const auto rejected = orchestrator.run(denied, hardware, native);
    CHECK(rejected.status == guff::SessionStatus::InvocationRejected);
    CHECK(!rejected.dojo_episode_id.has_value());

    auto human = session_request("corr-l12-005", "ok");
    human.route_request.signal.destructive = true;
    human.route_request.signal.uncertainty = 0.80;
    const auto route_rejected = orchestrator.run(human, hardware, native);
    CHECK(route_rejected.status == guff::SessionStatus::RouteRejected);
    CHECK(route_rejected.route.status == guff::ModelRouteStatus::HumanReviewRequired);

    auto switched = session_request("corr-l12-006", "fail-first");
    const auto switch_rejected = orchestrator.run(
        switched,
        hardware,
        native,
        [](std::size_t attempt, std::string_view) -> std::optional<guff::ForgeExecutionRequest> {
            if (attempt != 1U) return std::nullopt;
            auto retry = forge_request("corr-l12-006", "attempt:1", "retry-ok");
            retry.invocation.layer = guff::RealityLayer::Runtime;
            return retry;
        });
    CHECK(switch_rejected.status == guff::SessionStatus::VerificationFailed);
    CHECK(switch_rejected.zenkai.stop_reason == guff::ZenkaiStopReason::FatalFailure);
    CHECK(switch_rejected.dojo_episode_id.has_value());

    const auto all_episodes = dojo.replay();
    CHECK(all_episodes.size() == 3U);

    std::filesystem::remove_all(root, ec);
    return 0;
}
