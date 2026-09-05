#include "guff/execution_session.hpp"

#include "guff/session_journal.hpp"
#include "guff/sha256.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <sstream>
#include <utility>

namespace guff {
namespace {

bool valid_correlation_id(std::string_view value) {
    if (value.empty() || value.size() > 96U) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isalnum(ch) != 0 || ch == '-' || ch == '_' || ch == '.' || ch == ':';
    });
}

bool correlated_invocation(std::string_view correlation_id,
                           std::string_view invocation_id) {
    if (invocation_id.size() <= correlation_id.size()) return false;
    if (!invocation_id.starts_with(correlation_id)) return false;
    return invocation_id[correlation_id.size()] == ':';
}

std::size_t saturating_add(std::size_t lhs, std::size_t rhs) noexcept {
    if (rhs > std::numeric_limits<std::size_t>::max() - lhs) {
        return std::numeric_limits<std::size_t>::max();
    }
    return lhs + rhs;
}

void add_event(ExecutionSessionResult& result,
               const SessionBudget& budget,
               SessionStage stage,
               std::string status,
               std::string detail) {
    if (result.events.size() >= budget.max_events) {
        result.events_truncated = true;
        return;
    }
    if (detail.size() > budget.max_event_detail_bytes) {
        detail.resize(budget.max_event_detail_bytes);
    }
    result.events.push_back({result.events.size(), stage, std::move(status), std::move(detail)});
}

std::string make_session_id(const ExecutionSessionRequest& request,
                            const HardwareProfile& hardware) {
    std::ostringstream canonical;
    canonical << request.correlation_id << '\n'
              << hardware.immutable_id() << '\n'
              << static_cast<unsigned>(request.route_request.task) << '\n'
              << request.route_request.profile_name << '\n'
              << request.forge_request.invocation.invocation_id << '\n'
              << request.forge_request.invocation.slot_id << '\n'
              << static_cast<unsigned>(request.forge_request.invocation.capability) << '\n'
              << static_cast<unsigned>(request.forge_request.invocation.layer) << '\n'
              << request.forge_request.invocation.input_sha256 << '\n'
              << request.forge_request.invocation.payload_bytes;
    return "guff:session:sha256:" + sha256(canonical.str());
}

std::string request_contract_digest(const ExecutionSessionRequest& request,
                                    const HardwareProfile& hardware) {
    auto permissions = request.forge_request.invocation.permission_tokens;
    std::sort(permissions.begin(), permissions.end());

    std::ostringstream canonical;
    canonical << make_session_id(request, hardware) << '\n'
              << hardware.immutable_id() << '\n'
              << static_cast<unsigned>(request.route_request.task) << '\n'
              << request.route_request.profile_name << '\n'
              << request.forge_request.invocation.slot_id << '\n'
              << static_cast<unsigned>(request.forge_request.invocation.capability) << '\n'
              << static_cast<unsigned>(request.forge_request.invocation.layer) << '\n'
              << request.forge_request.invocation.input_sha256 << '\n'
              << request.forge_request.invocation.payload_bytes << '\n'
              << request.forge_request.budget.max_wall_time_ms << '\n'
              << request.forge_request.budget.max_output_bytes << '\n'
              << request.zenkai_budget.max_attempts << '\n'
              << request.zenkai_budget.max_tool_events << '\n'
              << request.zenkai_budget.max_evidence_items << '\n'
              << request.zenkai_budget.max_evidence_bytes << '\n'
              << request.zenkai_budget.max_trace_entries << '\n'
              << request.zenkai_budget.acceptance_confidence << '\n'
              << request.zenkai_budget.max_detail_bytes << '\n'
              << static_cast<unsigned>(request.zenkai_policy.retry_authority) << '\n'
              << request.session_budget.max_events << '\n'
              << request.session_budget.max_event_detail_bytes << '\n'
              << request.session_budget.max_artifacts << '\n'
              << request.session_budget.max_artifact_bytes << '\n';
    for (const auto& permission : permissions) canonical << permission << '\n';
    return sha256(canonical.str());
}

std::string execution_state(const std::string& correlation_id,
                            const ForgeExecutionRequest& request,
                            const ForgeExecutionResult& execution) {
    std::ostringstream canonical;
    canonical << correlation_id << '\n'
              << request.invocation.invocation_id << '\n'
              << request.invocation.input_sha256 << '\n'
              << static_cast<unsigned>(execution.status) << '\n'
              << execution.exit_code << '\n'
              << execution.captured_output_sha256 << '\n'
              << execution.observed_output_bytes;
    return "guff:execution:sha256:" + sha256(canonical.str());
}

std::string audit_digest(const ExecutionSessionResult& result) {
    std::ostringstream canonical;
    canonical << result.session_id << '\n'
              << result.correlation_id << '\n'
              << static_cast<unsigned>(result.status) << '\n'
              << result.reason << '\n';
    for (const auto& event : result.events) {
        canonical << event.sequence << '|'
                  << static_cast<unsigned>(event.stage) << '|'
                  << event.status << '|'
                  << event.detail << '\n';
    }
    canonical << "events_truncated=" << (result.events_truncated ? 1 : 0) << '\n';
    for (const auto& artifact : result.artifacts) {
        canonical << artifact.name << '|'
                  << artifact.locator << '|'
                  << artifact.sha256 << '|'
                  << artifact.bytes << '\n';
    }
    canonical << "rejected_artifacts=" << result.rejected_artifacts << '\n';
    if (result.dojo_episode_id) canonical << *result.dojo_episode_id << '\n';
    return sha256(canonical.str());
}

bool valid_artifact(const SessionArtifactCandidate& artifact) {
    return !artifact.name.empty() && artifact.name.size() <= 128U &&
           !artifact.locator.empty() && artifact.locator.size() <= 1024U &&
           is_sha256(artifact.sha256);
}

bool same_execution_contract(const ForgeExecutionRequest& base,
                             const ForgeExecutionRequest& retry) noexcept {
    return base.invocation.slot_id == retry.invocation.slot_id &&
           base.invocation.capability == retry.invocation.capability &&
           base.invocation.layer == retry.invocation.layer;
}

bool route_allows_execution(ModelRouteStatus status) noexcept {
    return status == ModelRouteStatus::Selected ||
           status == ModelRouteStatus::DeterministicPreferred;
}

std::vector<std::string> validate_request(const ExecutionSessionRequest& request) {
    std::vector<std::string> errors;
    if (!valid_correlation_id(request.correlation_id)) {
        errors.emplace_back("correlation_id must be 1-96 ASCII token characters");
    }
    if (!correlated_invocation(request.correlation_id,
                               request.forge_request.invocation.invocation_id)) {
        errors.emplace_back("FORGE invocation_id must begin with correlation_id plus ':'");
    }
    if (request.route_request.profile_name.empty()) {
        errors.emplace_back("route_request.profile_name is required for DOJO correlation");
    }
    if (request.summary.empty() || request.summary.size() > 2048U) {
        errors.emplace_back("summary must be 1-2048 bytes");
    }
    if (request.recorded_at_utc.empty() || request.recorded_at_utc.size() > 128U) {
        errors.emplace_back("recorded_at_utc must be 1-128 bytes");
    }
    if (request.dojo_tags.size() > 28U) {
        errors.emplace_back("at most 28 caller DOJO tags are allowed");
    }
    for (const auto& tag : request.dojo_tags) {
        if (tag.empty() || tag.size() > 128U) {
            errors.emplace_back("caller DOJO tags must be 1-128 bytes");
            break;
        }
    }
    if (request.session_budget.max_event_detail_bytes == 0U) {
        errors.emplace_back("session max_event_detail_bytes must be greater than zero");
    }
    return errors;
}

} // namespace

bool ExecutionSessionResult::succeeded() const noexcept {
    return status == SessionStatus::Completed && zenkai.verified;
}

ExecutionSessionOrchestrator::ExecutionSessionOrchestrator(
    const CaddyRouter& router,
    const ClubhouseRegistry& clubhouse,
    const ForgeAdapter& forge,
    DojoStore& dojo,
    SessionJournal* journal) noexcept
    : router_(router), clubhouse_(clubhouse), forge_(forge), dojo_(dojo), journal_(journal) {}

ExecutionSessionResult ExecutionSessionOrchestrator::run(
    const ExecutionSessionRequest& request,
    const HardwareProfile& hardware,
    const ForgeAdapter::ExecutorFunction& executor,
    const RetryRequestFactory& retry_factory,
    const VerificationFunction& verifier,
    const ArtifactCollector& artifact_collector) const {
    ExecutionSessionResult result;
    result.correlation_id = request.correlation_id;
    result.session_id = make_session_id(request, hardware);
    const auto request_sha256 = request_contract_digest(request, hardware);
    bool journal_open = false;

    auto finalize = [&]() -> ExecutionSessionResult {
        if (journal_ && journal_open) {
            const auto terminal_kind = result.status == SessionStatus::Completed
                ? JournalRecordKind::Commit
                : JournalRecordKind::Abort;
            add_event(result, request.session_budget, SessionStage::JournalTerminal,
                      std::string(to_string(terminal_kind)),
                      "terminal journal record requested after audit freeze");
            result.audit_sha256 = audit_digest(result);
            const auto terminal = journal_->finish({
                .kind = terminal_kind,
                .session_id = result.session_id,
                .correlation_id = request.correlation_id,
                .request_sha256 = request_sha256,
                .audit_sha256 = result.audit_sha256,
                .dojo_episode_id = result.dojo_episode_id.value_or(std::string{}),
                .terminal_status = std::string(to_string(result.status)),
                .recorded_at_utc = request.recorded_at_utc,
            });
            if (!terminal.ok()) {
                result.status = SessionStatus::JournalStoreFailed;
                result.reason = terminal.errors.empty()
                    ? "transaction journal failed to append terminal record"
                    : terminal.errors.front();
                add_event(result, request.session_budget, SessionStage::Aborted,
                          std::string(to_string(result.status)), result.reason);
                result.audit_sha256 = audit_digest(result);
            } else {
                result.journal_terminal_record_sha256 = terminal.record_sha256;
            }
            return std::move(result);
        }
        result.audit_sha256 = audit_digest(result);
        return std::move(result);
    };

    const auto validation = validate_request(request);
    if (!validation.empty()) {
        result.status = SessionStatus::InvalidRequest;
        result.reason = validation.front();
        add_event(result, request.session_budget, SessionStage::Aborted,
                  std::string(to_string(result.status)), result.reason);
        return finalize();
    }

    add_event(result, request.session_budget, SessionStage::Created,
              "SESSION_CREATED", "correlated transaction accepted");

    if (journal_) {
        const auto begin = journal_->begin({
            .session_id = result.session_id,
            .correlation_id = request.correlation_id,
            .request_sha256 = request_sha256,
            .recorded_at_utc = request.recorded_at_utc,
        });
        if (!begin.ok()) {
            result.status = SessionStatus::JournalStoreFailed;
            result.reason = begin.errors.empty()
                ? "transaction journal rejected BEGIN"
                : begin.errors.front();
            add_event(result, request.session_budget, SessionStage::JournalBegin,
                      std::string(to_string(begin.status)), result.reason);
            add_event(result, request.session_budget, SessionStage::Aborted,
                      std::string(to_string(result.status)), result.reason);
            return finalize();
        }
        journal_open = true;
        result.journal_begin_record_sha256 = begin.record_sha256;
        add_event(result, request.session_budget, SessionStage::JournalBegin,
                  std::string(to_string(begin.status)), "durable BEGIN committed before routing/execution");
    }

    result.route = router_.select(request.route_request, hardware);
    add_event(result, request.session_budget, SessionStage::Routed,
              std::string(to_string(result.route.status)), result.route.reason);
    if (!route_allows_execution(result.route.status)) {
        result.status = SessionStatus::RouteRejected;
        result.reason = "CADDY route does not authorize autonomous execution: " +
                        std::string(to_string(result.route.status));
        add_event(result, request.session_budget, SessionStage::Aborted,
                  std::string(to_string(result.status)), result.reason);
        return finalize();
    }

    result.slot_resolution = clubhouse_.resolve(request.forge_request.invocation);
    add_event(result, request.session_budget, SessionStage::SlotResolved,
              std::string(to_string(result.slot_resolution.status)),
              result.slot_resolution.reason);
    if (!result.slot_resolution.ready()) {
        result.status = SessionStatus::InvocationRejected;
        result.reason = "CLUBHOUSE rejected the base invocation: " +
                        result.slot_resolution.reason;
        add_event(result, request.session_budget, SessionStage::Aborted,
                  std::string(to_string(result.status)), result.reason);
        return finalize();
    }

    ZenkaiLoop zenkai(request.zenkai_budget);
    std::optional<ForgeExecutionResult> latest_execution;

    result.zenkai = zenkai.run(
        "guff:execution:sha256:" + sha256(result.session_id),
        request.zenkai_policy,
        [&](std::size_t attempt_index, std::string_view previous_state) {
            ZenkaiAttempt attempt;
            ForgeExecutionRequest execution_request;

            if (attempt_index == 0U) {
                execution_request = request.forge_request;
            } else {
                if (!retry_factory) {
                    attempt.candidate_state = std::string(previous_state);
                    attempt.produced_new_information = false;
                    attempt.verification = {false, 0.0, "no retry request factory supplied"};
                    return attempt;
                }
                auto retry = retry_factory(attempt_index, previous_state);
                if (!retry) {
                    attempt.candidate_state = std::string(previous_state);
                    attempt.produced_new_information = false;
                    attempt.verification = {false, 0.0, "retry planner produced no new request"};
                    return attempt;
                }
                execution_request = std::move(*retry);
            }

            if (!correlated_invocation(request.correlation_id,
                                       execution_request.invocation.invocation_id)) {
                attempt.candidate_state = std::string(previous_state);
                attempt.produced_new_information = false;
                attempt.fatal = true;
                attempt.verification = {false, 0.0, "retry invocation escaped the session correlation id"};
                add_event(result, request.session_budget, SessionStage::Executing,
                          "RETRY_REJECTED", attempt.verification.summary);
                return attempt;
            }
            if (!same_execution_contract(request.forge_request, execution_request)) {
                attempt.candidate_state = std::string(previous_state);
                attempt.produced_new_information = false;
                attempt.fatal = true;
                attempt.verification = {false, 0.0, "retry attempted to switch slot, capability, or STRATA layer"};
                add_event(result, request.session_budget, SessionStage::Executing,
                          "RETRY_REJECTED", attempt.verification.summary);
                return attempt;
            }

            add_event(result, request.session_budget, SessionStage::Executing,
                      "ATTEMPT", "attempt=" + std::to_string(attempt_index) +
                      " invocation=" + execution_request.invocation.invocation_id);

            auto execution = forge_.execute(execution_request, executor);
            attempt.candidate_state = execution_state(request.correlation_id,
                                                      execution_request,
                                                      execution);
            attempt.evidence = execution.evidence;
            attempt.produced_new_information = attempt.candidate_state != previous_state;
            if (verifier) {
                attempt.verification = verifier(execution);
            } else {
                attempt.verification = {
                    execution.succeeded(),
                    execution.succeeded() ? 1.0 : 0.0,
                    execution.reason,
                };
            }
            attempt.fatal = execution.status == ForgeStatus::InvalidRequest ||
                            execution.status == ForgeStatus::InvocationRejected ||
                            execution.status == ForgeStatus::InputMismatch;
            latest_execution = std::move(execution);
            return attempt;
        });

    result.last_execution = latest_execution;
    add_event(result, request.session_budget, SessionStage::Verifying,
              std::string(to_string(result.zenkai.stop_reason)),
              "attempts=" + std::to_string(result.zenkai.attempts) +
              " verified=" + (result.zenkai.verified ? std::string("yes") : std::string("no")));

    if (result.zenkai.verified && result.last_execution && artifact_collector) {
        const auto candidates = artifact_collector(*result.last_execution);
        for (const auto& candidate : candidates) {
            const auto next_bytes = saturating_add(result.promoted_artifact_bytes, candidate.bytes);
            if (!valid_artifact(candidate) ||
                result.artifacts.size() >= request.session_budget.max_artifacts ||
                next_bytes > request.session_budget.max_artifact_bytes) {
                ++result.rejected_artifacts;
                add_event(result, request.session_budget, SessionStage::ArtifactPromotion,
                          "ARTIFACT_REJECTED", candidate.name.empty() ? "unnamed artifact" : candidate.name);
                continue;
            }
            result.artifacts.push_back({candidate.name, candidate.locator, candidate.sha256, candidate.bytes});
            result.promoted_artifact_bytes = next_bytes;
            add_event(result, request.session_budget, SessionStage::ArtifactPromotion,
                      "ARTIFACT_PROMOTED", candidate.name + " sha256=" + candidate.sha256);
        }
    }

    std::vector<std::string> tags = request.dojo_tags;
    tags.push_back("correlation:" + request.correlation_id);
    tags.push_back("session:" + result.session_id);
    tags.push_back("artifacts:" + std::to_string(result.artifacts.size()));
    tags.push_back("artifact-rejections:" + std::to_string(result.rejected_artifacts));

    const auto model_id = result.route.selected_model_id.value_or(std::string{});
    auto episode = make_dojo_episode(
        request.route_request.task,
        request.route_request.profile_name,
        hardware.immutable_id(),
        model_id,
        std::string(to_string(result.route.status)),
        result.zenkai,
        result.route.trace.describe(),
        request.summary,
        request.recorded_at_utc,
        std::move(tags));
    const auto dojo_result = dojo_.append(std::move(episode));
    add_event(result, request.session_budget, SessionStage::DojoRecord,
              std::string(to_string(dojo_result.status)),
              dojo_result.ok() ? "DOJO episode committed" :
                                 (dojo_result.errors.empty() ? "DOJO store rejected episode" : dojo_result.errors.front()));
    if (!dojo_result.ok()) {
        result.status = SessionStatus::DojoStoreFailed;
        result.reason = dojo_result.errors.empty() ?
            "DOJO failed to commit the session episode" : dojo_result.errors.front();
        add_event(result, request.session_budget, SessionStage::Aborted,
                  std::string(to_string(result.status)), result.reason);
        return finalize();
    }
    result.dojo_episode_id = dojo_result.episode_id;

    if (!result.zenkai.verified) {
        result.status = SessionStatus::VerificationFailed;
        result.reason = "ZENKAI did not produce a verified terminal state: " +
                        std::string(to_string(result.zenkai.stop_reason));
        add_event(result, request.session_budget, SessionStage::Aborted,
                  std::string(to_string(result.status)), result.reason);
        return finalize();
    }

    result.status = SessionStatus::Completed;
    result.reason = "correlated execution session completed and committed to DOJO";
    add_event(result, request.session_budget, SessionStage::Completed,
              std::string(to_string(result.status)), result.reason);
    return finalize();
}

std::string_view to_string(SessionStatus status) noexcept {
    switch (status) {
    case SessionStatus::Completed: return "COMPLETED";
    case SessionStatus::InvalidRequest: return "INVALID_REQUEST";
    case SessionStatus::RouteRejected: return "ROUTE_REJECTED";
    case SessionStatus::InvocationRejected: return "INVOCATION_REJECTED";
    case SessionStatus::VerificationFailed: return "VERIFICATION_FAILED";
    case SessionStatus::DojoStoreFailed: return "DOJO_STORE_FAILED";
    case SessionStatus::JournalStoreFailed: return "JOURNAL_STORE_FAILED";
    }
    return "INVALID_REQUEST";
}

std::string_view to_string(SessionStage stage) noexcept {
    switch (stage) {
    case SessionStage::Created: return "CREATED";
    case SessionStage::JournalBegin: return "JOURNAL_BEGIN";
    case SessionStage::Routed: return "ROUTED";
    case SessionStage::SlotResolved: return "SLOT_RESOLVED";
    case SessionStage::Executing: return "EXECUTING";
    case SessionStage::Verifying: return "VERIFYING";
    case SessionStage::ArtifactPromotion: return "ARTIFACT_PROMOTION";
    case SessionStage::DojoRecord: return "DOJO_RECORD";
    case SessionStage::JournalTerminal: return "JOURNAL_TERMINAL";
    case SessionStage::Completed: return "COMPLETED";
    case SessionStage::Aborted: return "ABORTED";
    }
    return "ABORTED";
}

} // namespace guff
