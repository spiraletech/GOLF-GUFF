#pragma once

#include "guff/caddy_router.hpp"
#include "guff/clubhouse.hpp"
#include "guff/dojo.hpp"
#include "guff/forge.hpp"
#include "guff/hardware_profile.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

class SessionJournal;

enum class SessionStatus : std::uint8_t {
    Completed,
    InvalidRequest,
    RouteRejected,
    InvocationRejected,
    VerificationFailed,
    DojoStoreFailed,
    JournalStoreFailed
};

enum class SessionStage : std::uint8_t {
    Created,
    JournalBegin,
    Routed,
    SlotResolved,
    Executing,
    Verifying,
    ArtifactPromotion,
    DojoRecord,
    JournalTerminal,
    Completed,
    Aborted
};

struct SessionBudget {
    std::size_t max_events{64U};
    std::size_t max_event_detail_bytes{512U};
    std::size_t max_artifacts{16U};
    std::size_t max_artifact_bytes{512U * 1024U * 1024U};
};

struct SessionArtifactCandidate {
    std::string name;
    std::string locator;
    std::string sha256;
    std::size_t bytes{0U};
};

struct SessionArtifact {
    std::string name;
    std::string locator;
    std::string sha256;
    std::size_t bytes{0U};
};

struct SessionEvent {
    std::size_t sequence{0U};
    SessionStage stage{SessionStage::Created};
    std::string status;
    std::string detail;
};

struct ExecutionSessionRequest {
    std::string correlation_id;
    ModelRouteRequest route_request;
    ForgeExecutionRequest forge_request;
    ZenkaiBudget zenkai_budget{};
    ZenkaiRunPolicy zenkai_policy{};
    SessionBudget session_budget{};
    std::string summary;
    std::string recorded_at_utc;
    std::vector<std::string> dojo_tags;
    std::string parent_session_id;
    std::string recovery_authorization_sha256;
};

struct ExecutionSessionResult {
    SessionStatus status{SessionStatus::InvalidRequest};
    std::string correlation_id;
    std::string session_id;
    ModelRouteDecision route;
    SlotResolution slot_resolution;
    ZenkaiResult zenkai;
    std::optional<ForgeExecutionResult> last_execution;
    std::vector<SessionArtifact> artifacts;
    std::size_t rejected_artifacts{0U};
    std::size_t promoted_artifact_bytes{0U};
    std::vector<SessionEvent> events;
    bool events_truncated{false};
    std::optional<std::string> dojo_episode_id;
    std::optional<std::string> journal_begin_record_sha256;
    std::optional<std::string> journal_terminal_record_sha256;
    std::string audit_sha256;
    std::string reason;

    [[nodiscard]] bool succeeded() const noexcept;
};

class ExecutionSessionOrchestrator {
public:
    using RetryRequestFactory = std::function<std::optional<ForgeExecutionRequest>(
        std::size_t attempt_index,
        std::string_view previous_state)>;
    using VerificationFunction = std::function<VerificationOutcome(
        const ForgeExecutionResult& execution)>;
    using ArtifactCollector = std::function<std::vector<SessionArtifactCandidate>(
        const ForgeExecutionResult& execution)>;

    ExecutionSessionOrchestrator(const CaddyRouter& router,
                                 const ClubhouseRegistry& clubhouse,
                                 const ForgeAdapter& forge,
                                 DojoStore& dojo,
                                 SessionJournal* journal = nullptr) noexcept;

    [[nodiscard]] ExecutionSessionResult run(
        const ExecutionSessionRequest& request,
        const HardwareProfile& hardware,
        const ForgeAdapter::ExecutorFunction& executor,
        const RetryRequestFactory& retry_factory = {},
        const VerificationFunction& verifier = {},
        const ArtifactCollector& artifact_collector = {}) const;

private:
    const CaddyRouter& router_;
    const ClubhouseRegistry& clubhouse_;
    const ForgeAdapter& forge_;
    DojoStore& dojo_;
    SessionJournal* journal_{nullptr};
};

[[nodiscard]] std::string execution_session_id(
    const ExecutionSessionRequest& request,
    const HardwareProfile& hardware);
[[nodiscard]] std::string execution_request_sha256(
    const ExecutionSessionRequest& request,
    const HardwareProfile& hardware);
[[nodiscard]] std::string_view to_string(SessionStatus status) noexcept;
[[nodiscard]] std::string_view to_string(SessionStage stage) noexcept;

} // namespace guff
