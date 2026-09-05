#pragma once

#include "guff/execution_session.hpp"
#include "guff/session_journal.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class RecoveryDecision : std::uint8_t {
    Dismiss,
    RetryAsNewSession
};

enum class RecoveryDecisionStatus : std::uint8_t {
    Dismissed,
    RetryPrepared,
    AuthorizationRequired,
    ParentNotInterrupted,
    IdentityReuse,
    Invalid,
    JournalError
};

struct RecoveryAuthorization {
    bool approved{false};
    RecoveryDecision decision{RecoveryDecision::Dismiss};
    std::string parent_session_id;
    std::string parent_begin_record_sha256;
    std::string actor_reference;
    std::string issued_at_utc;
    std::string child_correlation_id;
    RetryAuthority child_retry_authority{RetryAuthority::None};
};

struct RecoveryDecisionResult {
    RecoveryDecisionStatus status{RecoveryDecisionStatus::Invalid};
    std::string authorization_id;
    std::string authorization_sha256;
    std::optional<ExecutionSessionRequest> child_request;
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

class RecoveryDecisionProtocol {
public:
    explicit RecoveryDecisionProtocol(SessionJournal& journal) noexcept;

    [[nodiscard]] RecoveryDecisionResult decide(
        const RecoveryAuthorization& authorization,
        const std::optional<ExecutionSessionRequest>& child_template = std::nullopt) const;

private:
    SessionJournal& journal_;
};

[[nodiscard]] std::string recovery_authorization_sha256(
    const RecoveryAuthorization& authorization);
[[nodiscard]] std::string recovery_authorization_id(
    const RecoveryAuthorization& authorization);
[[nodiscard]] std::string_view to_string(RecoveryDecision decision) noexcept;
[[nodiscard]] std::string_view to_string(RecoveryDecisionStatus status) noexcept;

} // namespace guff
