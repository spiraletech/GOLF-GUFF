#pragma once

#include "guff/authority_ledger.hpp"
#include "guff/policy_registry.hpp"
#include "guff/runtime_identity_store.hpp"
#include "guff/session_journal.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class OperatorReviewState : std::uint8_t {
    Pending,
    Deferred,
    Refused,
    Superseded
};

enum class OperatorConsoleStatus : std::uint8_t {
    Ready,
    Invalid,
    NotHumanReview,
    QueueFull,
    NotFound,
    AlreadyClosed,
    StorageFailure,
    Corrupt,
    SigningFailed
};

struct OperatorReviewTicket {
    std::uint32_t schema_version{1U};
    std::string ticket_id;
    std::string policy_id;
    std::string subject_id;
    std::string slot_id;
    SlotCapability capability{SlotCapability::GenericTool};
    RealityLayer layer{RealityLayer::Application};
    PolicyRisk risk{PolicyRisk::Critical};
    std::string reason;
    std::vector<std::string> matched_rule_ids;
    std::uint64_t created_at_unix_ms{0U};
    OperatorReviewState state{OperatorReviewState::Pending};
    std::uint64_t resolved_at_unix_ms{0U};
    std::string resolution_note_sha256;
};

struct OperatorReviewQueueBudget {
    std::size_t max_tickets{512U};
    std::size_t max_records{2048U};
    std::size_t max_matched_rules{32U};
    std::size_t max_reason_bytes{1024U};
};

struct OperatorReviewQueueResult {
    OperatorConsoleStatus status{OperatorConsoleStatus::Invalid};
    std::string ticket_id;
    OperatorReviewState state{OperatorReviewState::Pending};
    std::string record_sha256;
    std::string reason;

    [[nodiscard]] bool ok() const noexcept;
};

struct OperatorReviewQueueInspection {
    bool healthy{true};
    std::size_t records{0U};
    std::size_t tickets{0U};
    std::size_t pending{0U};
    std::size_t deferred{0U};
    std::size_t refused{0U};
    std::size_t superseded{0U};
    std::vector<OperatorReviewTicket> pending_tickets;
    std::vector<std::string> errors;
};

class OperatorReviewQueue {
public:
    explicit OperatorReviewQueue(std::filesystem::path journal_path,
                                 OperatorReviewQueueBudget budget = {});

    [[nodiscard]] OperatorReviewQueueResult enqueue(
        const PolicyEvaluationResult& result,
        const PolicyEvaluationRequest& request,
        std::uint64_t created_at_unix_ms);

    [[nodiscard]] OperatorReviewQueueResult close(
        std::string_view ticket_id,
        OperatorReviewState state,
        std::uint64_t resolved_at_unix_ms,
        std::string_view resolution_note_sha256);

    [[nodiscard]] OperatorReviewQueueInspection inspect() const;
    [[nodiscard]] std::optional<OperatorReviewTicket> ticket(
        std::string_view ticket_id) const;
    [[nodiscard]] const std::filesystem::path& journal_path() const noexcept;

private:
    std::filesystem::path journal_path_;
    OperatorReviewQueueBudget budget_;
};

struct ActivePolicyProvenance {
    std::string policy_id;
    std::string package_id;
    std::string signer_id;
    std::string algorithm;
    std::uint64_t signed_at_unix_ms{0U};
};

struct OperatorConsoleSnapshot {
    bool healthy{true};
    PolicyRegistrySnapshot policy;
    std::optional<ActivePolicyProvenance> active_policy;
    RecoveryInspection recovery;
    AuthorityLedgerInspection authority;
    RuntimeIdentityStoreInspection identities;
    OperatorReviewQueueInspection reviews;
    std::vector<std::string> errors;
};

struct OperatorPolicyControlRequest {
    PolicyControlAction action{PolicyControlAction::Activate};
    std::string policy_id;
    std::string actor_reference;
    std::uint64_t issued_at_unix_ms{0U};
    std::string nonce;
    std::string reason;
};

class OperatorConsole {
public:
    OperatorConsole(SignedPolicyRegistry& policy_registry,
                    SessionJournal& session_journal,
                    AuthorityLedger& authority_ledger,
                    RuntimeIdentityStore& identity_store,
                    OperatorReviewQueue& review_queue) noexcept;

    [[nodiscard]] OperatorConsoleSnapshot snapshot() const;

    [[nodiscard]] OperatorReviewQueueResult enqueue_review(
        const PolicyEvaluationResult& result,
        const PolicyEvaluationRequest& request,
        std::uint64_t created_at_unix_ms);

    [[nodiscard]] std::optional<SignedPolicyControl> issue_policy_control(
        const OperatorPolicyControlRequest& request,
        const AuthoritySigner& signer,
        std::vector<std::string>* errors = nullptr) const;

    [[nodiscard]] PolicyRegistryResult apply_policy_control(
        const SignedPolicyControl& control);

private:
    SignedPolicyRegistry& policy_registry_;
    SessionJournal& session_journal_;
    AuthorityLedger& authority_ledger_;
    RuntimeIdentityStore& identity_store_;
    OperatorReviewQueue& review_queue_;
};

[[nodiscard]] std::string_view to_string(OperatorReviewState state) noexcept;
[[nodiscard]] std::string_view to_string(OperatorConsoleStatus status) noexcept;

} // namespace guff
