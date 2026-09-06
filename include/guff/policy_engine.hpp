#pragma once

#include "guff/clubhouse.hpp"
#include "guff/runtime_identity_store.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class PolicyDecision : std::uint8_t {
    Allow,
    Refuse,
    HumanReview
};

enum class PolicyRisk : std::uint8_t {
    Low,
    Moderate,
    High,
    Critical
};

enum class PolicyAuthorityLevel : std::uint8_t {
    None,
    SignedReceipt,
    DurableReceipt,
    DelegatedReceipt,
    SessionKey,
    RuntimeLease,
    AttestedRuntimeLease
};

enum class PolicyEvaluationStatus : std::uint8_t {
    Decided,
    InvalidPolicy,
    InvalidRequest,
    IdentityRejected,
    AuthorityRejected,
    BudgetExceeded,
    PolicyInactive
};

struct PolicyOperation {
    std::string subject_id;
    std::string slot_id;
    SlotCapability capability{SlotCapability::GenericTool};
    RealityLayer layer{RealityLayer::Application};
    bool destructive{false};
    bool persistent{false};
    bool external_side_effect{false};
    bool requires_identity{true};
    bool requires_authority{true};
    double uncertainty{0.0};
};

struct PolicyAuthorityFacts {
    PolicyAuthorityLevel level{PolicyAuthorityLevel::None};
    bool validated{false};
    bool scope_matches{false};
    bool capability_matches{false};
    bool runtime_binding_matches{false};
    std::string authority_id;
};

struct PolicyRule {
    std::uint32_t schema_version{1U};
    std::string rule_name;
    int priority{0};
    PolicyDecision effect{PolicyDecision::Refuse};
    std::string subject_prefix;
    std::string slot_id;
    std::optional<SlotCapability> capability;
    std::optional<RealityLayer> layer;
    std::optional<bool> destructive;
    std::optional<bool> persistent;
    std::optional<bool> external_side_effect;
    PolicyRisk min_risk{PolicyRisk::Low};
    PolicyRisk max_risk{PolicyRisk::Critical};
    PolicyAuthorityLevel min_authority{PolicyAuthorityLevel::None};
    bool require_validated_authority{false};
    bool require_runtime_binding{false};
    bool require_active_identity{false};
    bool enabled{true};
    std::vector<std::string> tags;

    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] std::string immutable_id() const;
};

struct PolicyDocument {
    std::uint32_t schema_version{1U};
    std::string policy_name;
    PolicyDecision default_decision{PolicyDecision::Refuse};
    std::vector<PolicyRule> rules;

    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] std::string canonical_payload() const;
    [[nodiscard]] std::string immutable_id() const;
};

struct PolicyEvaluationBudget {
    std::size_t max_rules{256U};
    std::size_t max_matched_rules{64U};
    std::size_t max_trace_entries{64U};
    std::size_t max_reason_bytes{1024U};
};

struct PolicyTraceEntry {
    std::string code;
    std::string detail;
};

struct PolicyEvaluationRequest {
    PolicyOperation operation;
    PolicyAuthorityFacts authority;
    std::optional<RuntimeAttestationEvidence> identity_evidence;
};

struct PolicyEvaluationResult {
    PolicyEvaluationStatus status{PolicyEvaluationStatus::InvalidRequest};
    PolicyDecision decision{PolicyDecision::Refuse};
    PolicyRisk risk{PolicyRisk::Critical};
    std::string policy_id;
    std::vector<std::string> matched_rule_ids;
    std::vector<PolicyTraceEntry> trace;
    bool trace_truncated{false};
    bool matched_rules_truncated{false};
    std::string reason;

    [[nodiscard]] bool allowed() const noexcept;
};

class DeclarativePolicyEngine {
public:
    DeclarativePolicyEngine(
        PolicyDocument policy,
        const RuntimeIdentityStore& identity_store,
        PolicyEvaluationBudget budget = {});

    [[nodiscard]] PolicyEvaluationResult evaluate(
        const PolicyEvaluationRequest& request) const;
    [[nodiscard]] const PolicyDocument& policy() const noexcept;
    [[nodiscard]] const PolicyEvaluationBudget& budget() const noexcept;

private:
    PolicyDocument policy_;
    const RuntimeIdentityStore& identity_store_;
    PolicyEvaluationBudget budget_;
};

[[nodiscard]] PolicyRisk classify_policy_risk(
    const PolicyOperation& operation) noexcept;
[[nodiscard]] std::string canonical_policy_rule(const PolicyRule& rule);
[[nodiscard]] std::string_view to_string(PolicyDecision decision) noexcept;
[[nodiscard]] std::string_view to_string(PolicyRisk risk) noexcept;
[[nodiscard]] std::string_view to_string(PolicyAuthorityLevel level) noexcept;
[[nodiscard]] std::string_view to_string(PolicyEvaluationStatus status) noexcept;

} // namespace guff
