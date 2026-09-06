#include "guff/policy_engine.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <set>
#include <sstream>
#include <utility>

namespace guff {
namespace {

constexpr std::string_view kPolicyPrefix = "guff:policy:sha256:";
constexpr std::string_view kRulePrefix = "guff:policy-rule:sha256:";

int risk_rank(PolicyRisk value) noexcept {
    return static_cast<int>(value);
}

int authority_rank(PolicyAuthorityLevel value) noexcept {
    return static_cast<int>(value);
}

int decision_precedence(PolicyDecision value) noexcept {
    switch (value) {
    case PolicyDecision::Refuse: return 3;
    case PolicyDecision::HumanReview: return 2;
    case PolicyDecision::Allow: return 1;
    }
    return 3;
}

bool valid_text(std::string_view value, std::size_t max_bytes) {
    if (value.empty() || value.size() > max_bytes) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch >= 0x20U && ch != 0x7fU;
    });
}

bool valid_optional_text(std::string_view value, std::size_t max_bytes) {
    return value.empty() || valid_text(value, max_bytes);
}

std::string bool_token(bool value) {
    return value ? "1" : "0";
}

std::string optional_bool_token(const std::optional<bool>& value) {
    if (!value) return "*";
    return *value ? "1" : "0";
}

std::string optional_capability_token(const std::optional<SlotCapability>& value) {
    return value ? std::string(to_string(*value)) : "*";
}

std::string optional_layer_token(const std::optional<RealityLayer>& value) {
    return value ? std::string(to_string(*value)) : "*";
}

std::vector<std::string> canonical_tags(const std::vector<std::string>& tags) {
    std::vector<std::string> out = tags;
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

bool prefix_matches(std::string_view value, std::string_view prefix) {
    return prefix.empty() || value.starts_with(prefix);
}

bool rule_matches(const PolicyRule& rule,
                  const PolicyEvaluationRequest& request,
                  PolicyRisk risk,
                  const RuntimeIdentityStore& store) {
    const auto& operation = request.operation;
    if (!rule.enabled) return false;
    if (!prefix_matches(operation.subject_id, rule.subject_prefix)) return false;
    if (!rule.slot_id.empty() && operation.slot_id != rule.slot_id) return false;
    if (rule.capability && operation.capability != *rule.capability) return false;
    if (rule.layer && operation.layer != *rule.layer) return false;
    if (rule.destructive && operation.destructive != *rule.destructive) return false;
    if (rule.persistent && operation.persistent != *rule.persistent) return false;
    if (rule.external_side_effect &&
        operation.external_side_effect != *rule.external_side_effect) return false;
    if (risk_rank(risk) < risk_rank(rule.min_risk) ||
        risk_rank(risk) > risk_rank(rule.max_risk)) return false;
    if (authority_rank(request.authority.level) < authority_rank(rule.min_authority)) {
        return false;
    }
    if (rule.require_validated_authority && !request.authority.validated) return false;
    if (rule.require_runtime_binding && !request.authority.runtime_binding_matches) {
        return false;
    }
    if (rule.require_active_identity) {
        if (!request.identity_evidence ||
            !store.identity_active(*request.identity_evidence)) return false;
    }
    return true;
}

void append_trace(PolicyEvaluationResult& result,
                  const PolicyEvaluationBudget& budget,
                  std::string code,
                  std::string detail) {
    if (result.trace.size() >= budget.max_trace_entries) {
        result.trace_truncated = true;
        return;
    }
    if (detail.size() > budget.max_reason_bytes) {
        detail.resize(budget.max_reason_bytes);
    }
    result.trace.push_back({std::move(code), std::move(detail)});
}

PolicyEvaluationResult rejected(PolicyEvaluationStatus status,
                                PolicyRisk risk,
                                std::string policy_id,
                                std::string reason,
                                const PolicyEvaluationBudget& budget) {
    PolicyEvaluationResult result;
    result.status = status;
    result.decision = PolicyDecision::Refuse;
    result.risk = risk;
    result.policy_id = std::move(policy_id);
    if (reason.size() > budget.max_reason_bytes) reason.resize(budget.max_reason_bytes);
    result.reason = std::move(reason);
    append_trace(result, budget, "REFUSE", result.reason);
    return result;
}

} // namespace

bool PolicyEvaluationResult::allowed() const noexcept {
    return status == PolicyEvaluationStatus::Decided &&
           decision == PolicyDecision::Allow;
}

std::vector<std::string> PolicyRule::validate() const {
    std::vector<std::string> errors;
    if (schema_version != 1U) errors.emplace_back("policy rule schema_version must be 1");
    if (!valid_text(rule_name, 128U)) errors.emplace_back("policy rule_name must be printable and 1-128 bytes");
    if (!valid_optional_text(subject_prefix, 256U)) errors.emplace_back("policy subject_prefix is invalid");
    if (!valid_optional_text(slot_id, 192U)) errors.emplace_back("policy slot_id is invalid");
    if (priority < -1'000'000 || priority > 1'000'000) errors.emplace_back("policy priority exceeds bounded range");
    if (risk_rank(min_risk) > risk_rank(max_risk)) errors.emplace_back("policy min_risk exceeds max_risk");
    if (effect == PolicyDecision::Allow && subject_prefix.empty() && slot_id.empty() &&
        !capability && !layer && !destructive && !persistent && !external_side_effect) {
        errors.emplace_back("ALLOW rule must narrow at least one operation dimension");
    }
    if (require_runtime_binding &&
        authority_rank(min_authority) < authority_rank(PolicyAuthorityLevel::RuntimeLease)) {
        errors.emplace_back("runtime-binding rule must require at least RUNTIME_LEASE authority");
    }
    if (tags.size() > 32U) errors.emplace_back("policy rule tags exceed 32-entry ceiling");
    for (const auto& tag : tags) {
        if (!valid_text(tag, 64U)) errors.emplace_back("policy rule tag is invalid");
    }
    return errors;
}

std::string PolicyRule::immutable_id() const {
    return std::string(kRulePrefix) + sha256(canonical_policy_rule(*this));
}

std::vector<std::string> PolicyDocument::validate() const {
    std::vector<std::string> errors;
    if (schema_version != 1U) errors.emplace_back("policy schema_version must be 1");
    if (!valid_text(policy_name, 128U)) errors.emplace_back("policy_name must be printable and 1-128 bytes");
    if (default_decision != PolicyDecision::Refuse) {
        errors.emplace_back("policy default_decision must be REFUSE");
    }
    if (rules.empty()) errors.emplace_back("policy must contain at least one rule");

    std::set<std::string> names;
    for (const auto& rule : rules) {
        auto rule_errors = rule.validate();
        errors.insert(errors.end(), rule_errors.begin(), rule_errors.end());
        if (!names.insert(rule.rule_name).second) {
            errors.emplace_back("duplicate policy rule_name: " + rule.rule_name);
        }
    }
    return errors;
}

std::string PolicyDocument::canonical_payload() const {
    std::vector<std::string> rules_canonical;
    rules_canonical.reserve(rules.size());
    for (const auto& rule : rules) rules_canonical.push_back(canonical_policy_rule(rule));
    std::sort(rules_canonical.begin(), rules_canonical.end());

    std::ostringstream out;
    out << schema_version << '\n'
        << policy_name << '\n'
        << to_string(default_decision) << '\n'
        << rules_canonical.size() << '\n';
    for (const auto& rule : rules_canonical) out << rule.size() << ':' << rule << '\n';
    return out.str();
}

std::string PolicyDocument::immutable_id() const {
    return std::string(kPolicyPrefix) + sha256(canonical_payload());
}

DeclarativePolicyEngine::DeclarativePolicyEngine(
    PolicyDocument policy,
    const RuntimeIdentityStore& identity_store,
    PolicyEvaluationBudget budget)
    : policy_(std::move(policy)), identity_store_(identity_store), budget_(budget) {}

PolicyEvaluationResult DeclarativePolicyEngine::evaluate(
    const PolicyEvaluationRequest& request) const {
    const PolicyRisk risk = classify_policy_risk(request.operation);
    const std::string policy_id = policy_.immutable_id();

    if (budget_.max_rules == 0U || budget_.max_matched_rules == 0U ||
        budget_.max_trace_entries == 0U || budget_.max_reason_bytes == 0U) {
        return rejected(PolicyEvaluationStatus::BudgetExceeded, risk, policy_id,
                        "policy evaluation budget contains a zero ceiling", budget_);
    }

    const auto policy_errors = policy_.validate();
    if (!policy_errors.empty()) {
        return rejected(PolicyEvaluationStatus::InvalidPolicy, risk, policy_id,
                        policy_errors.front(), budget_);
    }
    if (policy_.rules.size() > budget_.max_rules) {
        return rejected(PolicyEvaluationStatus::BudgetExceeded, risk, policy_id,
                        "policy rule count exceeds evaluation ceiling", budget_);
    }

    const auto& operation = request.operation;
    if (!valid_text(operation.subject_id, 256U) || !valid_text(operation.slot_id, 192U) ||
        !std::isfinite(operation.uncertainty) || operation.uncertainty < 0.0 ||
        operation.uncertainty > 1.0) {
        return rejected(PolicyEvaluationStatus::InvalidRequest, risk, policy_id,
                        "policy operation is malformed", budget_);
    }

    if (operation.requires_identity) {
        if (!request.identity_evidence ||
            !validate_runtime_attestation_identity(*request.identity_evidence)) {
            return rejected(PolicyEvaluationStatus::IdentityRejected, risk, policy_id,
                            "required runtime identity evidence is missing or invalid", budget_);
        }
        const auto& binding = request.identity_evidence->binding;
        if (binding.slot_id != operation.slot_id || binding.layer != operation.layer) {
            return rejected(PolicyEvaluationStatus::IdentityRejected, risk, policy_id,
                            "runtime identity evidence does not match operation slot/STRATA", budget_);
        }
        if (!identity_store_.identity_active(*request.identity_evidence)) {
            return rejected(PolicyEvaluationStatus::IdentityRejected, risk, policy_id,
                            "runtime device/image/process identity is not active", budget_);
        }
    }

    if (operation.requires_authority) {
        if (!request.authority.validated ||
            request.authority.level == PolicyAuthorityLevel::None ||
            !request.authority.scope_matches ||
            !request.authority.capability_matches ||
            request.authority.authority_id.empty()) {
            return rejected(PolicyEvaluationStatus::AuthorityRejected, risk, policy_id,
                            "required authority facts are incomplete or rejected", budget_);
        }
        if (authority_rank(request.authority.level) >=
                authority_rank(PolicyAuthorityLevel::RuntimeLease) &&
            !request.authority.runtime_binding_matches) {
            return rejected(PolicyEvaluationStatus::AuthorityRejected, risk, policy_id,
                            "runtime authority is not bound to the current runtime coordinates", budget_);
        }
    }

    PolicyEvaluationResult result;
    result.status = PolicyEvaluationStatus::Decided;
    result.decision = policy_.default_decision;
    result.risk = risk;
    result.policy_id = policy_id;
    append_trace(result, budget_, "RISK", std::string(to_string(risk)));

    const PolicyRule* winning = nullptr;
    int winning_precedence = 0;
    int winning_priority = std::numeric_limits<int>::min();

    for (const auto& rule : policy_.rules) {
        if (!rule_matches(rule, request, risk, identity_store_)) continue;
        if (result.matched_rule_ids.size() < budget_.max_matched_rules) {
            result.matched_rule_ids.push_back(rule.immutable_id());
        } else {
            result.matched_rules_truncated = true;
        }
        append_trace(result, budget_, "MATCH",
                     rule.rule_name + " => " + std::string(to_string(rule.effect)));

        const int precedence = decision_precedence(rule.effect);
        if (!winning || precedence > winning_precedence ||
            (precedence == winning_precedence && rule.priority > winning_priority) ||
            (precedence == winning_precedence && rule.priority == winning_priority &&
             rule.immutable_id() < winning->immutable_id())) {
            winning = &rule;
            winning_precedence = precedence;
            winning_priority = rule.priority;
        }
    }

    if (!winning) {
        result.decision = PolicyDecision::Refuse;
        result.reason = "no policy rule matched; default deny";
        append_trace(result, budget_, "DEFAULT", result.reason);
        return result;
    }

    result.decision = winning->effect;
    result.reason = "policy rule " + winning->rule_name + " selected " +
                    std::string(to_string(winning->effect));
    if (result.reason.size() > budget_.max_reason_bytes) {
        result.reason.resize(budget_.max_reason_bytes);
    }
    append_trace(result, budget_, "DECISION", result.reason);
    return result;
}

const PolicyDocument& DeclarativePolicyEngine::policy() const noexcept {
    return policy_;
}

const PolicyEvaluationBudget& DeclarativePolicyEngine::budget() const noexcept {
    return budget_;
}

PolicyRisk classify_policy_risk(const PolicyOperation& operation) noexcept {
    PolicyRisk risk = PolicyRisk::Low;
    switch (operation.capability) {
    case SlotCapability::ModelInfer:
    case SlotCapability::RepositoryRead:
    case SlotCapability::AudioAnalyze:
    case SlotCapability::WorldObserve:
    case SlotCapability::TranslateRepresentation:
        risk = PolicyRisk::Low;
        break;
    case SlotCapability::CodeBuild:
    case SlotCapability::CodeTest:
    case SlotCapability::AudioGenerate:
    case SlotCapability::ImageGenerate:
    case SlotCapability::VideoRender:
        risk = PolicyRisk::Moderate;
        break;
    case SlotCapability::RepositoryWrite:
    case SlotCapability::WorldMutate:
    case SlotCapability::GenericTool:
        risk = PolicyRisk::High;
        break;
    }

    if (operation.uncertainty >= 0.75) risk = std::max(risk, PolicyRisk::High);
    else if (operation.uncertainty >= 0.40) risk = std::max(risk, PolicyRisk::Moderate);
    if (operation.persistent || operation.external_side_effect) {
        risk = std::max(risk, PolicyRisk::High);
    }
    if (operation.destructive) risk = PolicyRisk::Critical;
    return risk;
}

std::string canonical_policy_rule(const PolicyRule& rule) {
    std::ostringstream out;
    out << rule.schema_version << '\n'
        << rule.rule_name << '\n'
        << rule.priority << '\n'
        << to_string(rule.effect) << '\n'
        << rule.subject_prefix << '\n'
        << rule.slot_id << '\n'
        << optional_capability_token(rule.capability) << '\n'
        << optional_layer_token(rule.layer) << '\n'
        << optional_bool_token(rule.destructive) << '\n'
        << optional_bool_token(rule.persistent) << '\n'
        << optional_bool_token(rule.external_side_effect) << '\n'
        << to_string(rule.min_risk) << '\n'
        << to_string(rule.max_risk) << '\n'
        << to_string(rule.min_authority) << '\n'
        << bool_token(rule.require_validated_authority) << '\n'
        << bool_token(rule.require_runtime_binding) << '\n'
        << bool_token(rule.require_active_identity) << '\n'
        << bool_token(rule.enabled) << '\n';
    const auto tags = canonical_tags(rule.tags);
    out << tags.size() << '\n';
    for (const auto& tag : tags) out << tag.size() << ':' << tag << '\n';
    return out.str();
}

std::string_view to_string(PolicyDecision decision) noexcept {
    switch (decision) {
    case PolicyDecision::Allow: return "ALLOW";
    case PolicyDecision::Refuse: return "REFUSE";
    case PolicyDecision::HumanReview: return "HUMAN_REVIEW";
    }
    return "REFUSE";
}

std::string_view to_string(PolicyRisk risk) noexcept {
    switch (risk) {
    case PolicyRisk::Low: return "LOW";
    case PolicyRisk::Moderate: return "MODERATE";
    case PolicyRisk::High: return "HIGH";
    case PolicyRisk::Critical: return "CRITICAL";
    }
    return "CRITICAL";
}

std::string_view to_string(PolicyAuthorityLevel level) noexcept {
    switch (level) {
    case PolicyAuthorityLevel::None: return "NONE";
    case PolicyAuthorityLevel::SignedReceipt: return "SIGNED_RECEIPT";
    case PolicyAuthorityLevel::DurableReceipt: return "DURABLE_RECEIPT";
    case PolicyAuthorityLevel::DelegatedReceipt: return "DELEGATED_RECEIPT";
    case PolicyAuthorityLevel::SessionKey: return "SESSION_KEY";
    case PolicyAuthorityLevel::RuntimeLease: return "RUNTIME_LEASE";
    case PolicyAuthorityLevel::AttestedRuntimeLease: return "ATTESTED_RUNTIME_LEASE";
    }
    return "NONE";
}

std::string_view to_string(PolicyEvaluationStatus status) noexcept {
    switch (status) {
    case PolicyEvaluationStatus::Decided: return "DECIDED";
    case PolicyEvaluationStatus::InvalidPolicy: return "INVALID_POLICY";
    case PolicyEvaluationStatus::InvalidRequest: return "INVALID_REQUEST";
    case PolicyEvaluationStatus::IdentityRejected: return "IDENTITY_REJECTED";
    case PolicyEvaluationStatus::AuthorityRejected: return "AUTHORITY_REJECTED";
    case PolicyEvaluationStatus::BudgetExceeded: return "BUDGET_EXCEEDED";
    case PolicyEvaluationStatus::PolicyInactive: return "POLICY_INACTIVE";
    }
    return "INVALID_REQUEST";
}

} // namespace guff
