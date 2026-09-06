#include "guff/policy_engine.hpp"
#include "guff/sha256.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <utility>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "CHECK failed: " #expression << " @ " << __FILE__ << ':' << __LINE__ << '\n'; return 1; } } while (false)

namespace {

guff::RuntimeAttestationEvidence make_evidence(
    std::string slot,
    guff::RealityLayer layer,
    std::string session_seed = "l23-session") {
    guff::RuntimeAttestationEvidence evidence;
    evidence.provider_id = "guff.test-attestor.l23";
    evidence.trust = guff::RuntimeAttestationTrust::NativeOsLocal;
    evidence.binding.device_id = "guff:hardware:sha256:" + guff::sha256("l23-device");
    evidence.binding.executable_sha256 = guff::sha256("l23-executable");
    evidence.process_id = 23023U;
    evidence.process_started_unix_ms = 1'725'600'000'000ULL;
    evidence.binding.process_instance_sha256 = guff::runtime_process_instance_sha256(
        evidence.binding.device_id,
        evidence.binding.executable_sha256,
        evidence.process_id,
        evidence.process_started_unix_ms,
        guff::sha256("l23-process-nonce"));
    evidence.binding.slot_id = std::move(slot);
    evidence.binding.session_id = "guff:session:sha256:" + guff::sha256(session_seed);
    evidence.binding.layer = layer;
    evidence.observed_at_unix_ms = 1'725'600'010'000ULL;
    evidence.valid_until_unix_ms = evidence.observed_at_unix_ms + 5'000ULL;
    evidence.challenge_nonce = "challenge-l23";
    evidence.executable_locator_sha256 = guff::sha256("/opt/guff/l23-test");
    evidence.canonical_sha256 = guff::sha256(guff::canonical_runtime_attestation(evidence));
    evidence.attestation_id = guff::runtime_attestation_id(evidence);
    return evidence;
}

guff::PolicyAuthorityFacts runtime_authority() {
    return {
        .level = guff::PolicyAuthorityLevel::AttestedRuntimeLease,
        .validated = true,
        .scope_matches = true,
        .capability_matches = true,
        .runtime_binding_matches = true,
        .authority_id = "guff:lease:sha256:" + guff::sha256("l23-authority"),
    };
}

guff::PolicyDocument make_policy() {
    guff::PolicyDocument policy;
    policy.policy_name = "ring-l23-default";

    guff::PolicyRule read;
    read.rule_name = "allow-project-repository-read";
    read.priority = 100;
    read.effect = guff::PolicyDecision::Allow;
    read.subject_prefix = "project:";
    read.capability = guff::SlotCapability::RepositoryRead;
    read.layer = guff::RealityLayer::Project;
    read.max_risk = guff::PolicyRisk::Low;
    read.require_active_identity = true;

    guff::PolicyRule build;
    build.rule_name = "allow-attested-build";
    build.priority = 100;
    build.effect = guff::PolicyDecision::Allow;
    build.subject_prefix = "project:";
    build.capability = guff::SlotCapability::CodeBuild;
    build.layer = guff::RealityLayer::Project;
    build.min_risk = guff::PolicyRisk::Moderate;
    build.max_risk = guff::PolicyRisk::Moderate;
    build.min_authority = guff::PolicyAuthorityLevel::AttestedRuntimeLease;
    build.require_validated_authority = true;
    build.require_runtime_binding = true;
    build.require_active_identity = true;

    guff::PolicyRule high_review;
    high_review.rule_name = "review-high-risk-project-work";
    high_review.priority = 50;
    high_review.effect = guff::PolicyDecision::HumanReview;
    high_review.subject_prefix = "project:";
    high_review.min_risk = guff::PolicyRisk::High;
    high_review.max_risk = guff::PolicyRisk::Critical;
    high_review.min_authority = guff::PolicyAuthorityLevel::RuntimeLease;
    high_review.require_validated_authority = true;
    high_review.require_runtime_binding = true;
    high_review.require_active_identity = true;

    guff::PolicyRule deny_world;
    deny_world.rule_name = "deny-world-mutation";
    deny_world.priority = -100;
    deny_world.effect = guff::PolicyDecision::Refuse;
    deny_world.capability = guff::SlotCapability::WorldMutate;

    policy.rules = {read, build, high_review, deny_world};
    return policy;
}

guff::PolicyEvaluationRequest base_request(
    guff::RuntimeAttestationEvidence evidence,
    guff::SlotCapability capability,
    guff::RealityLayer layer) {
    guff::PolicyEvaluationRequest request;
    request.operation.subject_id = "project:spiraletech/GOLF-GUFF";
    request.operation.slot_id = evidence.binding.slot_id;
    request.operation.capability = capability;
    request.operation.layer = layer;
    request.operation.uncertainty = 0.05;
    request.authority = runtime_authority();
    request.identity_evidence = std::move(evidence);
    return request;
}

} // namespace

int main() {
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-l23-policy-engine");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);
    CHECK(!ec);

    guff::RuntimeIdentityStore identities(root / "identities.journal");

    auto build_evidence = make_evidence("forge.compiler", guff::RealityLayer::Project);
    CHECK(guff::validate_runtime_attestation_identity(build_evidence));
    CHECK(identities.record_attestation(build_evidence).ok());

    auto repo_evidence = make_evidence(
        "repo.reader", guff::RealityLayer::Project, "l23-repo-session");
    CHECK(identities.record_attestation(repo_evidence).ok());

    auto world_evidence = make_evidence(
        "hakui.world", guff::RealityLayer::Simulation, "l23-world-session");
    CHECK(identities.record_attestation(world_evidence).ok());

    auto policy = make_policy();
    CHECK(policy.validate().empty());
    const auto policy_id = policy.immutable_id();
    CHECK(policy_id.starts_with("guff:policy:sha256:"));

    // Rule order is not semantic; immutable policy identity is canonicalized.
    auto reordered = policy;
    std::reverse(reordered.rules.begin(), reordered.rules.end());
    CHECK(reordered.immutable_id() == policy_id);

    guff::DeclarativePolicyEngine engine(policy, identities);

    // Low-risk read can be allowed by policy without consuming an authority path.
    auto read_request = base_request(
        repo_evidence, guff::SlotCapability::RepositoryRead, guff::RealityLayer::Project);
    read_request.operation.requires_authority = false;
    read_request.authority = {};
    auto read_result = engine.evaluate(read_request);
    CHECK(read_result.status == guff::PolicyEvaluationStatus::Decided);
    CHECK(read_result.decision == guff::PolicyDecision::Allow);
    CHECK(read_result.risk == guff::PolicyRisk::Low);
    CHECK(read_result.policy_id == policy_id);

    // Moderate build requires validated attested-runtime authority and exact runtime binding.
    auto build_request = base_request(
        build_evidence, guff::SlotCapability::CodeBuild, guff::RealityLayer::Project);
    auto build_result = engine.evaluate(build_request);
    CHECK(build_result.allowed());
    CHECK(build_result.risk == guff::PolicyRisk::Moderate);

    auto missing_authority = build_request;
    missing_authority.authority = {};
    auto missing_authority_result = engine.evaluate(missing_authority);
    CHECK(missing_authority_result.status == guff::PolicyEvaluationStatus::AuthorityRejected);
    CHECK(missing_authority_result.decision == guff::PolicyDecision::Refuse);

    auto bad_scope = build_request;
    bad_scope.authority.scope_matches = false;
    CHECK(engine.evaluate(bad_scope).status == guff::PolicyEvaluationStatus::AuthorityRejected);

    auto bad_runtime = build_request;
    bad_runtime.authority.runtime_binding_matches = false;
    CHECK(engine.evaluate(bad_runtime).status == guff::PolicyEvaluationStatus::AuthorityRejected);

    auto wrong_slot_identity = build_request;
    wrong_slot_identity.operation.slot_id = "forge.other";
    CHECK(engine.evaluate(wrong_slot_identity).status == guff::PolicyEvaluationStatus::IdentityRejected);

    // High uncertainty raises a normally moderate build into review; allow rule no longer matches.
    auto uncertain = build_request;
    uncertain.operation.uncertainty = 0.90;
    auto uncertain_result = engine.evaluate(uncertain);
    CHECK(uncertain_result.risk == guff::PolicyRisk::High);
    CHECK(uncertain_result.decision == guff::PolicyDecision::HumanReview);

    // Destructive work is always classified CRITICAL before rules see it.
    auto destructive = build_request;
    destructive.operation.destructive = true;
    auto destructive_result = engine.evaluate(destructive);
    CHECK(destructive_result.risk == guff::PolicyRisk::Critical);
    CHECK(destructive_result.decision == guff::PolicyDecision::HumanReview);

    // Explicit deny beats review and allow regardless of lower numeric priority.
    auto world_request = base_request(
        world_evidence, guff::SlotCapability::WorldMutate, guff::RealityLayer::Simulation);
    world_request.operation.external_side_effect = true;
    auto world_result = engine.evaluate(world_request);
    CHECK(world_result.risk == guff::PolicyRisk::High);
    CHECK(world_result.decision == guff::PolicyDecision::Refuse);

    // No matching allow is default-deny.
    auto image_evidence = make_evidence(
        "image.generator", guff::RealityLayer::Application, "l23-image-session");
    CHECK(identities.record_attestation(image_evidence).ok());
    auto image_request = base_request(
        image_evidence, guff::SlotCapability::ImageGenerate, guff::RealityLayer::Application);
    auto image_result = engine.evaluate(image_request);
    CHECK(image_result.status == guff::PolicyEvaluationStatus::Decided);
    CHECK(image_result.decision == guff::PolicyDecision::Refuse);
    CHECK(image_result.reason.find("default deny") != std::string::npos);

    // Revocation is checked before permissive rules and does not mutate authority state.
    const auto process_id = guff::runtime_process_identity_id(
        build_evidence.provider_id, build_evidence.binding.process_instance_sha256);
    const auto before = identities.inspect();
    CHECK(identities.revoke_process(process_id, build_evidence.observed_at_unix_ms + 1U,
                                    "operator-revoked").ok());
    auto revoked_result = engine.evaluate(build_request);
    CHECK(revoked_result.status == guff::PolicyEvaluationStatus::IdentityRejected);
    CHECK(revoked_result.decision == guff::PolicyDecision::Refuse);
    const auto after = identities.inspect();
    CHECK(after.attestations == before.attestations);

    // Default-allow documents are invalid by construction.
    auto unsafe_policy = policy;
    unsafe_policy.default_decision = guff::PolicyDecision::Allow;
    guff::DeclarativePolicyEngine unsafe_engine(unsafe_policy, identities);
    auto unsafe_result = unsafe_engine.evaluate(read_request);
    CHECK(unsafe_result.status == guff::PolicyEvaluationStatus::InvalidPolicy);
    CHECK(unsafe_result.decision == guff::PolicyDecision::Refuse);

    // An unconstrained ALLOW rule is rejected to prevent accidental allow-all policy.
    guff::PolicyDocument wildcard_policy;
    wildcard_policy.policy_name = "unsafe-wildcard";
    guff::PolicyRule wildcard;
    wildcard.rule_name = "allow-everything";
    wildcard.effect = guff::PolicyDecision::Allow;
    wildcard_policy.rules = {wildcard};
    CHECK(!wildcard_policy.validate().empty());

    // Hard evaluation ceilings fail closed.
    guff::DeclarativePolicyEngine tiny_budget(
        policy, identities, {.max_rules = 1U, .max_matched_rules = 1U,
                             .max_trace_entries = 4U, .max_reason_bytes = 128U});
    auto budget_result = tiny_budget.evaluate(read_request);
    CHECK(budget_result.status == guff::PolicyEvaluationStatus::BudgetExceeded);
    CHECK(budget_result.decision == guff::PolicyDecision::Refuse);

    std::filesystem::remove_all(root, ec);
    return 0;
}
