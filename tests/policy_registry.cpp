#include "guff/policy_registry.hpp"
#include "guff/sha256.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "CHECK failed: " #expression << " @ " << __FILE__ << ':' << __LINE__ << '\n'; return 1; } } while (false)

namespace {

class TestSigner final : public guff::AuthoritySigner, public guff::AuthorityVerifier {
public:
    TestSigner(std::string id, std::string secret)
        : id_(std::move(id)), secret_(std::move(secret)) {}

    std::string signer_id() const override { return id_; }
    std::string algorithm() const override { return "TEST-SHA256"; }
    std::optional<std::string> sign(std::string_view canonical) const override {
        return guff::sha256(secret_ + "\n" + std::string(canonical));
    }
    bool knows(std::string_view signer, std::string_view algorithm_name) const override {
        return signer == id_ && algorithm_name == algorithm();
    }
    bool verify(std::string_view signer,
                std::string_view algorithm_name,
                std::string_view canonical,
                std::string_view signature) const override {
        if (!knows(signer, algorithm_name)) return false;
        const auto expected = sign(canonical);
        return expected && *expected == signature;
    }

private:
    std::string id_;
    std::string secret_;
};

guff::PolicyDocument make_policy(std::string name, bool review_builds) {
    guff::PolicyDocument policy;
    policy.policy_name = std::move(name);

    guff::PolicyRule read;
    read.rule_name = "allow-project-read";
    read.effect = guff::PolicyDecision::Allow;
    read.subject_prefix = "project:";
    read.capability = guff::SlotCapability::RepositoryRead;
    read.layer = guff::RealityLayer::Project;
    read.max_risk = guff::PolicyRisk::Low;

    guff::PolicyRule build;
    build.rule_name = review_builds ? "review-build" : "allow-build";
    build.effect = review_builds ? guff::PolicyDecision::HumanReview
                                 : guff::PolicyDecision::Allow;
    build.subject_prefix = "project:";
    build.capability = guff::SlotCapability::CodeBuild;
    build.layer = guff::RealityLayer::Project;
    build.min_risk = guff::PolicyRisk::Moderate;
    build.max_risk = guff::PolicyRisk::Moderate;

    policy.rules = {read, build};
    return policy;
}

guff::PolicyEvaluationRequest read_request() {
    guff::PolicyEvaluationRequest request;
    request.operation.subject_id = "project:spiraletech/GOLF-GUFF";
    request.operation.slot_id = "repo.reader";
    request.operation.capability = guff::SlotCapability::RepositoryRead;
    request.operation.layer = guff::RealityLayer::Project;
    request.operation.requires_identity = false;
    request.operation.requires_authority = false;
    return request;
}

guff::SignedPolicyControl make_control(
    guff::PolicyControlAction action,
    const guff::SignedPolicyPackage& package,
    std::string expected_active,
    std::string nonce,
    std::uint64_t now,
    const guff::AuthoritySigner& signer) {
    guff::PolicyControlEnvelope envelope;
    envelope.action = action;
    envelope.package_id = package.package_id;
    envelope.policy_id = package.policy_id;
    envelope.expected_active_policy_id = std::move(expected_active);
    envelope.actor_reference = "operator:local-console";
    envelope.issued_at_unix_ms = now;
    envelope.nonce = std::move(nonce);
    envelope.reason_sha256 = guff::sha256(
        std::string(guff::to_string(action)) + " policy control regression");
    auto control = guff::issue_signed_policy_control(envelope, signer);
    if (!control) std::abort();
    return *control;
}

} // namespace

int main() {
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-l24-policy-registry");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);
    CHECK(!ec);

    TestSigner author("policy-author:test", "author-secret");
    TestSigner admin("policy-admin:test", "admin-secret");

    const auto policy1 = make_policy("ring-policy-v1", false);
    const auto policy2 = make_policy("ring-policy-v2", true);
    const auto policy3 = make_policy("ring-policy-v3-never-active", false);
    CHECK(policy1.validate().empty());
    CHECK(policy2.validate().empty());
    CHECK(policy1.immutable_id() != policy2.immutable_id());

    auto package1 = guff::issue_signed_policy_package(policy1, 1'725'700'000'000ULL, author);
    auto package2 = guff::issue_signed_policy_package(policy2, 1'725'700'001'000ULL, author);
    auto package3 = guff::issue_signed_policy_package(policy3, 1'725'700'002'000ULL, author);
    CHECK(package1 && package2 && package3);
    CHECK(package1->package_id.starts_with("guff:policy-package:sha256:"));

    guff::RuntimeIdentityStore identities(root / "identities.journal");
    guff::SignedPolicyRegistry registry(root / "policies.journal", author, admin);

    CHECK(registry.register_policy(policy1, *package1).ok());
    CHECK(registry.register_policy(policy2, *package2).ok());
    CHECK(registry.register_policy(policy3, *package3).ok());
    CHECK(registry.register_policy(policy1, *package1).status ==
          guff::PolicyRegistryStatus::AlreadyRegistered);

    auto forged = *package2;
    forged.signature = guff::sha256("forged-policy-signature");
    CHECK(registry.register_policy(policy2, forged).status ==
          guff::PolicyRegistryStatus::SignatureRejected);

    guff::RegistryBackedPolicyEngine engine1(registry, policy1, identities);
    guff::RegistryBackedPolicyEngine engine2(registry, policy2, identities);
    const auto request = read_request();
    CHECK(engine1.evaluate(request).status == guff::PolicyEvaluationStatus::PolicyInactive);

    const auto activate1 = make_control(
        guff::PolicyControlAction::Activate, *package1, {}, "activate-v1", 100U, admin);
    CHECK(registry.apply_control(activate1).ok());
    CHECK(registry.is_active(policy1));
    CHECK(engine1.evaluate(request).allowed());
    CHECK(registry.apply_control(activate1).status ==
          guff::PolicyRegistryStatus::ReplayRejected);

    // Policy authorship and activation authority are distinct trust domains.
    const auto author_control = make_control(
        guff::PolicyControlAction::Activate, *package2, policy1.immutable_id(),
        "author-self-activate", 101U, author);
    CHECK(registry.apply_control(author_control).status ==
          guff::PolicyRegistryStatus::SignatureRejected);

    // A stale process cannot replace policy using an obsolete expected-active value.
    const auto stale_activate2 = make_control(
        guff::PolicyControlAction::Activate, *package2, {}, "stale-v2", 102U, admin);
    CHECK(registry.apply_control(stale_activate2).status ==
          guff::PolicyRegistryStatus::ActiveMismatch);
    CHECK(registry.is_active(policy1));

    // Same signer/nonce cannot authorize a distinct control object.
    const auto nonce_collision = make_control(
        guff::PolicyControlAction::Revoke, *package1, policy1.immutable_id(),
        "activate-v1", 103U, admin);
    CHECK(registry.apply_control(nonce_collision).status ==
          guff::PolicyRegistryStatus::ReplayRejected);

    const auto activate2 = make_control(
        guff::PolicyControlAction::Activate, *package2, policy1.immutable_id(),
        "activate-v2", 104U, admin);
    CHECK(registry.apply_control(activate2).ok());
    CHECK(registry.is_active(policy2));
    CHECK(engine1.evaluate(request).status == guff::PolicyEvaluationStatus::PolicyInactive);
    CHECK(engine2.evaluate(request).allowed());

    // ROLLBACK is restricted to a policy that was previously active.
    const auto invalid_rollback3 = make_control(
        guff::PolicyControlAction::Rollback, *package3, policy2.immutable_id(),
        "rollback-never-active", 105U, admin);
    CHECK(registry.apply_control(invalid_rollback3).status ==
          guff::PolicyRegistryStatus::Invalid);

    const auto rollback1 = make_control(
        guff::PolicyControlAction::Rollback, *package1, policy2.immutable_id(),
        "rollback-v1", 106U, admin);
    CHECK(registry.apply_control(rollback1).ok());
    CHECK(registry.is_active(policy1));

    // Revoking the active policy fails closed to no active policy.
    const auto revoke1 = make_control(
        guff::PolicyControlAction::Revoke, *package1, policy1.immutable_id(),
        "revoke-v1", 107U, admin);
    CHECK(registry.apply_control(revoke1).ok());
    CHECK(registry.active_policy_id().empty());
    CHECK(engine1.evaluate(request).status == guff::PolicyEvaluationStatus::PolicyInactive);

    const auto reactivate_revoked1 = make_control(
        guff::PolicyControlAction::Activate, *package1, {}, "reactivate-revoked", 108U, admin);
    CHECK(registry.apply_control(reactivate_revoked1).status ==
          guff::PolicyRegistryStatus::PolicyRevoked);

    const auto reactivate2 = make_control(
        guff::PolicyControlAction::Activate, *package2, {}, "activate-v2-again", 109U, admin);
    CHECK(registry.apply_control(reactivate2).ok());

    // Cold replay reconstructs policy versions, revocation, generation and active identity.
    guff::SignedPolicyRegistry reopened(root / "policies.journal", author, admin);
    const auto snapshot = reopened.inspect();
    CHECK(snapshot.healthy);
    CHECK(snapshot.registered_policies == 3U);
    CHECK(snapshot.revoked_policies == 1U);
    CHECK(snapshot.active_policy_id == policy2.immutable_id());
    CHECK(snapshot.activation_generation == 5U);
    guff::RegistryBackedPolicyEngine reopened_engine(reopened, policy2, identities);
    CHECK(reopened_engine.evaluate(request).allowed());

    // Tail corruption is fail-closed: no stale in-memory policy remains authorized.
    {
        std::ofstream corrupt(root / "policies.journal", std::ios::app);
        CHECK(static_cast<bool>(corrupt));
        corrupt << "CORRUPTED-L24-TAIL\n";
    }
    CHECK(!reopened.inspect().healthy);
    CHECK(reopened_engine.evaluate(request).status == guff::PolicyEvaluationStatus::PolicyInactive);

    std::filesystem::remove_all(root, ec);
    return 0;
}
