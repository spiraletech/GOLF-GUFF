#include "guff/operator_console.hpp"
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

guff::PolicyEvaluationRequest build_request() {
    guff::PolicyEvaluationRequest request;
    request.operation.subject_id = "project:spiraletech/GOLF-GUFF";
    request.operation.slot_id = "forge.compiler";
    request.operation.capability = guff::SlotCapability::CodeBuild;
    request.operation.layer = guff::RealityLayer::Project;
    request.operation.requires_identity = false;
    request.operation.requires_authority = false;
    return request;
}

guff::SignedPolicyControl direct_control(
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
    envelope.actor_reference = "operator:test-bootstrap";
    envelope.issued_at_unix_ms = now;
    envelope.nonce = std::move(nonce);
    envelope.reason_sha256 = guff::sha256("bootstrap policy control");
    auto control = guff::issue_signed_policy_control(envelope, signer);
    if (!control) std::abort();
    return *control;
}

} // namespace

int main() {
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-l25-operator-console");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);
    CHECK(!ec);

    TestSigner author("policy-author:l25", "author-secret");
    TestSigner admin("policy-admin:l25", "admin-secret");

    const auto policy1 = make_policy("operator-policy-review", true);
    const auto policy2 = make_policy("operator-policy-allow", false);
    auto package1 = guff::issue_signed_policy_package(policy1, 1000U, author);
    auto package2 = guff::issue_signed_policy_package(policy2, 2000U, author);
    CHECK(package1 && package2);

    guff::SignedPolicyRegistry registry(root / "policies.journal", author, admin);
    CHECK(registry.register_policy(policy1, *package1).ok());
    CHECK(registry.register_policy(policy2, *package2).ok());
    CHECK(registry.apply_control(direct_control(
        guff::PolicyControlAction::Activate, *package1, {}, "activate-p1", 3000U, admin)).ok());

    guff::SessionJournal sessions(root / "sessions.journal");
    guff::JournalBegin interrupted;
    interrupted.session_id = "guff:session:sha256:" + guff::sha256("l25-interrupted-session");
    interrupted.correlation_id = "l25-interrupted";
    interrupted.request_sha256 = guff::sha256("interrupted request");
    interrupted.recorded_at_utc = "2026-09-06T05:10:00Z";
    CHECK(sessions.begin(interrupted).ok());

    guff::AuthorityLedger authority(root / "authority.journal", admin,
                                    [] { return 10'000ULL; });
    guff::RuntimeIdentityStore identities(root / "identities.journal");
    guff::OperatorReviewQueue reviews(root / "reviews.journal");
    guff::OperatorConsole console(registry, sessions, authority, identities, reviews);

    auto snapshot = console.snapshot();
    CHECK(snapshot.healthy);
    CHECK(snapshot.policy.active_policy_id == policy1.immutable_id());
    CHECK(snapshot.active_policy.has_value());
    CHECK(snapshot.active_policy->package_id == package1->package_id);
    CHECK(snapshot.active_policy->signer_id == author.signer_id());
    CHECK(snapshot.recovery.interrupted.size() == 1U);
    CHECK(snapshot.authority.healthy);
    CHECK(snapshot.identities.healthy);
    CHECK(snapshot.reviews.pending == 0U);

    guff::RegistryBackedPolicyEngine engine(registry, policy1, identities);
    const auto request = build_request();
    const auto decision = engine.evaluate(request);
    CHECK(decision.status == guff::PolicyEvaluationStatus::Decided);
    CHECK(decision.decision == guff::PolicyDecision::HumanReview);

    const auto queued = console.enqueue_review(decision, request, 4000U);
    CHECK(queued.ok());
    CHECK(queued.ticket_id.starts_with("guff:operator-review:sha256:"));
    snapshot = console.snapshot();
    CHECK(snapshot.reviews.pending == 1U);
    CHECK(snapshot.reviews.pending_tickets.size() == 1U);
    CHECK(snapshot.reviews.pending_tickets.front().policy_id == policy1.immutable_id());
    CHECK(snapshot.reviews.pending_tickets.front().reason == decision.reason);

    // Queue closure is deliberately non-authorizing: there is no ALLOW state.
    const auto deferred = reviews.close(
        queued.ticket_id,
        guff::OperatorReviewState::Deferred,
        5000U,
        guff::sha256("operator needs stronger authority evidence"));
    CHECK(deferred.ok());
    CHECK(reviews.close(
        queued.ticket_id,
        guff::OperatorReviewState::Refused,
        5001U,
        guff::sha256("second close")).status == guff::OperatorConsoleStatus::AlreadyClosed);

    guff::OperatorReviewQueue reopened_reviews(root / "reviews.journal");
    const auto review_state = reopened_reviews.inspect();
    CHECK(review_state.healthy);
    CHECK(review_state.tickets == 1U);
    CHECK(review_state.pending == 0U);
    CHECK(review_state.deferred == 1U);

    // The operator surface can issue a signed control but cannot bypass L24 trust domains.
    guff::OperatorPolicyControlRequest activate2;
    activate2.action = guff::PolicyControlAction::Activate;
    activate2.policy_id = policy2.immutable_id();
    activate2.actor_reference = "operator:local-console";
    activate2.issued_at_unix_ms = 6000U;
    activate2.nonce = "activate-policy2";
    activate2.reason = "switch from review policy to approved build policy";

    std::vector<std::string> errors;
    const auto unauthorized_control = console.issue_policy_control(activate2, author, &errors);
    CHECK(unauthorized_control.has_value());
    CHECK(console.apply_policy_control(*unauthorized_control).status ==
          guff::PolicyRegistryStatus::SignatureRejected);
    CHECK(registry.active_policy_id() == policy1.immutable_id());

    errors.clear();
    const auto control = console.issue_policy_control(activate2, admin, &errors);
    CHECK(control.has_value());
    CHECK(errors.empty());
    CHECK(control->envelope.expected_active_policy_id == policy1.immutable_id());
    CHECK(control->envelope.package_id == package2->package_id);
    CHECK(control->envelope.reason_sha256 == guff::sha256(activate2.reason));
    CHECK(console.apply_policy_control(*control).ok());
    CHECK(registry.active_policy_id() == policy2.immutable_id());
    CHECK(console.apply_policy_control(*control).status ==
          guff::PolicyRegistryStatus::ReplayRejected);

    snapshot = console.snapshot();
    CHECK(snapshot.healthy);
    CHECK(snapshot.active_policy.has_value());
    CHECK(snapshot.active_policy->policy_id == policy2.immutable_id());
    CHECK(snapshot.active_policy->signer_id == author.signer_id());

    // An old HUMAN_REVIEW decision cannot be queued after its policy stops being active.
    CHECK(console.enqueue_review(decision, request, 7000U).status ==
          guff::OperatorConsoleStatus::Invalid);

    // An ALLOW decision never enters the review queue.
    guff::RegistryBackedPolicyEngine engine2(registry, policy2, identities);
    const auto allowed = engine2.evaluate(request);
    CHECK(allowed.allowed());
    CHECK(console.enqueue_review(allowed, request, 7001U).status ==
          guff::OperatorConsoleStatus::NotHumanReview);

    // Review-journal corruption makes the aggregate console unhealthy instead of hiding it.
    {
        std::ofstream corrupt(root / "reviews.journal", std::ios::app);
        CHECK(static_cast<bool>(corrupt));
        corrupt << "CORRUPTED-L25-TAIL\n";
    }
    CHECK(!console.snapshot().healthy);

    std::filesystem::remove_all(root, ec);
    return 0;
}
