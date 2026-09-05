#include "guff/authority_delegation.hpp"
#include "guff/authority_gate.hpp"
#include "guff/sha256.hpp"

#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "CHECK failed: " #expression << " @ " << __FILE__ << ':' << __LINE__ << '\n'; return 1; } } while (false)

namespace {

class TestSigner final : public guff::AuthoritySigner, public guff::AuthorityVerifier {
public:
    std::string signer_id() const override { return "local:l18-delegation-signer"; }
    std::string algorithm() const override { return "TEST-SHA256"; }
    std::optional<std::string> sign(std::string_view canonical) const override {
        return guff::sha256(std::string("l18-delegation-secret\n") + std::string(canonical));
    }
    bool knows(std::string_view signer, std::string_view algorithm_name) const override {
        return signer == signer_id() && algorithm_name == algorithm();
    }
    bool verify(std::string_view signer,
                std::string_view algorithm_name,
                std::string_view canonical,
                std::string_view signature) const override {
        if (!knows(signer, algorithm_name)) return false;
        const auto expected = sign(canonical);
        return expected && *expected == signature;
    }
};

std::optional<guff::AuthorityReceipt> root_receipt(
    const TestSigner& signer,
    std::string nonce,
    std::string scope_path,
    std::vector<std::string> capabilities,
    std::uint64_t issued_at,
    std::uint64_t expires_at,
    std::uint32_t max_uses,
    std::uint32_t max_depth) {
    guff::AuthorityEnvelope envelope;
    envelope.schema_version = 3U;
    envelope.purpose = guff::AuthorityPurpose::CapabilityGrant;
    envelope.subject_id = "project:spiraletech/GOLF-GUFF";
    envelope.actor_reference = "human:l18-root";
    envelope.signer_id = signer.signer_id();
    envelope.signer_key_id = "key-delegation";
    envelope.issued_at_utc = "2026-09-05T04:00:00Z";
    envelope.issued_at_unix_ms = issued_at;
    envelope.expires_at_unix_ms = expires_at;
    envelope.max_uses = max_uses;
    envelope.nonce = std::move(nonce);
    envelope.scope_path = std::move(scope_path);
    envelope.scope_sha256 = guff::sha256(envelope.scope_path);
    envelope.delegation_depth = 0U;
    envelope.max_delegation_depth = max_depth;
    envelope.capabilities = std::move(capabilities);
    return guff::issue_authority_receipt(envelope, signer);
}

guff::DelegationRequest child_request(
    const guff::AuthorityReceipt& parent,
    std::string nonce,
    std::string scope_path,
    std::vector<std::string> capabilities,
    std::uint64_t issued_at,
    std::uint64_t expires_at,
    std::uint32_t max_uses,
    std::uint32_t max_depth = 0U) {
    guff::DelegationRequest request;
    request.parent = parent;
    request.actor_reference = "agent:l18-child";
    request.issued_at_utc = "2026-09-05T04:01:00Z";
    request.nonce = std::move(nonce);
    request.scope_path = std::move(scope_path);
    request.capabilities = std::move(capabilities);
    request.issued_at_unix_ms = issued_at;
    request.expires_at_unix_ms = expires_at;
    request.max_uses = max_uses;
    request.max_delegation_depth = max_depth;
    return request;
}

} // namespace

int main() {
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-l18-authority-delegation");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);

    TestSigner signer;
    std::uint64_t now = 2'000U;
    const auto journal = root / "authority.journal";
    guff::AuthorityLedger ledger(journal, signer, [&]() { return now; });
    CHECK(ledger.trust_key({
        .signer_id = signer.signer_id(),
        .key_id = "key-delegation",
        .algorithm = signer.algorithm(),
        .valid_from_unix_ms = 1'000U,
    }).ok());
    guff::AuthorityDelegator delegator(ledger, signer);
    guff::AuthorityGate gate(ledger);

    auto parent = root_receipt(
        signer,
        "root-parent",
        "project:spiraletech/GOLF-GUFF",
        {"code:build", "code:test", "repo:read"},
        1'500U,
        5'000U,
        6U,
        2U);
    CHECK(parent.has_value());

    const auto parent_uses_before_rejects = ledger.use_count(parent->receipt_id);
    auto escaped_scope = delegator.delegate(
        child_request(*parent, "escape", "project:spiraletech/OTHER",
                      {"code:build"}, 1'600U, 3'000U, 1U), signer);
    CHECK(escaped_scope.status == guff::DelegationStatus::ScopeAmplification);
    CHECK(ledger.use_count(parent->receipt_id) == parent_uses_before_rejects);

    auto amplified_capability = delegator.delegate(
        child_request(*parent, "cap-escape", "project:spiraletech/GOLF-GUFF/src",
                      {"code:build", "world:mutate"}, 1'600U, 3'000U, 1U), signer);
    CHECK(amplified_capability.status == guff::DelegationStatus::CapabilityAmplification);
    CHECK(ledger.use_count(parent->receipt_id) == parent_uses_before_rejects);

    auto long_lived = delegator.delegate(
        child_request(*parent, "long-life", "project:spiraletech/GOLF-GUFF/src",
                      {"code:build"}, 1'600U, 6'000U, 1U), signer);
    CHECK(long_lived.status == guff::DelegationStatus::LifetimeAmplification);
    CHECK(ledger.use_count(parent->receipt_id) == parent_uses_before_rejects);

    auto child = delegator.delegate(
        child_request(*parent, "child-one", "project:spiraletech/GOLF-GUFF/src",
                      {"code:build"}, 1'600U, 3'500U, 2U, 1U), signer);
    CHECK(child.ok());
    CHECK(child.child->envelope.parent_receipt_id == parent->receipt_id);
    CHECK(child.child->envelope.delegation_depth == 1U);
    CHECK(child.child->envelope.max_delegation_depth == 1U);
    CHECK(ledger.delegation_registered(child.child->receipt_id));
    CHECK(ledger.delegation_parent(child.child->receipt_id) == parent->receipt_id);
    CHECK(ledger.use_count(parent->receipt_id) == 1U);
    CHECK(ledger.delegated_uses(parent->receipt_id) == 2U);

    const auto child_scope = child.child->envelope.scope_sha256;
    auto child_use_one = gate.authorize(
        child.child,
        guff::AuthorityPurpose::CapabilityGrant,
        child.child->envelope.subject_id,
        child_scope);
    CHECK(child_use_one.ok());
    auto child_use_two = gate.authorize(
        child.child,
        guff::AuthorityPurpose::CapabilityGrant,
        child.child->envelope.subject_id,
        child_scope);
    CHECK(child_use_two.ok());
    auto child_exhausted = gate.authorize(
        child.child,
        guff::AuthorityPurpose::CapabilityGrant,
        child.child->envelope.subject_id,
        child_scope);
    CHECK(child_exhausted.status == guff::AuthorityGateStatus::LedgerRejected);
    CHECK(child_exhausted.ledger_status == guff::AuthorityLedgerStatus::UseLimitReached);

    // The parent began with six uses. Delegation consumes one use and reserves two,
    // leaving exactly three direct parent uses; the fourth must fail.
    for (int i = 0; i < 3; ++i) {
        CHECK(gate.authorize(
            parent,
            guff::AuthorityPurpose::CapabilityGrant,
            parent->envelope.subject_id,
            parent->envelope.scope_sha256).ok());
    }
    auto parent_exhausted = gate.authorize(
        parent,
        guff::AuthorityPurpose::CapabilityGrant,
        parent->envelope.subject_id,
        parent->envelope.scope_sha256);
    CHECK(parent_exhausted.ledger_status == guff::AuthorityLedgerStatus::UseLimitReached);

    // Nested delegation proves budget conservation recursively.
    auto root_two = root_receipt(
        signer,
        "root-two",
        "project:spiraletech/GOLF-GUFF",
        {"code:build", "code:test", "repo:read"},
        1'500U,
        5'000U,
        10U,
        3U);
    CHECK(root_two);
    auto middle = delegator.delegate(
        child_request(*root_two, "middle", "project:spiraletech/GOLF-GUFF/src",
                      {"code:build", "code:test"}, 1'650U, 4'000U, 5U, 3U), signer);
    CHECK(middle.ok());
    auto leaf = delegator.delegate(
        child_request(*middle.child, "leaf", "project:spiraletech/GOLF-GUFF/src/compiler",
                      {"code:build"}, 1'700U, 3'000U, 2U, 2U), signer);
    CHECK(leaf.ok());
    CHECK(leaf.child->envelope.delegation_depth == 2U);
    CHECK(ledger.use_count(middle.child->receipt_id) == 1U);
    CHECK(ledger.delegated_uses(middle.child->receipt_id) == 2U);

    CHECK(gate.authorize(
        leaf.child, guff::AuthorityPurpose::CapabilityGrant,
        leaf.child->envelope.subject_id, leaf.child->envelope.scope_sha256).ok());
    CHECK(gate.authorize(
        leaf.child, guff::AuthorityPurpose::CapabilityGrant,
        leaf.child->envelope.subject_id, leaf.child->envelope.scope_sha256).ok());

    // Five-use middle: one spent to delegate + two reserved leaves two direct uses.
    CHECK(gate.authorize(
        middle.child, guff::AuthorityPurpose::CapabilityGrant,
        middle.child->envelope.subject_id, middle.child->envelope.scope_sha256).ok());
    CHECK(gate.authorize(
        middle.child, guff::AuthorityPurpose::CapabilityGrant,
        middle.child->envelope.subject_id, middle.child->envelope.scope_sha256).ok());
    CHECK(gate.authorize(
        middle.child, guff::AuthorityPurpose::CapabilityGrant,
        middle.child->envelope.subject_id, middle.child->envelope.scope_sha256).ledger_status ==
          guff::AuthorityLedgerStatus::UseLimitReached);

    // A delegated-looking child that was never registered cannot cross the gate.
    auto orphan_request = child_request(
        *root_two, "orphan", "project:spiraletech/GOLF-GUFF/docs",
        {"repo:read"}, 1'800U, 2'900U, 1U, 1U);
    guff::AuthorityEnvelope orphan_envelope;
    orphan_envelope.schema_version = 3U;
    orphan_envelope.purpose = root_two->envelope.purpose;
    orphan_envelope.subject_id = root_two->envelope.subject_id;
    orphan_envelope.actor_reference = orphan_request.actor_reference;
    orphan_envelope.signer_id = root_two->envelope.signer_id;
    orphan_envelope.signer_key_id = root_two->envelope.signer_key_id;
    orphan_envelope.issued_at_utc = orphan_request.issued_at_utc;
    orphan_envelope.issued_at_unix_ms = orphan_request.issued_at_unix_ms;
    orphan_envelope.expires_at_unix_ms = orphan_request.expires_at_unix_ms;
    orphan_envelope.max_uses = orphan_request.max_uses;
    orphan_envelope.nonce = orphan_request.nonce;
    orphan_envelope.scope_path = orphan_request.scope_path;
    orphan_envelope.scope_sha256 = guff::sha256(orphan_envelope.scope_path);
    orphan_envelope.parent_receipt_id = root_two->receipt_id;
    orphan_envelope.delegation_depth = 1U;
    orphan_envelope.max_delegation_depth = 1U;
    orphan_envelope.capabilities = orphan_request.capabilities;
    auto orphan = guff::issue_authority_receipt(orphan_envelope, signer);
    CHECK(orphan);
    auto orphan_denied = gate.authorize(
        orphan, guff::AuthorityPurpose::CapabilityGrant,
        orphan->envelope.subject_id, orphan->envelope.scope_sha256);
    CHECK(orphan_denied.ledger_status == guff::AuthorityLedgerStatus::DelegationRejected);

    // Parent revocation cascades to descendants even though their signatures remain valid.
    auto revocation_root = root_receipt(
        signer, "revocation-root", "project:spiraletech/GOLF-GUFF",
        {"code:build", "code:test"}, 1'500U, 5'000U, 8U, 3U);
    CHECK(revocation_root);
    auto revocation_mid = delegator.delegate(
        child_request(*revocation_root, "revocation-mid", "project:spiraletech/GOLF-GUFF/src",
                      {"code:build"}, 1'600U, 4'000U, 3U, 2U), signer);
    CHECK(revocation_mid.ok());
    auto revocation_leaf = delegator.delegate(
        child_request(*revocation_mid.child, "revocation-leaf",
                      "project:spiraletech/GOLF-GUFF/src/compiler",
                      {"code:build"}, 1'700U, 3'000U, 1U, 2U), signer);
    CHECK(revocation_leaf.ok());
    CHECK(ledger.revoke_receipt(revocation_mid.child->receipt_id, now).ok());
    auto cascaded = gate.authorize(
        revocation_leaf.child, guff::AuthorityPurpose::CapabilityGrant,
        revocation_leaf.child->envelope.subject_id,
        revocation_leaf.child->envelope.scope_sha256);
    CHECK(cascaded.ledger_status == guff::AuthorityLedgerStatus::ReceiptRevoked);

    const auto before_restart = ledger.inspect();
    CHECK(before_restart.healthy);
    CHECK(before_restart.delegated_receipts >= 4U);
    guff::AuthorityLedger reopened(journal, signer, [&]() { return now; });
    CHECK(reopened.inspect().healthy);
    CHECK(reopened.inspect().records == before_restart.records);
    CHECK(reopened.inspect().delegated_receipts == before_restart.delegated_receipts);
    CHECK(reopened.delegation_parent(child.child->receipt_id) == parent->receipt_id);
    CHECK(reopened.delegated_uses(parent->receipt_id) == 2U);

    std::filesystem::remove_all(root, ec);
    return 0;
}
