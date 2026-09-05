#include "guff/session_key.hpp"
#include "guff/sha256.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "CHECK failed: " #expression << " @ " << __FILE__ << ':' << __LINE__ << '\n'; return 1; } } while (false)

namespace {

class RootSigner final : public guff::AuthoritySigner, public guff::AuthorityVerifier {
public:
    std::string signer_id() const override { return "local:l19-root"; }
    std::string algorithm() const override { return "TEST-SHA256"; }
    std::optional<std::string> sign(std::string_view canonical) const override {
        return guff::sha256(std::string("l19-root-secret\n") + std::string(canonical));
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

class ChildSigner final : public guff::SessionKeySigner {
public:
    ChildSigner(std::string signer, std::string key, std::string secret)
        : signer_(std::move(signer)), key_(std::move(key)), secret_(std::move(secret)) {}

    std::string signer_id() const override { return signer_; }
    std::string key_id() const override { return key_; }
    std::string algorithm() const override { return "TEST-SHA256"; }
    std::string key_fingerprint_sha256() const override {
        return guff::sha256("public:" + signer_ + ":" + key_);
    }
    std::optional<std::string> sign(std::string_view canonical) const override {
        return guff::sha256(secret_ + "\n" + std::string(canonical));
    }
    const std::string& secret() const noexcept { return secret_; }

private:
    std::string signer_;
    std::string key_;
    std::string secret_;
};

class ChildVerifier final : public guff::SessionKeyVerifier {
public:
    void add(const ChildSigner& signer) {
        secrets_[id(signer.signer_id(), signer.key_id(), signer.algorithm())] = signer.secret();
    }

    bool knows_key(std::string_view signer,
                   std::string_view key,
                   std::string_view algorithm) const override {
        return secrets_.contains(id(signer, key, algorithm));
    }

    std::optional<std::string> key_fingerprint_sha256(
        std::string_view signer,
        std::string_view key,
        std::string_view algorithm) const override {
        if (!knows_key(signer, key, algorithm)) return std::nullopt;
        return guff::sha256("public:" + std::string(signer) + ":" + std::string(key));
    }

    bool verify_key(std::string_view signer,
                    std::string_view key,
                    std::string_view algorithm,
                    std::string_view canonical,
                    std::string_view signature) const override {
        const auto it = secrets_.find(id(signer, key, algorithm));
        if (it == secrets_.end()) return false;
        return guff::sha256(it->second + "\n" + std::string(canonical)) == signature;
    }

private:
    static std::string id(std::string_view signer,
                          std::string_view key,
                          std::string_view algorithm) {
        return std::string(signer) + "\n" + std::string(key) + "\n" + std::string(algorithm);
    }
    std::unordered_map<std::string, std::string> secrets_;
};

std::optional<guff::AuthorityReceipt> root_receipt(
    const RootSigner& signer,
    std::string nonce,
    std::uint32_t max_uses = 16U) {
    guff::AuthorityEnvelope envelope;
    envelope.schema_version = 3U;
    envelope.purpose = guff::AuthorityPurpose::CapabilityGrant;
    envelope.subject_id = "project:spiraletech/GOLF-GUFF";
    envelope.actor_reference = "human:l19-root";
    envelope.signer_id = signer.signer_id();
    envelope.signer_key_id = "key-root";
    envelope.issued_at_utc = "2026-09-05T05:00:00Z";
    envelope.issued_at_unix_ms = 1'700'000'000'000ULL;
    envelope.expires_at_unix_ms = 8'000'000'000'000ULL;
    envelope.max_uses = max_uses;
    envelope.nonce = std::move(nonce);
    envelope.scope_path = "project:spiraletech/GOLF-GUFF";
    envelope.scope_sha256 = guff::sha256(envelope.scope_path);
    envelope.delegation_depth = 0U;
    envelope.max_delegation_depth = 3U;
    envelope.capabilities = {"code:build", "code:test", "repo:read"};
    return guff::issue_authority_receipt(envelope, signer);
}

guff::SessionKeyHandoffRequest handoff_request(
    const guff::AuthorityReceipt& parent,
    std::string suffix,
    std::string scope,
    std::vector<std::string> capabilities,
    std::uint32_t uses = 2U) {
    guff::SessionKeyHandoffRequest request;
    request.parent = parent;
    request.actor_reference = "slot:xenon:" + suffix;
    request.issued_at_utc = "2026-09-05T05:01:00Z";
    request.voucher_nonce = "voucher-" + suffix;
    request.certificate_nonce = "certificate-" + suffix;
    request.receipt_nonce = "receipt-" + suffix;
    request.scope_path = std::move(scope);
    request.capabilities = std::move(capabilities);
    request.issued_at_unix_ms = 1'700'000'100'000ULL;
    request.expires_at_unix_ms = 8'000'000'000'000ULL - 1'000ULL;
    request.max_uses = uses;
    request.max_delegation_depth = 2U;
    return request;
}

} // namespace

int main() {
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-l19-session-key");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);

    RootSigner root_signer;
    ChildSigner xenon_key("slot:xenon-session", "ephemeral-001", "xenon-ephemeral-secret");
    ChildSigner hakui_key("slot:hakui-session", "ephemeral-002", "hakui-ephemeral-secret");
    ChildSigner spare_key("slot:spare-session", "ephemeral-003", "spare-ephemeral-secret");
    ChildVerifier child_verifier;
    child_verifier.add(xenon_key);
    child_verifier.add(hakui_key);
    child_verifier.add(spare_key);

    std::uint64_t authority_now = 1'800'000'000'000ULL;
    guff::AuthorityLedger authority_ledger(
        root / "authority.journal", root_signer, [&]() { return authority_now; });
    CHECK(authority_ledger.trust_key({
        .signer_id = root_signer.signer_id(),
        .key_id = "key-root",
        .algorithm = root_signer.algorithm(),
        .valid_from_unix_ms = 1'600'000'000'000ULL,
    }).ok());
    guff::AuthorityGate backing_gate(authority_ledger);
    guff::AuthorityDelegator delegator(authority_ledger, root_signer);
    guff::SessionKeyLedger session_ledger(root / "session-key.journal");
    guff::AuthoritySessionKeyHandoff handoff(
        delegator, session_ledger, root_signer, child_verifier);
    guff::SessionKeyAuthorityGate session_gate(
        session_ledger, root_signer, child_verifier, backing_gate);

    auto parent = root_receipt(root_signer, "root-l19");
    CHECK(parent);

    auto issued = handoff.issue(
        handoff_request(*parent,
                        "xenon",
                        "project:spiraletech/GOLF-GUFF/src/xenon",
                        {"code:build"},
                        2U),
        root_signer,
        xenon_key);
    CHECK(issued.ok());
    CHECK(issued.bundle->receipt.signer_id == xenon_key.signer_id());
    CHECK(issued.bundle->receipt.key_id == xenon_key.key_id());
    CHECK(issued.bundle->certificate.child_key_fingerprint_sha256 ==
          xenon_key.key_fingerprint_sha256());
    CHECK(issued.bundle->voucher.envelope.signer_id == root_signer.signer_id());
    CHECK(issued.bundle->voucher.envelope.parent_receipt_id == parent->receipt_id);
    CHECK(session_ledger.bundle_registered(issued.bundle->receipt.receipt_id));
    CHECK(authority_ledger.use_count(parent->receipt_id) == 1U);
    CHECK(authority_ledger.delegated_uses(parent->receipt_id) == 2U);

    const auto scope = issued.bundle->receipt.scope_sha256;
    const auto voucher_id = issued.bundle->voucher.receipt_id;

    // Capability denial happens before either backing voucher or child receipt is consumed.
    const auto wrong_capability = session_gate.authorize(
        *issued.bundle,
        guff::AuthorityPurpose::CapabilityGrant,
        issued.bundle->receipt.subject_id,
        scope,
        "code:test");
    CHECK(wrong_capability.status == guff::SessionKeyStatus::CapabilityMismatch);
    CHECK(session_ledger.use_count(issued.bundle->receipt.receipt_id) == 0U);
    CHECK(authority_ledger.use_count(voucher_id) == 0U);

    auto allowed_one = session_gate.authorize(
        *issued.bundle,
        guff::AuthorityPurpose::CapabilityGrant,
        issued.bundle->receipt.subject_id,
        scope,
        "code:build");
    CHECK(allowed_one.ok());
    CHECK(allowed_one.use_count == 1U);
    CHECK(authority_ledger.use_count(voucher_id) == 1U);

    auto allowed_two = session_gate.authorize(
        *issued.bundle,
        guff::AuthorityPurpose::CapabilityGrant,
        issued.bundle->receipt.subject_id,
        scope,
        "code:build");
    CHECK(allowed_two.ok());
    CHECK(allowed_two.use_count == 2U);
    CHECK(authority_ledger.use_count(voucher_id) == 2U);

    const auto exhausted = session_gate.authorize(
        *issued.bundle,
        guff::AuthorityPurpose::CapabilityGrant,
        issued.bundle->receipt.subject_id,
        scope,
        "code:build");
    CHECK(exhausted.status == guff::SessionKeyStatus::UseLimitReached);
    CHECK(authority_ledger.use_count(voucher_id) == 2U);

    // Tampering with the ephemeral key fingerprint is rejected before voucher consumption.
    auto tampered = *issued.bundle;
    tampered.receipt.key_fingerprint_sha256 = guff::sha256("forged-child-key");
    const auto tampered_result = session_ledger.preflight(
        tampered,
        root_signer,
        child_verifier,
        guff::AuthorityPurpose::CapabilityGrant,
        tampered.receipt.subject_id,
        tampered.receipt.scope_sha256,
        "code:build");
    CHECK(tampered_result.status == guff::SessionKeyStatus::NotRegistered ||
          tampered_result.status == guff::SessionKeyStatus::FingerprintMismatch);

    // A second branch gets its own key, then key-level revocation kills it without touching root trust.
    auto hakui = handoff.issue(
        handoff_request(*parent,
                        "hakui",
                        "project:spiraletech/GOLF-GUFF/src/hakui",
                        {"code:build"},
                        1U),
        root_signer,
        hakui_key);
    CHECK(hakui.ok());
    CHECK(session_ledger.revoke_key(
        hakui_key.signer_id(), hakui_key.key_id(), 1ULL).ok());
    const auto revoked_key = session_gate.authorize(
        *hakui.bundle,
        guff::AuthorityPurpose::CapabilityGrant,
        hakui.bundle->receipt.subject_id,
        hakui.bundle->receipt.scope_sha256,
        "code:build");
    CHECK(revoked_key.status == guff::SessionKeyStatus::KeyRevoked);
    CHECK(authority_ledger.use_count(hakui.bundle->voucher.receipt_id) == 0U);

    // Cold replay retains handoff registrations, use counters, and delegated-key revocation.
    const auto before_restart = session_ledger.inspect();
    CHECK(before_restart.healthy);
    guff::SessionKeyLedger reopened(root / "session-key.journal");
    CHECK(reopened.inspect().healthy);
    CHECK(reopened.inspect().records == before_restart.records);
    CHECK(reopened.inspect().registered_handoffs == before_restart.registered_handoffs);
    CHECK(reopened.use_count(issued.bundle->receipt.receipt_id) == 2U);
    guff::SessionKeyAuthorityGate reopened_gate(
        reopened, root_signer, child_verifier, backing_gate);
    const auto reopened_exhausted = reopened_gate.authorize(
        *issued.bundle,
        guff::AuthorityPurpose::CapabilityGrant,
        issued.bundle->receipt.subject_id,
        scope,
        "code:build");
    CHECK(reopened_exhausted.status == guff::SessionKeyStatus::UseLimitReached);
    const auto reopened_revoked = reopened_gate.authorize(
        *hakui.bundle,
        guff::AuthorityPurpose::CapabilityGrant,
        hakui.bundle->receipt.subject_id,
        hakui.bundle->receipt.scope_sha256,
        "code:build");
    CHECK(reopened_revoked.status == guff::SessionKeyStatus::KeyRevoked);

    // Ancestor receipt revocation propagates through the backing L18 voucher.
    auto ancestor_branch = handoff.issue(
        handoff_request(*parent,
                        "ancestor",
                        "project:spiraletech/GOLF-GUFF/src/session",
                        {"code:build"},
                        1U),
        root_signer,
        spare_key);
    CHECK(ancestor_branch.ok());
    CHECK(authority_ledger.revoke_receipt(parent->receipt_id, authority_now).ok());
    const auto ancestor_revoked = session_gate.authorize(
        *ancestor_branch.bundle,
        guff::AuthorityPurpose::CapabilityGrant,
        ancestor_branch.bundle->receipt.subject_id,
        ancestor_branch.bundle->receipt.scope_sha256,
        "code:build");
    CHECK(ancestor_revoked.status == guff::SessionKeyStatus::VoucherRejected);
    CHECK(ancestor_revoked.backing_ledger_status == guff::AuthorityLedgerStatus::ReceiptRevoked);
    CHECK(session_ledger.use_count(ancestor_branch.bundle->receipt.receipt_id) == 0U);

    // An unregistered but correctly signed child bundle cannot cross the session-key boundary.
    auto orphan = *ancestor_branch.bundle;
    orphan.receipt.receipt_id = "guff:session-key:sha256:" + guff::sha256("orphan");
    const auto orphan_result = session_ledger.preflight(
        orphan,
        root_signer,
        child_verifier,
        guff::AuthorityPurpose::CapabilityGrant,
        orphan.receipt.subject_id,
        orphan.receipt.scope_sha256,
        "code:build");
    CHECK(orphan_result.status == guff::SessionKeyStatus::NotRegistered);

    std::filesystem::remove_all(root, ec);
    return 0;
}
