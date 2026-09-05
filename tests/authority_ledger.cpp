#include "guff/authority_ledger.hpp"
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
    std::string signer_id() const override { return "local:l17-ledger-signer"; }
    std::string algorithm() const override { return "TEST-SHA256"; }
    std::optional<std::string> sign(std::string_view canonical) const override {
        return guff::sha256(std::string("l17-ledger-secret\n") + std::string(canonical));
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

std::optional<guff::AuthorityReceipt> receipt_for(
    const TestSigner& signer,
    std::string key_id,
    std::string subject,
    std::string scope,
    std::string nonce,
    std::uint64_t issued_at,
    std::uint64_t expires_at,
    std::uint32_t max_uses = 1U) {
    guff::AuthorityEnvelope envelope;
    envelope.schema_version = 2U;
    envelope.purpose = guff::AuthorityPurpose::CapabilityGrant;
    envelope.subject_id = std::move(subject);
    envelope.actor_reference = "human:l17-regression";
    envelope.signer_id = signer.signer_id();
    envelope.signer_key_id = std::move(key_id);
    envelope.issued_at_utc = "2026-09-05T03:00:00Z";
    envelope.issued_at_unix_ms = issued_at;
    envelope.expires_at_unix_ms = expires_at;
    envelope.max_uses = max_uses;
    envelope.nonce = std::move(nonce);
    envelope.scope_sha256 = std::move(scope);
    return guff::issue_authority_receipt(envelope, signer);
}

} // namespace

int main() {
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-l17-authority-ledger");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);
    const auto journal_path = root / "authority.journal";

    TestSigner signer;
    std::uint64_t now = 2'000U;
    guff::AuthorityLedger ledger(journal_path, signer, [&]() { return now; });
    CHECK(ledger.inspect().healthy);

    CHECK(ledger.trust_key({
        .signer_id = signer.signer_id(),
        .key_id = "key-old",
        .algorithm = signer.algorithm(),
        .valid_from_unix_ms = 1'000U,
    }).ok());

    const auto scope_one = guff::sha256("one-shot-scope");
    auto one_shot = receipt_for(
        signer, "key-old", "subject:one", scope_one, "nonce-one", 1'500U, 4'000U, 1U);
    CHECK(one_shot.has_value());
    auto first = ledger.authorize_and_consume(
        *one_shot, guff::AuthorityPurpose::CapabilityGrant, "subject:one", scope_one);
    CHECK(first.ok());
    CHECK(first.use_count == 1U);
    auto replay = ledger.authorize_and_consume(
        *one_shot, guff::AuthorityPurpose::CapabilityGrant, "subject:one", scope_one);
    CHECK(replay.status == guff::AuthorityLedgerStatus::UseLimitReached);

    const auto scope_two = guff::sha256("bounded-scope");
    auto bounded = receipt_for(
        signer, "key-old", "subject:two", scope_two, "nonce-two", 1'600U, 4'000U, 2U);
    CHECK(bounded.has_value());
    CHECK(ledger.authorize_and_consume(
        *bounded, guff::AuthorityPurpose::CapabilityGrant, "subject:two", scope_two).ok());
    CHECK(ledger.authorize_and_consume(
        *bounded, guff::AuthorityPurpose::CapabilityGrant, "subject:two", scope_two).ok());
    CHECK(ledger.authorize_and_consume(
        *bounded, guff::AuthorityPurpose::CapabilityGrant, "subject:two", scope_two).status ==
          guff::AuthorityLedgerStatus::UseLimitReached);

    const auto collision_scope_a = guff::sha256("collision-a");
    const auto collision_scope_b = guff::sha256("collision-b");
    auto collision_a = receipt_for(
        signer, "key-old", "subject:collision", collision_scope_a,
        "nonce-collision", 1'700U, 4'000U, 2U);
    auto collision_b = receipt_for(
        signer, "key-old", "subject:collision", collision_scope_b,
        "nonce-collision", 1'701U, 4'000U, 2U);
    CHECK(collision_a && collision_b);
    CHECK(ledger.authorize_and_consume(
        *collision_a, guff::AuthorityPurpose::CapabilityGrant,
        "subject:collision", collision_scope_a).ok());
    CHECK(ledger.authorize_and_consume(
        *collision_b, guff::AuthorityPurpose::CapabilityGrant,
        "subject:collision", collision_scope_b).status == guff::AuthorityLedgerStatus::NonceReplay);

    const auto revoked_scope = guff::sha256("revoked-receipt");
    auto revoked_receipt = receipt_for(
        signer, "key-old", "subject:revoked", revoked_scope,
        "nonce-revoked", 1'800U, 4'000U, 1U);
    CHECK(revoked_receipt);
    CHECK(ledger.revoke_receipt(revoked_receipt->receipt_id, 1'900U).ok());
    CHECK(ledger.authorize_and_consume(
        *revoked_receipt, guff::AuthorityPurpose::CapabilityGrant,
        "subject:revoked", revoked_scope).status == guff::AuthorityLedgerStatus::ReceiptRevoked);

    const auto expired_scope = guff::sha256("expired-receipt");
    auto expired = receipt_for(
        signer, "key-old", "subject:expired", expired_scope,
        "nonce-expired", 1'800U, 2'100U, 1U);
    CHECK(expired);
    now = 2'200U;
    CHECK(ledger.authorize_and_consume(
        *expired, guff::AuthorityPurpose::CapabilityGrant,
        "subject:expired", expired_scope).status == guff::AuthorityLedgerStatus::ReceiptExpired);

    CHECK(ledger.retire_key(signer.signer_id(), "key-old", 2'500U).ok());
    CHECK(ledger.trust_key({
        .signer_id = signer.signer_id(),
        .key_id = "key-new",
        .algorithm = signer.algorithm(),
        .valid_from_unix_ms = 2'500U,
    }).ok());

    now = 2'600U;
    const auto old_good_scope = guff::sha256("old-good");
    auto old_good = receipt_for(
        signer, "key-old", "subject:old-good", old_good_scope,
        "nonce-old-good", 2'400U, 3'500U, 1U);
    CHECK(old_good);
    CHECK(ledger.authorize_and_consume(
        *old_good, guff::AuthorityPurpose::CapabilityGrant,
        "subject:old-good", old_good_scope).ok());

    const auto old_late_scope = guff::sha256("old-late");
    auto old_late = receipt_for(
        signer, "key-old", "subject:old-late", old_late_scope,
        "nonce-old-late", 2'550U, 3'500U, 1U);
    CHECK(old_late);
    CHECK(ledger.authorize_and_consume(
        *old_late, guff::AuthorityPurpose::CapabilityGrant,
        "subject:old-late", old_late_scope).status == guff::AuthorityLedgerStatus::KeyInactive);

    const auto new_scope = guff::sha256("new-key");
    auto new_receipt = receipt_for(
        signer, "key-new", "subject:new", new_scope,
        "nonce-new", 2'550U, 4'000U, 1U);
    CHECK(new_receipt);
    CHECK(ledger.authorize_and_consume(
        *new_receipt, guff::AuthorityPurpose::CapabilityGrant,
        "subject:new", new_scope).ok());

    CHECK(ledger.revoke_key(signer.signer_id(), "key-new", 2'700U).ok());
    now = 2'701U;
    const auto new_revoked_scope = guff::sha256("new-key-revoked");
    auto new_after_revoke = receipt_for(
        signer, "key-new", "subject:new-revoked", new_revoked_scope,
        "nonce-new-revoked", 2'600U, 4'000U, 1U);
    CHECK(new_after_revoke);
    CHECK(ledger.authorize_and_consume(
        *new_after_revoke, guff::AuthorityPurpose::CapabilityGrant,
        "subject:new-revoked", new_revoked_scope).status == guff::AuthorityLedgerStatus::KeyInactive);

    const auto before_restart = ledger.inspect();
    CHECK(before_restart.healthy);
    CHECK(before_restart.trusted_keys == 2U);
    CHECK(before_restart.revoked_receipts == 1U);
    CHECK(ledger.use_count(bounded->receipt_id) == 2U);

    guff::AuthorityLedger reopened(journal_path, signer, [&]() { return now; });
    const auto after_restart = reopened.inspect();
    CHECK(after_restart.healthy);
    CHECK(after_restart.records == before_restart.records);
    CHECK(after_restart.trusted_keys == before_restart.trusted_keys);
    CHECK(reopened.use_count(bounded->receipt_id) == 2U);
    CHECK(reopened.receipt_revoked(revoked_receipt->receipt_id));
    CHECK(reopened.authorize_and_consume(
        *bounded, guff::AuthorityPurpose::CapabilityGrant,
        "subject:two", scope_two).status == guff::AuthorityLedgerStatus::UseLimitReached);

    {
        std::ofstream corrupt(journal_path, std::ios::binary | std::ios::app);
        CHECK(static_cast<bool>(corrupt));
        corrupt << "corrupt-tail\n";
    }
    std::vector<std::string> replay_errors;
    CHECK(!reopened.replay(&replay_errors));
    CHECK(!replay_errors.empty());
    CHECK(!reopened.inspect().healthy);
    CHECK(reopened.trust_key({
        .signer_id = signer.signer_id(),
        .key_id = "key-corrupt",
        .algorithm = signer.algorithm(),
        .valid_from_unix_ms = 3'000U,
    }).status == guff::AuthorityLedgerStatus::Corrupt);

    std::filesystem::remove_all(root, ec);
    return 0;
}
