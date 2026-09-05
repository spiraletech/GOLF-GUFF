#include "guff/runtime_lease.hpp"
#include "guff/sha256.hpp"

#include <filesystem>
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
    std::string signer_id() const override { return "local:l20-root"; }
    std::string algorithm() const override { return "TEST-SHA256"; }
    std::optional<std::string> sign(std::string_view canonical) const override {
        return guff::sha256(std::string("l20-root-secret\n") + std::string(canonical));
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

std::optional<guff::AuthorityReceipt> root_receipt(const RootSigner& signer) {
    guff::AuthorityEnvelope envelope;
    envelope.schema_version = 3U;
    envelope.purpose = guff::AuthorityPurpose::CapabilityGrant;
    envelope.subject_id = "project:spiraletech/GOLF-GUFF";
    envelope.actor_reference = "human:l20-root";
    envelope.signer_id = signer.signer_id();
    envelope.signer_key_id = "key-root";
    envelope.issued_at_utc = "2026-09-05T06:00:00Z";
    envelope.issued_at_unix_ms = 1'700'000'000'000ULL;
    envelope.expires_at_unix_ms = 8'000'000'000'000ULL;
    envelope.max_uses = 20U;
    envelope.nonce = "root-l20";
    envelope.scope_path = "project:spiraletech/GOLF-GUFF";
    envelope.scope_sha256 = guff::sha256(envelope.scope_path);
    envelope.delegation_depth = 0U;
    envelope.max_delegation_depth = 3U;
    envelope.capabilities = {"code:build", "code:test", "repo:read"};
    return guff::issue_authority_receipt(envelope, signer);
}

guff::SessionKeyHandoffRequest handoff_request(const guff::AuthorityReceipt& parent) {
    guff::SessionKeyHandoffRequest request;
    request.parent = parent;
    request.actor_reference = "slot:xenon:l20";
    request.issued_at_utc = "2026-09-05T06:01:00Z";
    request.voucher_nonce = "voucher-l20";
    request.certificate_nonce = "certificate-l20";
    request.receipt_nonce = "receipt-l20";
    request.scope_path = "project:spiraletech/GOLF-GUFF/src/xenon";
    request.capabilities = {"code:build"};
    request.issued_at_unix_ms = 1'700'000'100'000ULL;
    request.expires_at_unix_ms = 7'000'000'000'000ULL;
    request.max_uses = 4U;
    request.max_delegation_depth = 2U;
    return request;
}

guff::RuntimeBinding binding_for(std::string_view suffix = "a") {
    guff::RuntimeBinding binding;
    binding.device_id = "guff:hardware:sha256:" + guff::sha256(std::string("device-") + std::string(suffix));
    binding.executable_sha256 = guff::sha256(std::string("xenon.exe-") + std::string(suffix));
    binding.process_instance_sha256 = guff::runtime_process_instance_sha256(
        binding.device_id,
        binding.executable_sha256,
        4242U,
        1'800'000'000'000ULL,
        std::string("boot-nonce-") + std::string(suffix));
    binding.slot_id = "xenon.audio";
    binding.session_id = "guff:session:sha256:" + guff::sha256(std::string("transaction-") + std::string(suffix));
    binding.layer = guff::RealityLayer::Runtime;
    return binding;
}

} // namespace

int main() {
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-l20-runtime-lease");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);

    RootSigner root_signer;
    ChildSigner xenon_key("slot:xenon-session", "ephemeral-l20", "xenon-l20-secret");
    ChildVerifier child_verifier;
    child_verifier.add(xenon_key);

    std::uint64_t now = 1'800'000'000'000ULL;
    guff::AuthorityLedger authority_ledger(
        root / "authority.journal", root_signer, [&]() { return now; });
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

    auto parent = root_receipt(root_signer);
    CHECK(parent);
    auto issued = handoff.issue(handoff_request(*parent), root_signer, xenon_key);
    CHECK(issued.ok());

    guff::RuntimeLeaseLedger lease_ledger(root / "runtime-lease.journal", [&]() { return now; });
    guff::RuntimeLeaseAuthorityGate runtime_gate(lease_ledger, child_verifier, session_gate);

    guff::RuntimeLeaseIssueRequest lease_request;
    lease_request.binding = binding_for("a");
    lease_request.capability = "code:build";
    lease_request.issued_at_unix_ms = now;
    lease_request.expires_at_unix_ms = now + 60'000ULL;
    lease_request.max_uses = 2U;
    lease_request.nonce = "runtime-lease-a";

    std::vector<std::string> issue_errors;
    auto lease = guff::RuntimeLeaseIssuer::issue(
        *issued.bundle, lease_request, xenon_key, &issue_errors);
    CHECK(lease);
    CHECK(issue_errors.empty());
    CHECK(lease->session_key_receipt_id == issued.bundle->receipt.receipt_id);
    CHECK(lease->binding.session_id == lease_request.binding.session_id);
    CHECK(lease_ledger.register_lease(*lease, *issued.bundle, child_verifier).ok());
    CHECK(lease_ledger.lease_registered(lease->lease_id));

    const auto voucher_id = issued.bundle->voucher.receipt_id;
    const auto child_receipt_id = issued.bundle->receipt.receipt_id;

    // Stolen packets on the wrong device/process/executable/session/slot/layer fail before any authority burns.
    auto wrong_device = lease_request.binding;
    wrong_device.device_id = "guff:hardware:sha256:" + guff::sha256("device-stolen");
    CHECK(runtime_gate.authorize(*lease, *issued.bundle, wrong_device).status ==
          guff::RuntimeLeaseStatus::DeviceMismatch);

    auto wrong_executable = lease_request.binding;
    wrong_executable.executable_sha256 = guff::sha256("different-executable");
    CHECK(runtime_gate.authorize(*lease, *issued.bundle, wrong_executable).status ==
          guff::RuntimeLeaseStatus::ExecutableMismatch);

    auto wrong_process = lease_request.binding;
    wrong_process.process_instance_sha256 = guff::sha256("different-process-instance");
    CHECK(runtime_gate.authorize(*lease, *issued.bundle, wrong_process).status ==
          guff::RuntimeLeaseStatus::ProcessMismatch);

    auto wrong_slot = lease_request.binding;
    wrong_slot.slot_id = "hakui.world";
    CHECK(runtime_gate.authorize(*lease, *issued.bundle, wrong_slot).status ==
          guff::RuntimeLeaseStatus::SlotMismatch);

    auto wrong_session = lease_request.binding;
    wrong_session.session_id = "guff:session:sha256:" + guff::sha256("other-session");
    CHECK(runtime_gate.authorize(*lease, *issued.bundle, wrong_session).status ==
          guff::RuntimeLeaseStatus::SessionMismatch);

    auto wrong_layer = lease_request.binding;
    wrong_layer.layer = guff::RealityLayer::Project;
    CHECK(runtime_gate.authorize(*lease, *issued.bundle, wrong_layer).status ==
          guff::RuntimeLeaseStatus::LayerMismatch);

    CHECK(lease_ledger.use_count(lease->lease_id) == 0U);
    CHECK(session_ledger.use_count(child_receipt_id) == 0U);
    CHECK(authority_ledger.use_count(voucher_id) == 0U);

    auto allowed_one = runtime_gate.authorize(*lease, *issued.bundle, lease_request.binding);
    CHECK(allowed_one.ok());
    CHECK(allowed_one.use_count == 1U);
    CHECK(session_ledger.use_count(child_receipt_id) == 1U);
    CHECK(authority_ledger.use_count(voucher_id) == 1U);

    auto allowed_two = runtime_gate.authorize(*lease, *issued.bundle, lease_request.binding);
    CHECK(allowed_two.ok());
    CHECK(allowed_two.use_count == 2U);
    CHECK(session_ledger.use_count(child_receipt_id) == 2U);
    CHECK(authority_ledger.use_count(voucher_id) == 2U);

    // Lease exhaustion is checked before spending the remaining L19 authority.
    auto lease_exhausted = runtime_gate.authorize(*lease, *issued.bundle, lease_request.binding);
    CHECK(lease_exhausted.status == guff::RuntimeLeaseStatus::UseLimitReached);
    CHECK(session_ledger.use_count(child_receipt_id) == 2U);
    CHECK(authority_ledger.use_count(voucher_id) == 2U);

    // A second, one-use lease can be independently revoked without revoking the session key.
    guff::RuntimeLeaseIssueRequest revoked_request = lease_request;
    revoked_request.binding = binding_for("b");
    revoked_request.max_uses = 1U;
    revoked_request.nonce = "runtime-lease-b";
    auto revoked_lease = guff::RuntimeLeaseIssuer::issue(
        *issued.bundle, revoked_request, xenon_key);
    CHECK(revoked_lease);
    CHECK(lease_ledger.register_lease(*revoked_lease, *issued.bundle, child_verifier).ok());
    CHECK(lease_ledger.revoke_lease(revoked_lease->lease_id, now).ok());
    CHECK(runtime_gate.authorize(*revoked_lease, *issued.bundle, revoked_request.binding).status ==
          guff::RuntimeLeaseStatus::LeaseRevoked);
    CHECK(session_ledger.use_count(child_receipt_id) == 2U);

    // Cold replay retains coordinates, use counters, and revocation state.
    const auto before_restart = lease_ledger.inspect();
    CHECK(before_restart.healthy);
    guff::RuntimeLeaseLedger reopened(root / "runtime-lease.journal", [&]() { return now; });
    CHECK(reopened.inspect().healthy);
    CHECK(reopened.inspect().records == before_restart.records);
    CHECK(reopened.inspect().registered_leases == 2U);
    CHECK(reopened.use_count(lease->lease_id) == 2U);
    CHECK(reopened.lease_revoked(revoked_lease->lease_id));

    guff::RuntimeLeaseAuthorityGate reopened_gate(reopened, child_verifier, session_gate);
    CHECK(reopened_gate.authorize(*lease, *issued.bundle, lease_request.binding).status ==
          guff::RuntimeLeaseStatus::UseLimitReached);

    // A copied lease still cannot cross from another device after restart.
    auto stolen_after_restart = lease_request.binding;
    stolen_after_restart.device_id = "guff:hardware:sha256:" + guff::sha256("device-c");
    CHECK(reopened_gate.authorize(*lease, *issued.bundle, stolen_after_restart).status ==
          guff::RuntimeLeaseStatus::DeviceMismatch);

    // A separately issued lease expires independently of the longer-lived session key.
    guff::RuntimeLeaseIssueRequest expiring_request = lease_request;
    expiring_request.binding = binding_for("c");
    expiring_request.max_uses = 1U;
    expiring_request.nonce = "runtime-lease-c";
    expiring_request.expires_at_unix_ms = now + 1U;
    auto expiring = guff::RuntimeLeaseIssuer::issue(
        *issued.bundle, expiring_request, xenon_key);
    CHECK(expiring);
    CHECK(reopened.register_lease(*expiring, *issued.bundle, child_verifier).ok());
    now += 2U;
    CHECK(reopened_gate.authorize(*expiring, *issued.bundle, expiring_request.binding).status ==
          guff::RuntimeLeaseStatus::LeaseExpired);
    CHECK(session_ledger.use_count(child_receipt_id) == 2U);

    // Tampering with signed runtime coordinates invalidates the lease identity.
    auto tampered = *lease;
    tampered.binding.slot_id = "xenon.tampered";
    const auto tampered_result = reopened.preflight(
        tampered, *issued.bundle, child_verifier, tampered.binding);
    CHECK(tampered_result.status == guff::RuntimeLeaseStatus::SignatureRejected ||
          tampered_result.status == guff::RuntimeLeaseStatus::NotRegistered);

    std::filesystem::remove_all(root, ec);
    return 0;
}
