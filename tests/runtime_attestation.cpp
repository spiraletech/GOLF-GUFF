#include "guff/runtime_attestation.hpp"
#include "guff/sha256.hpp"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

#define CHECK(expression) do { if (!(expression)) { std::cerr << "CHECK failed: " #expression << " @ " << __FILE__ << ':' << __LINE__ << '\n'; return 1; } } while (false)

namespace {

std::uint64_t wall_now_ms() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

class RootSigner final : public guff::AuthoritySigner, public guff::AuthorityVerifier {
public:
    std::string signer_id() const override { return "local:l21-root"; }
    std::string algorithm() const override { return "TEST-SHA256"; }
    std::optional<std::string> sign(std::string_view canonical) const override {
        return guff::sha256(std::string("l21-root-secret\n") + std::string(canonical));
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

class FixedProvider final : public guff::RuntimeAttestationProvider {
public:
    explicit FixedProvider(guff::RuntimeAttestationEvidence evidence)
        : evidence_(std::move(evidence)) {}

    std::string provider_id() const override { return evidence_.provider_id; }
    guff::RuntimeAttestationTrust trust() const noexcept override { return evidence_.trust; }
    guff::RuntimeAttestationResult attest(
        const guff::RuntimeAttestationRequest&) const override {
        return {guff::RuntimeAttestationStatus::Attested, evidence_, {}};
    }

private:
    guff::RuntimeAttestationEvidence evidence_;
};

void refresh_identity(guff::RuntimeAttestationEvidence& evidence) {
    evidence.canonical_sha256 = guff::sha256(guff::canonical_runtime_attestation(evidence));
    evidence.attestation_id = guff::runtime_attestation_id(evidence);
}

std::optional<guff::AuthorityReceipt> root_receipt(
    const RootSigner& signer,
    std::uint64_t now) {
    guff::AuthorityEnvelope envelope;
    envelope.schema_version = 3U;
    envelope.purpose = guff::AuthorityPurpose::CapabilityGrant;
    envelope.subject_id = "project:spiraletech/GOLF-GUFF";
    envelope.actor_reference = "human:l21-root";
    envelope.signer_id = signer.signer_id();
    envelope.signer_key_id = "key-root";
    envelope.issued_at_utc = "2026-09-05T19:00:00Z";
    envelope.issued_at_unix_ms = now - 60'000ULL;
    envelope.expires_at_unix_ms = now + 600'000ULL;
    envelope.max_uses = 16U;
    envelope.nonce = "root-l21";
    envelope.scope_path = "project:spiraletech/GOLF-GUFF";
    envelope.scope_sha256 = guff::sha256(envelope.scope_path);
    envelope.delegation_depth = 0U;
    envelope.max_delegation_depth = 3U;
    envelope.capabilities = {"code:build", "code:test", "repo:read"};
    return guff::issue_authority_receipt(envelope, signer);
}

guff::SessionKeyHandoffRequest handoff_request(
    const guff::AuthorityReceipt& parent,
    std::uint64_t now) {
    guff::SessionKeyHandoffRequest request;
    request.parent = parent;
    request.actor_reference = "slot:xenon:l21";
    request.issued_at_utc = "2026-09-05T19:01:00Z";
    request.voucher_nonce = "voucher-l21";
    request.certificate_nonce = "certificate-l21";
    request.receipt_nonce = "receipt-l21";
    request.scope_path = "project:spiraletech/GOLF-GUFF/src/xenon";
    request.capabilities = {"code:build"};
    request.issued_at_unix_ms = now - 30'000ULL;
    request.expires_at_unix_ms = now + 300'000ULL;
    request.max_uses = 4U;
    request.max_delegation_depth = 2U;
    return request;
}

std::optional<std::string> current_executable_sha256() {
#if defined(_WIN32)
    std::vector<wchar_t> buffer(512U);
    for (unsigned attempt = 0U; attempt < 8U; ++attempt) {
        const DWORD length = GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0U) return std::nullopt;
        if (length < buffer.size() - 1U) {
            return guff::sha256_file(
                std::filesystem::path(std::wstring(buffer.data(), length)));
        }
        buffer.resize(buffer.size() * 2U);
    }
    return std::nullopt;
#elif defined(__linux__)
    return guff::sha256_file("/proc/self/exe");
#else
    return std::nullopt;
#endif
}

std::uint64_t current_process_id() {
#if defined(_WIN32)
    return static_cast<std::uint64_t>(GetCurrentProcessId());
#elif defined(__linux__)
    return static_cast<std::uint64_t>(getpid());
#else
    return 0U;
#endif
}

} // namespace

int main() {
#if !defined(_WIN32) && !defined(__linux__)
    return 0;
#else
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-l21-runtime-attestation");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);

    std::uint64_t now = wall_now_ms();
    guff::NativeRuntimeAttestationProvider native_provider([&]() { return now; });

    guff::RuntimeAttestationRequest attestation_request;
    attestation_request.slot_id = "xenon.audio";
    attestation_request.session_id = "guff:session:sha256:" + guff::sha256("l21-session");
    attestation_request.layer = guff::RealityLayer::Runtime;
    attestation_request.challenge_nonce = "challenge-l21-a";
    attestation_request.max_age_ms = 3'000U;

    auto native = native_provider.attest(attestation_request);
    CHECK(native.ok());
    CHECK(native.evidence);
    CHECK(native.evidence->provider_id == native_provider.provider_id());
    CHECK(guff::validate_runtime_attestation_identity(*native.evidence));
    CHECK(native.evidence->process_id == current_process_id());
    CHECK(native.evidence->process_started_unix_ms > 0U);
    CHECK(native.evidence->binding.slot_id == attestation_request.slot_id);
    CHECK(native.evidence->binding.session_id == attestation_request.session_id);
    CHECK(native.evidence->binding.layer == guff::RealityLayer::Runtime);
    CHECK(native.evidence->binding.device_id.starts_with("guff:hardware:sha256:"));
    CHECK(guff::is_sha256(native.evidence->binding.process_instance_sha256));
    auto executable_digest = current_executable_sha256();
    CHECK(executable_digest);
    CHECK(native.evidence->binding.executable_sha256 == *executable_digest);

    // The process binding remains stable while challenge-bound attestation identity changes.
    auto second_request = attestation_request;
    second_request.challenge_nonce = "challenge-l21-b";
    auto second = native_provider.attest(second_request);
    CHECK(second.ok());
    CHECK(guff::runtime_binding_sha256(second.evidence->binding) ==
          guff::runtime_binding_sha256(native.evidence->binding));
    CHECK(second.evidence->attestation_id != native.evidence->attestation_id);

    RootSigner root_signer;
    ChildSigner xenon_key("slot:xenon-session", "ephemeral-l21", "xenon-l21-secret");
    ChildVerifier child_verifier;
    child_verifier.add(xenon_key);

    guff::AuthorityLedger authority_ledger(
        root / "authority.journal", root_signer, [&]() { return now; });
    CHECK(authority_ledger.trust_key({
        .signer_id = root_signer.signer_id(),
        .key_id = "key-root",
        .algorithm = root_signer.algorithm(),
        .valid_from_unix_ms = now - 120'000ULL,
    }).ok());
    guff::AuthorityGate backing_gate(authority_ledger);
    guff::AuthorityDelegator delegator(authority_ledger, root_signer);
    guff::SessionKeyLedger session_ledger(root / "session-key.journal");
    guff::AuthoritySessionKeyHandoff handoff(
        delegator, session_ledger, root_signer, child_verifier);
    guff::SessionKeyAuthorityGate session_gate(
        session_ledger, root_signer, child_verifier, backing_gate);

    auto parent = root_receipt(root_signer, now);
    CHECK(parent);
    auto issued = handoff.issue(handoff_request(*parent, now), root_signer, xenon_key);
    CHECK(issued.ok());

    guff::AttestedRuntimeLeaseIssueRequest issue_request;
    issue_request.capability = "code:build";
    issue_request.expires_at_unix_ms = now + 120'000ULL;
    issue_request.max_uses = 2U;
    issue_request.nonce = "attested-lease-l21";
    std::vector<std::string> issue_errors;
    auto lease = guff::AttestedRuntimeLeaseIssuer::issue(
        *issued.bundle, *native.evidence, issue_request, xenon_key, &issue_errors);
    CHECK(lease);
    CHECK(issue_errors.empty());
    CHECK(guff::runtime_binding_sha256(lease->binding) ==
          guff::runtime_binding_sha256(native.evidence->binding));

    guff::RuntimeLeaseLedger lease_ledger(root / "runtime-lease.journal", [&]() { return now; });
    CHECK(lease_ledger.register_lease(*lease, *issued.bundle, child_verifier).ok());
    guff::RuntimeLeaseAuthorityGate runtime_gate(lease_ledger, child_verifier, session_gate);
    guff::AttestedRuntimeLeaseAuthorityGate attested_gate(
        native_provider,
        runtime_gate,
        {.max_age_ms = 3'000U,
         .max_future_skew_ms = 500U,
         .allow_degraded_device_identity = true},
        [&]() { return now; });

    const auto voucher_id = issued.bundle->voucher.receipt_id;
    const auto child_id = issued.bundle->receipt.receipt_id;

    auto allowed = attested_gate.authorize(*lease, *issued.bundle, attestation_request);
    CHECK(allowed.ok());
    CHECK(!allowed.attestation_id.empty());
    CHECK(lease_ledger.use_count(lease->lease_id) == 1U);
    CHECK(session_ledger.use_count(child_id) == 1U);
    CHECK(authority_ledger.use_count(voucher_id) == 1U);

    // Wrong-runtime evidence is rejected by L20 after attestation, without spending another use.
    auto other_runtime = *native.evidence;
    other_runtime.provider_id = "guff.test-attestor.other-runtime.v1";
    other_runtime.binding.device_id = "guff:hardware:sha256:" + guff::sha256("other-device");
    other_runtime.challenge_nonce = "challenge-other-runtime";
    refresh_identity(other_runtime);
    FixedProvider other_provider(other_runtime);
    guff::AttestedRuntimeLeaseAuthorityGate other_gate(
        other_provider,
        runtime_gate,
        {.max_age_ms = 3'000U,
         .max_future_skew_ms = 500U,
         .allow_degraded_device_identity = true},
        [&]() { return now; });
    auto other_request = attestation_request;
    other_request.challenge_nonce = other_runtime.challenge_nonce;
    auto wrong_runtime = other_gate.authorize(*lease, *issued.bundle, other_request);
    CHECK(wrong_runtime.status == guff::AttestedRuntimeLeaseStatus::LeaseRejected);
    CHECK(wrong_runtime.lease.status == guff::RuntimeLeaseStatus::DeviceMismatch);
    CHECK(lease_ledger.use_count(lease->lease_id) == 1U);
    CHECK(session_ledger.use_count(child_id) == 1U);
    CHECK(authority_ledger.use_count(voucher_id) == 1U);

    // Stale but internally consistent evidence dies before reaching the L20/L19 consume path.
    auto stale = *native.evidence;
    stale.provider_id = "guff.test-attestor.stale.v1";
    stale.challenge_nonce = "challenge-stale";
    stale.observed_at_unix_ms = now - 10'000ULL;
    stale.valid_until_unix_ms = stale.observed_at_unix_ms + 1'000ULL;
    refresh_identity(stale);
    FixedProvider stale_provider(stale);
    guff::AttestedRuntimeLeaseAuthorityGate stale_gate(
        stale_provider,
        runtime_gate,
        {.max_age_ms = 3'000U,
         .max_future_skew_ms = 500U,
         .allow_degraded_device_identity = true},
        [&]() { return now; });
    auto stale_request = attestation_request;
    stale_request.challenge_nonce = stale.challenge_nonce;
    auto stale_result = stale_gate.authorize(*lease, *issued.bundle, stale_request);
    CHECK(stale_result.status == guff::AttestedRuntimeLeaseStatus::AttestationRejected);
    CHECK(stale_result.attestation_status == guff::RuntimeAttestationStatus::Stale);
    CHECK(lease_ledger.use_count(lease->lease_id) == 1U);
    CHECK(session_ledger.use_count(child_id) == 1U);

    // Challenge mismatch is detected even when the evidence digest itself is valid.
    auto challenge = *native.evidence;
    challenge.provider_id = "guff.test-attestor.challenge.v1";
    challenge.challenge_nonce = "signed-other-challenge";
    refresh_identity(challenge);
    FixedProvider challenge_provider(challenge);
    guff::AttestedRuntimeLeaseAuthorityGate challenge_gate(
        challenge_provider,
        runtime_gate,
        {.max_age_ms = 3'000U,
         .max_future_skew_ms = 500U,
         .allow_degraded_device_identity = true},
        [&]() { return now; });
    auto challenge_request = attestation_request;
    challenge_request.challenge_nonce = "requested-challenge";
    auto challenge_result = challenge_gate.authorize(
        *lease, *issued.bundle, challenge_request);
    CHECK(challenge_result.status == guff::AttestedRuntimeLeaseStatus::AttestationRejected);
    CHECK(challenge_result.attestation_status == guff::RuntimeAttestationStatus::ChallengeMismatch);
    CHECK(lease_ledger.use_count(lease->lease_id) == 1U);

    // Canonical tampering is rejected before runtime authority is consumed.
    auto tampered = *native.evidence;
    tampered.provider_id = "guff.test-attestor.tampered.v1";
    tampered.challenge_nonce = "challenge-tampered";
    refresh_identity(tampered);
    tampered.binding.executable_sha256 = guff::sha256("tampered-after-digest");
    FixedProvider tampered_provider(tampered);
    guff::AttestedRuntimeLeaseAuthorityGate tampered_gate(
        tampered_provider,
        runtime_gate,
        {.max_age_ms = 3'000U,
         .max_future_skew_ms = 500U,
         .allow_degraded_device_identity = true},
        [&]() { return now; });
    auto tampered_request = attestation_request;
    tampered_request.challenge_nonce = tampered.challenge_nonce;
    auto tampered_result = tampered_gate.authorize(
        *lease, *issued.bundle, tampered_request);
    CHECK(tampered_result.status == guff::AttestedRuntimeLeaseStatus::AttestationRejected);
    CHECK(tampered_result.attestation_status == guff::RuntimeAttestationStatus::EvidenceInvalid);
    CHECK(lease_ledger.use_count(lease->lease_id) == 1U);

    // Default policy refuses degraded machine identity before L20 is touched.
    auto degraded = *native.evidence;
    degraded.provider_id = "guff.test-attestor.degraded.v1";
    degraded.trust = guff::RuntimeAttestationTrust::NativeOsLocalDegraded;
    degraded.challenge_nonce = "challenge-degraded";
    refresh_identity(degraded);
    FixedProvider degraded_provider(degraded);
    guff::AttestedRuntimeLeaseAuthorityGate strict_gate(
        degraded_provider,
        runtime_gate,
        {},
        [&]() { return now; });
    auto degraded_request = attestation_request;
    degraded_request.challenge_nonce = degraded.challenge_nonce;
    auto degraded_result = strict_gate.authorize(
        *lease, *issued.bundle, degraded_request);
    CHECK(degraded_result.status == guff::AttestedRuntimeLeaseStatus::AttestationRejected);
    CHECK(degraded_result.attestation_status == guff::RuntimeAttestationStatus::DeviceMeasurementFailed);
    CHECK(lease_ledger.use_count(lease->lease_id) == 1U);

    // A fresh second native attestation spends exactly the final lease/session/voucher use.
    now += 10U;
    auto final_request = attestation_request;
    final_request.challenge_nonce = "challenge-l21-final";
    auto final_allowed = attested_gate.authorize(*lease, *issued.bundle, final_request);
    CHECK(final_allowed.ok());
    CHECK(lease_ledger.use_count(lease->lease_id) == 2U);
    CHECK(session_ledger.use_count(child_id) == 2U);
    CHECK(authority_ledger.use_count(voucher_id) == 2U);

    std::filesystem::remove_all(root, ec);
    return 0;
#endif
}
