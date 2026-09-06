#pragma once

#include "guff/runtime_lease.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class RuntimeAttestationTrust : std::uint8_t {
    NativeOsLocal,
    NativeOsLocalDegraded
};

enum class RuntimeAttestationStatus : std::uint8_t {
    Attested,
    InvalidRequest,
    UnsupportedPlatform,
    DeviceMeasurementFailed,
    ExecutableMeasurementFailed,
    ProcessMeasurementFailed,
    EvidenceInvalid,
    ProviderMismatch,
    ChallengeMismatch,
    ContextMismatch,
    Stale
};

struct RuntimeAttestationRequest {
    std::string slot_id;
    std::string session_id;
    RealityLayer layer{RealityLayer::Runtime};
    std::string challenge_nonce;
    std::uint64_t max_age_ms{5'000U};
};

struct RuntimeAttestationEvidence {
    std::uint32_t schema_version{1U};
    std::string provider_id;
    RuntimeAttestationTrust trust{RuntimeAttestationTrust::NativeOsLocal};
    RuntimeBinding binding;
    std::uint64_t process_id{0U};
    std::uint64_t process_started_unix_ms{0U};
    std::uint64_t observed_at_unix_ms{0U};
    std::uint64_t valid_until_unix_ms{0U};
    std::string challenge_nonce;
    std::string executable_locator_sha256;
    std::string canonical_sha256;
    std::string attestation_id;
};

struct RuntimeAttestationResult {
    RuntimeAttestationStatus status{RuntimeAttestationStatus::InvalidRequest};
    std::optional<RuntimeAttestationEvidence> evidence;
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

class RuntimeAttestationProvider {
public:
    virtual ~RuntimeAttestationProvider() = default;
    [[nodiscard]] virtual std::string provider_id() const = 0;
    [[nodiscard]] virtual RuntimeAttestationTrust trust() const noexcept = 0;
    [[nodiscard]] virtual RuntimeAttestationResult attest(
        const RuntimeAttestationRequest& request) const = 0;
};

class NativeRuntimeAttestationProvider final : public RuntimeAttestationProvider {
public:
    using Clock = std::function<std::uint64_t()>;

    explicit NativeRuntimeAttestationProvider(Clock clock = {});

    [[nodiscard]] std::string provider_id() const override;
    [[nodiscard]] RuntimeAttestationTrust trust() const noexcept override;
    [[nodiscard]] RuntimeAttestationResult attest(
        const RuntimeAttestationRequest& request) const override;

private:
    Clock clock_;
};

struct RuntimeAttestationPolicy {
    std::uint64_t max_age_ms{5'000U};
    std::uint64_t max_future_skew_ms{1'000U};
    bool allow_degraded_device_identity{false};
};

enum class AttestedRuntimeLeaseStatus : std::uint8_t {
    Allowed,
    AttestationRejected,
    LeaseRejected
};

struct AttestedRuntimeLeaseResult {
    AttestedRuntimeLeaseStatus status{AttestedRuntimeLeaseStatus::AttestationRejected};
    RuntimeAttestationStatus attestation_status{RuntimeAttestationStatus::InvalidRequest};
    RuntimeLeaseResult lease;
    std::string attestation_id;
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

class AttestedRuntimeLeaseAuthorityGate {
public:
    using Clock = std::function<std::uint64_t()>;

    AttestedRuntimeLeaseAuthorityGate(
        const RuntimeAttestationProvider& provider,
        const RuntimeLeaseAuthorityGate& lease_gate,
        RuntimeAttestationPolicy policy = {},
        Clock clock = {});

    [[nodiscard]] AttestedRuntimeLeaseResult authorize(
        const RuntimeCapabilityLease& lease,
        const SessionKeyBundle& bundle,
        const RuntimeAttestationRequest& request) const;

private:
    const RuntimeAttestationProvider& provider_;
    const RuntimeLeaseAuthorityGate& lease_gate_;
    RuntimeAttestationPolicy policy_;
    Clock clock_;
};

struct AttestedRuntimeLeaseIssueRequest {
    std::string capability;
    std::uint64_t expires_at_unix_ms{0U};
    std::uint32_t max_uses{1U};
    std::string nonce;
};

class AttestedRuntimeLeaseIssuer {
public:
    [[nodiscard]] static std::optional<RuntimeCapabilityLease> issue(
        const SessionKeyBundle& bundle,
        const RuntimeAttestationEvidence& evidence,
        const AttestedRuntimeLeaseIssueRequest& request,
        const SessionKeySigner& signer,
        std::vector<std::string>* errors = nullptr);
};

[[nodiscard]] std::string canonical_runtime_attestation(
    const RuntimeAttestationEvidence& evidence);
[[nodiscard]] std::string runtime_attestation_id(
    const RuntimeAttestationEvidence& evidence);
[[nodiscard]] bool validate_runtime_attestation_identity(
    const RuntimeAttestationEvidence& evidence) noexcept;
[[nodiscard]] std::string_view to_string(RuntimeAttestationTrust trust) noexcept;
[[nodiscard]] std::string_view to_string(RuntimeAttestationStatus status) noexcept;
[[nodiscard]] std::string_view to_string(AttestedRuntimeLeaseStatus status) noexcept;

} // namespace guff
