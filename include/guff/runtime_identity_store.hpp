#pragma once

#include "guff/runtime_attestation.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace guff {

enum class RuntimeIdentityStoreStatus : std::uint8_t {
    Recorded,
    AlreadyRecorded,
    InvalidEvidence,
    DeviceRevoked,
    ExecutableRevoked,
    ProcessRevoked,
    Collision,
    CapacityExceeded,
    NotFound,
    StorageError,
    Corrupt
};

struct RuntimeIdentityStoreBudget {
    std::size_t max_devices{256U};
    std::size_t max_executables{2048U};
    std::size_t max_processes{4096U};
    std::size_t max_attestations{8192U};
};

struct RuntimeDeviceIdentity {
    std::string record_id;
    std::string provider_id;
    std::string device_id;
    RuntimeAttestationTrust strongest_trust{RuntimeAttestationTrust::NativeOsLocalDegraded};
    std::uint64_t first_seen_unix_ms{0U};
    std::uint64_t last_seen_unix_ms{0U};
    std::size_t observations{0U};
    std::uint64_t revoked_at_unix_ms{0U};
    std::string revocation_reason_code;

    [[nodiscard]] bool revoked() const noexcept;
};

struct RuntimeExecutableIdentity {
    std::string record_id;
    std::string executable_sha256;
    std::uint64_t first_seen_unix_ms{0U};
    std::uint64_t last_seen_unix_ms{0U};
    std::size_t observations{0U};
    std::uint64_t revoked_at_unix_ms{0U};
    std::string revocation_reason_code;

    [[nodiscard]] bool revoked() const noexcept;
};

struct RuntimeProcessIdentity {
    std::string record_id;
    std::string provider_id;
    std::string process_instance_sha256;
    std::string device_record_id;
    std::string executable_record_id;
    std::string device_id;
    std::string executable_sha256;
    std::uint64_t process_id{0U};
    std::uint64_t process_started_unix_ms{0U};
    std::uint64_t first_seen_unix_ms{0U};
    std::uint64_t last_seen_unix_ms{0U};
    std::size_t observations{0U};
    std::uint64_t revoked_at_unix_ms{0U};
    std::string revocation_reason_code;

    [[nodiscard]] bool revoked() const noexcept;
};

struct RuntimeIdentityObservation {
    std::string attestation_id;
    std::string canonical_sha256;
    std::string provider_id;
    RuntimeAttestationTrust trust{RuntimeAttestationTrust::NativeOsLocal};
    std::string device_record_id;
    std::string executable_record_id;
    std::string process_record_id;
    std::string slot_id;
    std::string session_id;
    RealityLayer layer{RealityLayer::Runtime};
    std::uint64_t observed_at_unix_ms{0U};
    std::uint64_t valid_until_unix_ms{0U};
    std::string challenge_sha256;
    std::string executable_locator_sha256;
};

struct RuntimeIdentityStoreResult {
    RuntimeIdentityStoreStatus status{RuntimeIdentityStoreStatus::InvalidEvidence};
    std::string device_record_id;
    std::string executable_record_id;
    std::string process_record_id;
    std::string attestation_id;
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

struct RuntimeIdentityStoreInspection {
    bool healthy{true};
    std::size_t records{0U};
    std::size_t devices{0U};
    std::size_t executables{0U};
    std::size_t processes{0U};
    std::size_t attestations{0U};
    std::size_t revoked_devices{0U};
    std::size_t revoked_executables{0U};
    std::size_t revoked_processes{0U};
    std::vector<std::string> errors;
};

class RuntimeIdentityStore {
public:
    explicit RuntimeIdentityStore(
        std::filesystem::path journal_path,
        RuntimeIdentityStoreBudget budget = {});

    [[nodiscard]] RuntimeIdentityStoreResult record_attestation(
        const RuntimeAttestationEvidence& evidence);

    [[nodiscard]] RuntimeIdentityStoreResult revoke_device(
        std::string_view record_id,
        std::uint64_t revoked_at_unix_ms,
        std::string_view reason_code);
    [[nodiscard]] RuntimeIdentityStoreResult revoke_executable(
        std::string_view record_id,
        std::uint64_t revoked_at_unix_ms,
        std::string_view reason_code);
    [[nodiscard]] RuntimeIdentityStoreResult revoke_process(
        std::string_view record_id,
        std::uint64_t revoked_at_unix_ms,
        std::string_view reason_code);

    [[nodiscard]] std::optional<RuntimeDeviceIdentity> device(
        std::string_view record_id) const;
    [[nodiscard]] std::optional<RuntimeExecutableIdentity> executable(
        std::string_view record_id) const;
    [[nodiscard]] std::optional<RuntimeProcessIdentity> process(
        std::string_view record_id) const;
    [[nodiscard]] std::optional<RuntimeIdentityObservation> attestation(
        std::string_view attestation_id) const;

    [[nodiscard]] bool identity_active(
        const RuntimeAttestationEvidence& evidence) const noexcept;
    [[nodiscard]] bool replay(std::vector<std::string>* errors = nullptr);
    [[nodiscard]] RuntimeIdentityStoreInspection inspect() const;
    [[nodiscard]] const RuntimeIdentityStoreBudget& budget() const noexcept;
    [[nodiscard]] const std::filesystem::path& journal_path() const noexcept;

private:
    [[nodiscard]] bool append_event(std::string_view body, std::string* error);
    [[nodiscard]] RuntimeIdentityStoreResult revoke_impl(
        char kind,
        std::string_view record_id,
        std::uint64_t revoked_at_unix_ms,
        std::string_view reason_code);

    std::filesystem::path journal_path_;
    RuntimeIdentityStoreBudget budget_;
    std::unordered_map<std::string, RuntimeDeviceIdentity> devices_;
    std::unordered_map<std::string, RuntimeExecutableIdentity> executables_;
    std::unordered_map<std::string, RuntimeProcessIdentity> processes_;
    std::unordered_map<std::string, RuntimeIdentityObservation> attestations_;
    std::size_t sequence_{0U};
    std::string last_record_sha256_;
    bool healthy_{true};
    std::vector<std::string> errors_;
};

class IdentityTrackingRuntimeAttestationProvider final
    : public RuntimeAttestationProvider {
public:
    IdentityTrackingRuntimeAttestationProvider(
        const RuntimeAttestationProvider& inner,
        RuntimeIdentityStore& store) noexcept;

    [[nodiscard]] std::string provider_id() const override;
    [[nodiscard]] RuntimeAttestationTrust trust() const noexcept override;
    [[nodiscard]] RuntimeAttestationResult attest(
        const RuntimeAttestationRequest& request) const override;

private:
    const RuntimeAttestationProvider& inner_;
    RuntimeIdentityStore& store_;
};

[[nodiscard]] std::string runtime_device_identity_id(
    std::string_view provider_id,
    std::string_view device_id);
[[nodiscard]] std::string runtime_executable_identity_id(
    std::string_view executable_sha256);
[[nodiscard]] std::string runtime_process_identity_id(
    std::string_view provider_id,
    std::string_view process_instance_sha256);
[[nodiscard]] std::string_view to_string(
    RuntimeIdentityStoreStatus status) noexcept;

} // namespace guff
