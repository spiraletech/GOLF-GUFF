#pragma once

#include "guff/hardware_profile.hpp"
#include "guff/kernel_task.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class ReplaySourceOutcome : std::uint8_t {
    Completed,
    Failed
};

enum class ReplayPreflightStatus : std::uint8_t {
    Ready,
    InvalidCapsule,
    InputDrift,
    HardwareDrift
};

enum class ReplayVerificationStatus : std::uint8_t {
    ExactMatch,
    ReproducedFailure,
    InvalidCapsule,
    InputDrift,
    HardwareDrift,
    RuntimeDrift,
    OutputDrift,
    FailureDrift,
    ReplayIncomplete
};

struct KernelFailureProof {
    std::uint32_t schema_version{1U};
    KernelTaskStatus task_status{KernelTaskStatus::InvalidRequest};
    bool execution_present{false};
    ForgeStatus forge_status{ForgeStatus::InvalidRequest};
    int exit_code{-1};
    std::string request_contract_sha256;
    std::string hardware_id;
    std::string selected_model_id;
    std::string artifact_id;
    std::string binding_id;
    std::string slot_immutable_id;
    std::string route_trace_sha256;
    std::string captured_output_sha256;
    std::string reason_sha256;

    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] std::string canonical_payload() const;
    [[nodiscard]] std::string immutable_id() const;
};

struct KernelReplayCapsule {
    std::uint32_t schema_version{1U};
    ReplaySourceOutcome source_outcome{ReplaySourceOutcome::Completed};
    std::string source_proof_id;
    std::string request_contract_sha256;
    std::string hardware_id;
    KernelTaskStatus expected_task_status{KernelTaskStatus::InvalidRequest};
    std::string model_id;
    std::string cartridge_id;
    std::string artifact_id;
    std::string binding_id;
    std::string slot_immutable_id;
    std::string prompt_sha256;
    std::string context_sha256;
    std::string answer_sha256;
    bool semantic_verified{false};
    std::string failure_proof_id;

    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] std::string canonical_payload() const;
    [[nodiscard]] std::string immutable_id() const;
};

struct ReplayPreflight {
    ReplayPreflightStatus status{ReplayPreflightStatus::InvalidCapsule};
    std::string capsule_id;
    std::string request_contract_sha256;
    std::string hardware_id;
    std::string reason;

    [[nodiscard]] bool ready() const noexcept;
};

struct ReplayVerification {
    ReplayVerificationStatus status{ReplayVerificationStatus::InvalidCapsule};
    std::string capsule_id;
    std::string observed_proof_id;
    std::string reason;

    [[nodiscard]] bool matched() const noexcept;
};

class KernelReplayProof {
public:
    [[nodiscard]] std::optional<KernelFailureProof> capture_failure(
        const KernelTaskRequest& request,
        const KernelTaskResult& result,
        const HardwareProfile& hardware) const;

    [[nodiscard]] std::optional<KernelReplayCapsule> capture(
        const KernelTaskRequest& request,
        const KernelTaskResult& result,
        const HardwareProfile& hardware) const;

    [[nodiscard]] ReplayPreflight preflight(
        const KernelReplayCapsule& capsule,
        const KernelTaskRequest& replay_request,
        const HardwareProfile& hardware) const;

    [[nodiscard]] ReplayVerification verify(
        const KernelReplayCapsule& capsule,
        const KernelTaskRequest& replay_request,
        const KernelTaskResult& replay_result,
        const HardwareProfile& hardware) const;
};

[[nodiscard]] std::string replay_request_contract_sha256(
    const KernelTaskRequest& request);

[[nodiscard]] std::string_view to_string(ReplaySourceOutcome outcome) noexcept;
[[nodiscard]] std::string_view to_string(ReplayPreflightStatus status) noexcept;
[[nodiscard]] std::string_view to_string(ReplayVerificationStatus status) noexcept;

} // namespace guff
