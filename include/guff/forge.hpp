#pragma once

#include "guff/clubhouse.hpp"
#include "guff/zenkai.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class ForgeStatus : std::uint8_t {
    Completed,
    InvalidRequest,
    InvocationRejected,
    InputMismatch,
    ExecutorError,
    Timeout,
    OutputBudget,
    ExecutionFailed
};

struct ForgeBudget {
    std::uint64_t max_wall_time_ms{30'000U};
    std::size_t max_output_bytes{64U * 1024U};
};

struct ForgeExecutionRequest {
    SlotInvocation invocation;
    std::string payload;
    ForgeBudget budget{};
};

class ForgeOutputSink {
public:
    explicit ForgeOutputSink(std::size_t max_bytes);

    [[nodiscard]] bool write(std::string_view chunk);
    [[nodiscard]] std::string_view captured() const noexcept;
    [[nodiscard]] std::size_t captured_bytes() const noexcept;
    [[nodiscard]] std::size_t observed_bytes() const noexcept;
    [[nodiscard]] bool truncated() const noexcept;

private:
    std::size_t max_bytes_{0U};
    std::size_t observed_bytes_{0U};
    bool truncated_{false};
    std::string captured_;
};

struct ForgeExecutorReport {
    bool completed{false};
    int exit_code{-1};
    std::uint64_t reported_wall_time_ms{0U};
};

struct ForgeExecutionResult {
    ForgeStatus status{ForgeStatus::InvalidRequest};
    InvocationStatus invocation_status{InvocationStatus::Invalid};
    std::string invocation_id;
    std::string slot_id;
    std::string slot_immutable_id;
    int exit_code{-1};
    std::uint64_t wall_time_ms{0U};
    std::size_t captured_output_bytes{0U};
    std::size_t observed_output_bytes{0U};
    bool output_truncated{false};
    std::string captured_output_sha256;
    std::vector<ZenkaiEvidence> evidence;
    std::string reason;

    [[nodiscard]] bool succeeded() const noexcept;
};

class ForgeAdapter {
public:
    using ExecutorFunction = std::function<ForgeExecutorReport(
        const SlotManifest& slot,
        const ForgeExecutionRequest& request,
        ForgeOutputSink& output)>;

    explicit ForgeAdapter(const ClubhouseRegistry& clubhouse) noexcept;

    [[nodiscard]] ForgeExecutionResult execute(
        const ForgeExecutionRequest& request,
        const ExecutorFunction& executor) const;

private:
    const ClubhouseRegistry& clubhouse_;
};

[[nodiscard]] EvidenceKind forge_evidence_kind(SlotCapability capability) noexcept;
[[nodiscard]] std::string_view to_string(ForgeStatus status) noexcept;

} // namespace guff
