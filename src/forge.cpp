#include "guff/forge.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <utility>

namespace guff {
namespace {

std::size_t saturating_add(std::size_t lhs, std::size_t rhs) noexcept {
    if (rhs > std::numeric_limits<std::size_t>::max() - lhs) {
        return std::numeric_limits<std::size_t>::max();
    }
    return lhs + rhs;
}

void append_execution_evidence(ForgeExecutionResult& result,
                               SlotCapability capability,
                               std::string_view source,
                               bool passed) {
    std::string detail = "status=" + std::string(to_string(result.status)) +
                         " exit=" + std::to_string(result.exit_code) +
                         " wall_ms=" + std::to_string(result.wall_time_ms) +
                         " output_bytes=" + std::to_string(result.observed_output_bytes);
    if (!result.captured_output_sha256.empty()) {
        detail += " captured_sha256=" + result.captured_output_sha256;
    }
    result.evidence.push_back({forge_evidence_kind(capability), std::string(source), passed, std::move(detail)});
}

} // namespace

ForgeOutputSink::ForgeOutputSink(std::size_t max_bytes) : max_bytes_(max_bytes) {
    captured_.reserve(std::min<std::size_t>(max_bytes_, 4096U));
}

bool ForgeOutputSink::write(std::string_view chunk) {
    observed_bytes_ = saturating_add(observed_bytes_, chunk.size());
    if (chunk.empty()) {
        return !truncated_;
    }

    const auto room = max_bytes_ > captured_.size() ? max_bytes_ - captured_.size() : 0U;
    const auto take = std::min(room, chunk.size());
    if (take > 0U) {
        captured_.append(chunk.data(), take);
    }
    if (take != chunk.size()) {
        truncated_ = true;
        return false;
    }
    return true;
}

std::string_view ForgeOutputSink::captured() const noexcept { return captured_; }
std::size_t ForgeOutputSink::captured_bytes() const noexcept { return captured_.size(); }
std::size_t ForgeOutputSink::observed_bytes() const noexcept { return observed_bytes_; }
bool ForgeOutputSink::truncated() const noexcept { return truncated_; }

bool ForgeExecutionResult::succeeded() const noexcept {
    return status == ForgeStatus::Completed;
}

ForgeAdapter::ForgeAdapter(const ClubhouseRegistry& clubhouse) noexcept : clubhouse_(clubhouse) {}

ForgeExecutionResult ForgeAdapter::execute(const ForgeExecutionRequest& request,
                                           const ExecutorFunction& executor) const {
    ForgeExecutionResult result;
    result.invocation_id = request.invocation.invocation_id;
    result.slot_id = request.invocation.slot_id;

    if (request.budget.max_wall_time_ms == 0U || request.budget.max_output_bytes == 0U) {
        result.status = ForgeStatus::InvalidRequest;
        result.reason = "FORGE budgets must be greater than zero";
        return result;
    }
    if (request.payload.size() != request.invocation.payload_bytes ||
        sha256(request.payload) != request.invocation.input_sha256) {
        result.status = ForgeStatus::InputMismatch;
        result.reason = "payload bytes/hash do not match CLUBHOUSE invocation identity";
        return result;
    }

    const auto resolution = clubhouse_.resolve(request.invocation);
    result.invocation_status = resolution.status;
    if (!resolution.ready() || !resolution.slot) {
        result.status = ForgeStatus::InvocationRejected;
        result.reason = resolution.reason;
        return result;
    }

    const auto& slot = *resolution.slot;
    result.slot_immutable_id = slot.immutable_id();
    if (!executor) {
        result.status = ForgeStatus::ExecutorError;
        result.reason = "no executor adapter supplied";
        return result;
    }

    ForgeOutputSink output(request.budget.max_output_bytes);
    ForgeExecutorReport report;
    const auto started = std::chrono::steady_clock::now();
    try {
        report = executor(slot, request, output);
    } catch (...) {
        result.status = ForgeStatus::ExecutorError;
        result.reason = "executor adapter threw an exception";
        return result;
    }
    const auto ended = std::chrono::steady_clock::now();
    const auto measured = std::chrono::duration_cast<std::chrono::milliseconds>(ended - started).count();
    const auto measured_ms = measured < 0 ? 0U : static_cast<std::uint64_t>(measured);

    result.exit_code = report.exit_code;
    result.wall_time_ms = std::max(measured_ms, report.reported_wall_time_ms);
    result.captured_output_bytes = output.captured_bytes();
    result.observed_output_bytes = output.observed_bytes();
    result.output_truncated = output.truncated();
    if (!output.captured().empty()) {
        result.captured_output_sha256 = sha256(output.captured());
    }

    const auto evidence_source = slot.slot_name + ":" + std::string(to_string(request.invocation.capability));
    if (result.wall_time_ms > request.budget.max_wall_time_ms) {
        result.status = ForgeStatus::Timeout;
        result.reason = "executor exceeded FORGE wall-time budget";
        append_execution_evidence(result, request.invocation.capability, evidence_source, false);
        return result;
    }
    if (output.truncated()) {
        result.status = ForgeStatus::OutputBudget;
        result.reason = "executor exceeded FORGE output budget";
        append_execution_evidence(result, request.invocation.capability, evidence_source, false);
        return result;
    }
    if (!report.completed) {
        result.status = ForgeStatus::ExecutorError;
        result.reason = "executor did not report a completed execution";
        append_execution_evidence(result, request.invocation.capability, evidence_source, false);
        return result;
    }
    if (report.exit_code != 0) {
        result.status = ForgeStatus::ExecutionFailed;
        result.reason = "executor completed with a non-zero exit code";
        append_execution_evidence(result, request.invocation.capability, evidence_source, false);
        return result;
    }

    result.status = ForgeStatus::Completed;
    result.reason = "execution completed within FORGE budgets";
    append_execution_evidence(result, request.invocation.capability, evidence_source, true);
    return result;
}

EvidenceKind forge_evidence_kind(SlotCapability capability) noexcept {
    switch (capability) {
    case SlotCapability::CodeBuild: return EvidenceKind::Build;
    case SlotCapability::CodeTest: return EvidenceKind::Test;
    default: return EvidenceKind::Tool;
    }
}

std::string_view to_string(ForgeStatus status) noexcept {
    switch (status) {
    case ForgeStatus::Completed: return "COMPLETED";
    case ForgeStatus::InvalidRequest: return "INVALID_REQUEST";
    case ForgeStatus::InvocationRejected: return "INVOCATION_REJECTED";
    case ForgeStatus::InputMismatch: return "INPUT_MISMATCH";
    case ForgeStatus::ExecutorError: return "EXECUTOR_ERROR";
    case ForgeStatus::Timeout: return "TIMEOUT";
    case ForgeStatus::OutputBudget: return "OUTPUT_BUDGET";
    case ForgeStatus::ExecutionFailed: return "EXECUTION_FAILED";
    }
    return "INVALID_REQUEST";
}

} // namespace guff
