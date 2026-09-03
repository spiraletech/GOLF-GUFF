#include "guff/zenkai.hpp"

#include <algorithm>
#include <utility>

namespace guff {
namespace {

std::size_t evidence_bytes(const ZenkaiEvidence& evidence) noexcept {
    return evidence.source.size() + evidence.detail.size();
}

bool is_tool_event(EvidenceKind kind) noexcept {
    return kind == EvidenceKind::Build || kind == EvidenceKind::Test || kind == EvidenceKind::Tool;
}

void append_trace(ZenkaiResult& result,
                  std::size_t max_entries,
                  std::size_t attempt,
                  std::string stage,
                  std::string detail) {
    if (result.trace.size() >= max_entries) {
        result.trace_truncated = true;
        return;
    }
    result.trace.push_back({attempt, std::move(stage), std::move(detail)});
}

} // namespace

ZenkaiLoop::ZenkaiLoop(ZenkaiBudget budget) : budget_(budget) {
    budget_.max_attempts = std::max<std::size_t>(1U, budget_.max_attempts);
    budget_.max_tool_events = std::max<std::size_t>(1U, budget_.max_tool_events);
    budget_.max_evidence_items = std::max<std::size_t>(1U, budget_.max_evidence_items);
    budget_.max_evidence_bytes = std::max<std::size_t>(1U, budget_.max_evidence_bytes);
    budget_.max_trace_entries = std::max<std::size_t>(1U, budget_.max_trace_entries);
    budget_.max_detail_bytes = std::max<std::size_t>(1U, budget_.max_detail_bytes);
    budget_.acceptance_confidence = std::clamp(budget_.acceptance_confidence, 0.0, 1.0);
}

ZenkaiResult ZenkaiLoop::run(std::string initial_state,
                             const ZenkaiRunPolicy& policy,
                             const AttemptFunction& attempt) const {
    ZenkaiResult result;
    result.final_state = std::move(initial_state);

    for (std::size_t index = 0U; index < budget_.max_attempts; ++index) {
        if (index > 0U && policy.retry_authority != RetryAuthority::Bounded) {
            result.stop_reason = ZenkaiStopReason::RetryNotAuthorized;
            append_trace(result, budget_.max_trace_entries, index, "STOP",
                         "retry authority is not granted");
            return result;
        }

        append_trace(result, budget_.max_trace_entries, index, "ATTEMPT", "attempt started");
        auto current = attempt(index, result.final_state);
        ++result.attempts;

        if (!current.candidate_state.empty()) {
            result.final_state = std::move(current.candidate_state);
        }

        for (auto& evidence : current.evidence) {
            if (evidence.detail.size() > budget_.max_detail_bytes) {
                evidence.detail.resize(budget_.max_detail_bytes);
            }
            if (evidence.source.size() > budget_.max_detail_bytes) {
                evidence.source.resize(budget_.max_detail_bytes);
            }

            const auto bytes = evidence_bytes(evidence);
            const auto next_tool_events = result.tool_events + (is_tool_event(evidence.kind) ? 1U : 0U);
            if (next_tool_events > budget_.max_tool_events) {
                result.stop_reason = ZenkaiStopReason::ToolBudget;
                append_trace(result, budget_.max_trace_entries, index, "STOP", "tool-event budget exhausted");
                return result;
            }
            if (result.evidence_items + 1U > budget_.max_evidence_items ||
                bytes > budget_.max_evidence_bytes - std::min(result.evidence_bytes, budget_.max_evidence_bytes)) {
                result.stop_reason = ZenkaiStopReason::EvidenceBudget;
                append_trace(result, budget_.max_trace_entries, index, "STOP", "evidence budget exhausted");
                return result;
            }

            ++result.evidence_items;
            result.evidence_bytes += bytes;
            result.tool_events = next_tool_events;
            append_trace(result, budget_.max_trace_entries, index,
                         evidence.passed ? "EVIDENCE_PASS" : "EVIDENCE_FAIL",
                         std::string(to_string(evidence.kind)) + ": " + evidence.source);
        }

        current.verification.confidence = std::clamp(current.verification.confidence, 0.0, 1.0);
        append_trace(result, budget_.max_trace_entries, index,
                     current.verification.passed ? "VERIFY_PASS" : "VERIFY_FAIL",
                     current.verification.summary);

        if (current.fatal) {
            result.stop_reason = ZenkaiStopReason::FatalFailure;
            append_trace(result, budget_.max_trace_entries, index, "STOP", "attempt reported fatal failure");
            return result;
        }

        if (current.verification.passed &&
            current.verification.confidence >= budget_.acceptance_confidence) {
            result.verified = true;
            result.stop_reason = ZenkaiStopReason::Verified;
            append_trace(result, budget_.max_trace_entries, index, "STOP", "verification threshold satisfied");
            return result;
        }

        if (!current.produced_new_information) {
            result.stop_reason = ZenkaiStopReason::NoNewInformation;
            append_trace(result, budget_.max_trace_entries, index, "STOP", "attempt produced no new information");
            return result;
        }
    }

    result.stop_reason = ZenkaiStopReason::AttemptBudget;
    append_trace(result, budget_.max_trace_entries, result.attempts, "STOP", "attempt budget exhausted");
    return result;
}

std::string_view to_string(EvidenceKind kind) noexcept {
    switch (kind) {
    case EvidenceKind::Build: return "BUILD";
    case EvidenceKind::Test: return "TEST";
    case EvidenceKind::Tool: return "TOOL";
    case EvidenceKind::Verifier: return "VERIFIER";
    }
    return "TOOL";
}

std::string_view to_string(RetryAuthority authority) noexcept {
    switch (authority) {
    case RetryAuthority::None: return "NONE";
    case RetryAuthority::Bounded: return "BOUNDED";
    }
    return "NONE";
}

std::string_view to_string(ZenkaiStopReason reason) noexcept {
    switch (reason) {
    case ZenkaiStopReason::Verified: return "VERIFIED";
    case ZenkaiStopReason::RetryNotAuthorized: return "RETRY_NOT_AUTHORIZED";
    case ZenkaiStopReason::NoNewInformation: return "NO_NEW_INFORMATION";
    case ZenkaiStopReason::FatalFailure: return "FATAL_FAILURE";
    case ZenkaiStopReason::AttemptBudget: return "ATTEMPT_BUDGET";
    case ZenkaiStopReason::ToolBudget: return "TOOL_BUDGET";
    case ZenkaiStopReason::EvidenceBudget: return "EVIDENCE_BUDGET";
    }
    return "ATTEMPT_BUDGET";
}

} // namespace guff
