#include "guff/zenkai.hpp"

#include <cassert>
#include <string>

int main() {
    guff::ZenkaiBudget budget;
    budget.max_attempts = 3U;
    budget.max_tool_events = 6U;
    budget.max_evidence_items = 8U;
    budget.max_evidence_bytes = 2048U;
    budget.acceptance_confidence = 0.90;
    guff::ZenkaiLoop loop(budget);

    std::size_t calls = 0U;
    const auto repaired = loop.run(
        "broken",
        {.retry_authority = guff::RetryAuthority::Bounded},
        [&](std::size_t attempt, std::string_view previous) {
            ++calls;
            guff::ZenkaiAttempt result;
            if (attempt == 0U) {
                assert(previous == "broken");
                result.candidate_state = "patch-v1";
                result.evidence = {
                    {guff::EvidenceKind::Build, "cmake-build", false, "compile error"},
                    {guff::EvidenceKind::Verifier, "compiler-diagnostic", true, "localized failing symbol"},
                };
                result.verification = {false, 0.62, "build still fails"};
                return result;
            }
            assert(previous == "patch-v1");
            result.candidate_state = "patch-v2";
            result.evidence = {
                {guff::EvidenceKind::Build, "cmake-build", true, "build passed"},
                {guff::EvidenceKind::Test, "ctest", true, "all tests passed"},
            };
            result.verification = {true, 0.97, "compile and test evidence agree"};
            return result;
        });
    assert(calls == 2U);
    assert(repaired.verified);
    assert(repaired.stop_reason == guff::ZenkaiStopReason::Verified);
    assert(repaired.final_state == "patch-v2");
    assert(repaired.attempts == 2U);
    assert(repaired.tool_events == 3U);

    calls = 0U;
    const auto denied = loop.run(
        "broken",
        {.retry_authority = guff::RetryAuthority::None},
        [&](std::size_t, std::string_view) {
            ++calls;
            guff::ZenkaiAttempt result;
            result.candidate_state = "still-broken";
            result.evidence = {{guff::EvidenceKind::Test, "ctest", false, "failure"}};
            result.verification = {false, 0.30, "not fixed"};
            return result;
        });
    assert(calls == 1U);
    assert(!denied.verified);
    assert(denied.stop_reason == guff::ZenkaiStopReason::RetryNotAuthorized);

    const auto no_new = loop.run(
        "state",
        {.retry_authority = guff::RetryAuthority::Bounded},
        [](std::size_t, std::string_view previous) {
            guff::ZenkaiAttempt result;
            result.candidate_state = std::string(previous);
            result.produced_new_information = false;
            result.verification = {false, 0.50, "no delta"};
            return result;
        });
    assert(no_new.stop_reason == guff::ZenkaiStopReason::NoNewInformation);
    assert(no_new.attempts == 1U);

    guff::ZenkaiBudget tiny;
    tiny.max_attempts = 3U;
    tiny.max_tool_events = 1U;
    guff::ZenkaiLoop tool_limited(tiny);
    const auto tool_stop = tool_limited.run(
        "state",
        {.retry_authority = guff::RetryAuthority::Bounded},
        [](std::size_t, std::string_view) {
            guff::ZenkaiAttempt result;
            result.evidence = {
                {guff::EvidenceKind::Build, "build", false, "failure"},
                {guff::EvidenceKind::Test, "test", false, "failure"},
            };
            result.verification = {false, 0.10, "bad"};
            return result;
        });
    assert(tool_stop.stop_reason == guff::ZenkaiStopReason::ToolBudget);
    assert(tool_stop.tool_events == 1U);

    guff::ZenkaiBudget capped;
    capped.max_attempts = 2U;
    capped.max_trace_entries = 2U;
    guff::ZenkaiLoop trace_limited(capped);
    const auto trace_stop = trace_limited.run(
        "state",
        {.retry_authority = guff::RetryAuthority::Bounded},
        [](std::size_t, std::string_view) {
            guff::ZenkaiAttempt result;
            result.evidence = {{guff::EvidenceKind::Verifier, "v", false, "x"}};
            result.verification = {false, 0.10, "fail"};
            return result;
        });
    assert(trace_stop.stop_reason == guff::ZenkaiStopReason::AttemptBudget);
    assert(trace_stop.trace.size() == 2U);
    assert(trace_stop.trace_truncated);

    return 0;
}
