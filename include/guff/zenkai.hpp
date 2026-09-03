#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class EvidenceKind : std::uint8_t {
    Build,
    Test,
    Tool,
    Verifier
};

enum class RetryAuthority : std::uint8_t {
    None,
    Bounded
};

enum class ZenkaiStopReason : std::uint8_t {
    Verified,
    RetryNotAuthorized,
    NoNewInformation,
    FatalFailure,
    AttemptBudget,
    ToolBudget,
    EvidenceBudget
};

struct ZenkaiEvidence {
    EvidenceKind kind{EvidenceKind::Tool};
    std::string source;
    bool passed{false};
    std::string detail;
};

struct VerificationOutcome {
    bool passed{false};
    double confidence{0.0};
    std::string summary;
};

struct ZenkaiAttempt {
    std::string candidate_state;
    std::vector<ZenkaiEvidence> evidence;
    VerificationOutcome verification;
    bool produced_new_information{true};
    bool fatal{false};
};

struct ZenkaiBudget {
    std::size_t max_attempts{4U};
    std::size_t max_tool_events{16U};
    std::size_t max_evidence_items{64U};
    std::size_t max_evidence_bytes{64U * 1024U};
    std::size_t max_trace_entries{64U};
    double acceptance_confidence{0.85};
    std::size_t max_detail_bytes{4096U};
};

struct ZenkaiRunPolicy {
    RetryAuthority retry_authority{RetryAuthority::None};
};

struct ZenkaiTraceEntry {
    std::size_t attempt{0U};
    std::string stage;
    std::string detail;
};

struct ZenkaiResult {
    std::string final_state;
    ZenkaiStopReason stop_reason{ZenkaiStopReason::AttemptBudget};
    bool verified{false};
    std::size_t attempts{0U};
    std::size_t evidence_items{0U};
    std::size_t evidence_bytes{0U};
    std::size_t tool_events{0U};
    std::vector<ZenkaiTraceEntry> trace;
    bool trace_truncated{false};
};

class ZenkaiLoop {
public:
    using AttemptFunction = std::function<ZenkaiAttempt(
        std::size_t attempt_index,
        std::string_view previous_state)>;

    explicit ZenkaiLoop(ZenkaiBudget budget = {});

    [[nodiscard]] ZenkaiResult run(std::string initial_state,
                                   const ZenkaiRunPolicy& policy,
                                   const AttemptFunction& attempt) const;

private:
    ZenkaiBudget budget_;
};

[[nodiscard]] std::string_view to_string(EvidenceKind kind) noexcept;
[[nodiscard]] std::string_view to_string(RetryAuthority authority) noexcept;
[[nodiscard]] std::string_view to_string(ZenkaiStopReason reason) noexcept;

} // namespace guff
