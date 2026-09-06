#pragma once

#include "guff/operator_console.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class RingReleaseStatus : std::uint8_t {
    Ready,
    Blocked,
    Invalid
};

struct RingReleaseEvidence {
    std::string name;
    bool passed{false};
    std::string evidence_sha256;
    std::string detail;
};

struct RingReleaseBudget {
    std::size_t max_evidence{32U};
    std::size_t max_blockers{32U};
    std::size_t max_detail_bytes{1024U};
};

struct RingReleaseResult {
    RingReleaseStatus status{RingReleaseStatus::Invalid};
    std::string release_id;
    std::size_t checks{0U};
    std::vector<std::string> blockers;
    std::vector<std::string> trace;

    [[nodiscard]] bool ready() const noexcept;
};

class RingReleaseGate {
public:
    explicit RingReleaseGate(RingReleaseBudget budget = {});

    [[nodiscard]] RingReleaseResult evaluate(
        const OperatorConsoleSnapshot& snapshot,
        const std::vector<RingReleaseEvidence>& evidence) const;

    [[nodiscard]] const RingReleaseBudget& budget() const noexcept;

    [[nodiscard]] static std::vector<std::string> required_evidence_names();

private:
    RingReleaseBudget budget_;
};

[[nodiscard]] std::string canonical_ring_release_material(
    const OperatorConsoleSnapshot& snapshot,
    const std::vector<RingReleaseEvidence>& evidence);
[[nodiscard]] std::string_view to_string(RingReleaseStatus status) noexcept;

} // namespace guff
