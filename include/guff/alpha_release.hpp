#pragma once

#include "guff/release_gate.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class AlphaReleaseStatus : std::uint8_t {
    Ready,
    Blocked,
    Invalid
};

struct AlphaReleaseEvidence {
    std::string name;
    bool passed{false};
    std::string evidence_sha256;
    std::string detail;
};

struct AlphaReleaseRequest {
    std::string version{"0.31.0-alpha.1"};
    std::string commit_sha;
    std::string source_tree_sha256;
    RingReleaseResult ring_release;
    std::vector<AlphaReleaseEvidence> evidence;
};

struct AlphaReleaseBudget {
    std::size_t max_evidence{32U};
    std::size_t max_blockers{32U};
    std::size_t max_detail_bytes{1024U};
};

struct AlphaReleaseCertificate {
    AlphaReleaseStatus status{AlphaReleaseStatus::Invalid};
    std::string alpha_release_id;
    std::string version;
    std::string commit_sha;
    std::string source_tree_sha256;
    std::string ring_release_id;
    std::size_t checks{0U};
    std::vector<std::string> blockers;
    std::vector<std::string> trace;

    [[nodiscard]] bool ready() const noexcept;
};

class AlphaReleaseGate {
public:
    explicit AlphaReleaseGate(AlphaReleaseBudget budget = {});

    [[nodiscard]] AlphaReleaseCertificate evaluate(
        const AlphaReleaseRequest& request) const;

    [[nodiscard]] const AlphaReleaseBudget& budget() const noexcept;

    [[nodiscard]] static std::vector<std::string> required_evidence_names();

private:
    AlphaReleaseBudget budget_;
};

[[nodiscard]] std::string canonical_alpha_release_material(
    const AlphaReleaseRequest& request);
[[nodiscard]] std::string_view to_string(AlphaReleaseStatus status) noexcept;

} // namespace guff
