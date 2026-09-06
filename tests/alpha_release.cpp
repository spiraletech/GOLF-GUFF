#include "guff/alpha_release.hpp"
#include "guff/sha256.hpp"

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "CHECK failed: " #expression << " @ " << __FILE__ << ':' << __LINE__ << '\n'; return 1; } } while (false)

namespace {

guff::RingReleaseResult ready_ring() {
    guff::RingReleaseResult ring;
    ring.status = guff::RingReleaseStatus::Ready;
    ring.release_id = "guff:ring-release:sha256:" + guff::sha256("l31-ring-ready");
    ring.checks = 20U;
    return ring;
}

std::vector<guff::AlphaReleaseEvidence> full_evidence() {
    std::vector<guff::AlphaReleaseEvidence> evidence;
    for (const auto& name : guff::AlphaReleaseGate::required_evidence_names()) {
        evidence.push_back({name, true, guff::sha256("alpha:" + name), "verified"});
    }
    return evidence;
}

guff::AlphaReleaseRequest request() {
    guff::AlphaReleaseRequest value;
    value.version = "0.31.0-alpha.1";
    value.commit_sha = "104601f5300a07cb44c2d2b741abcd6f835be74d";
    value.source_tree_sha256 = guff::sha256("l31-source-tree");
    value.ring_release = ready_ring();
    value.evidence = full_evidence();
    return value;
}

bool has_blocker(const guff::AlphaReleaseCertificate& certificate,
                 const std::string& needle) {
    return std::any_of(certificate.blockers.begin(), certificate.blockers.end(),
                       [&](const std::string& value) {
                           return value.find(needle) != std::string::npos;
                       });
}

} // namespace

int main() {
    guff::AlphaReleaseGate gate;
    auto alpha = request();

    const auto ready = gate.evaluate(alpha);
    CHECK(ready.ready());
    CHECK(ready.status == guff::AlphaReleaseStatus::Ready);
    CHECK(ready.alpha_release_id.starts_with("guff:alpha-release:sha256:"));
    CHECK(ready.version == alpha.version);
    CHECK(ready.commit_sha == alpha.commit_sha);
    CHECK(ready.source_tree_sha256 == alpha.source_tree_sha256);
    CHECK(ready.ring_release_id == alpha.ring_release.release_id);
    CHECK(ready.blockers.empty());
    CHECK(ready.checks == 16U);

    auto reversed = alpha;
    std::reverse(reversed.evidence.begin(), reversed.evidence.end());
    const auto reordered = gate.evaluate(reversed);
    CHECK(reordered.ready());
    CHECK(reordered.alpha_release_id == ready.alpha_release_id);

    auto missing = alpha;
    missing.evidence.pop_back();
    const auto missing_result = gate.evaluate(missing);
    CHECK(missing_result.status == guff::AlphaReleaseStatus::Blocked);
    CHECK(has_blocker(missing_result, "required alpha evidence present"));

    auto failed = alpha;
    failed.evidence.front().passed = false;
    const auto failed_result = gate.evaluate(failed);
    CHECK(failed_result.status == guff::AlphaReleaseStatus::Blocked);
    CHECK(has_blocker(failed_result, "all supplied alpha evidence"));
    CHECK(has_blocker(failed_result, "required alpha evidence passed"));

    auto blocked_ring = alpha;
    blocked_ring.ring_release.status = guff::RingReleaseStatus::Blocked;
    const auto blocked_ring_result = gate.evaluate(blocked_ring);
    CHECK(blocked_ring_result.status == guff::AlphaReleaseStatus::Blocked);
    CHECK(has_blocker(blocked_ring_result, "ring release gate"));

    auto malformed_ring = alpha;
    malformed_ring.ring_release.release_id = "guff:ring-release:sha256:not-a-digest";
    const auto malformed_ring_result = gate.evaluate(malformed_ring);
    CHECK(malformed_ring_result.status == guff::AlphaReleaseStatus::Blocked);
    CHECK(has_blocker(malformed_ring_result, "content-addressed"));

    auto wrong_version = alpha;
    wrong_version.version = "0.32.0-alpha.1";
    CHECK(gate.evaluate(wrong_version).status == guff::AlphaReleaseStatus::Blocked);

    auto bad_commit = alpha;
    bad_commit.commit_sha = "not-a-git-object";
    CHECK(gate.evaluate(bad_commit).status == guff::AlphaReleaseStatus::Blocked);

    auto bad_tree = alpha;
    bad_tree.source_tree_sha256 = "not-a-sha256";
    CHECK(gate.evaluate(bad_tree).status == guff::AlphaReleaseStatus::Blocked);

    auto duplicate = alpha;
    duplicate.evidence.push_back(duplicate.evidence.front());
    CHECK(gate.evaluate(duplicate).status == guff::AlphaReleaseStatus::Invalid);

    auto malformed_evidence = alpha;
    malformed_evidence.evidence.front().evidence_sha256 = "broken";
    CHECK(gate.evaluate(malformed_evidence).status == guff::AlphaReleaseStatus::Invalid);

    guff::AlphaReleaseGate zero({.max_evidence = 0U,
                                 .max_blockers = 8U,
                                 .max_detail_bytes = 128U});
    CHECK(zero.evaluate(alpha).status == guff::AlphaReleaseStatus::Invalid);

    return 0;
}
