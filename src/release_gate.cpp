#include "guff/release_gate.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <sstream>
#include <utility>

namespace guff {
namespace {

constexpr std::string_view kReleasePrefix = "guff:ring-release:sha256:";

bool valid_text(std::string_view value, std::size_t max_bytes) {
    if (value.empty() || value.size() > max_bytes) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch >= 0x20U && ch != 0x7fU;
    });
}

void push_bounded(std::vector<std::string>& out,
                  std::size_t limit,
                  std::string value) {
    if (out.size() < limit) out.push_back(std::move(value));
}

std::vector<RingReleaseEvidence> sorted_evidence(
    const std::vector<RingReleaseEvidence>& evidence) {
    auto sorted = evidence;
    std::sort(sorted.begin(), sorted.end(),
              [](const RingReleaseEvidence& a, const RingReleaseEvidence& b) {
                  if (a.name != b.name) return a.name < b.name;
                  if (a.evidence_sha256 != b.evidence_sha256)
                      return a.evidence_sha256 < b.evidence_sha256;
                  return a.detail < b.detail;
              });
    return sorted;
}

} // namespace

bool RingReleaseResult::ready() const noexcept {
    return status == RingReleaseStatus::Ready;
}

RingReleaseGate::RingReleaseGate(RingReleaseBudget budget)
    : budget_(budget) {}

RingReleaseResult RingReleaseGate::evaluate(
    const OperatorConsoleSnapshot& snapshot,
    const std::vector<RingReleaseEvidence>& evidence) const {
    RingReleaseResult result;

    if (budget_.max_evidence == 0U || budget_.max_blockers == 0U ||
        budget_.max_detail_bytes == 0U) {
        result.status = RingReleaseStatus::Invalid;
        result.blockers.emplace_back("release gate budget contains a zero ceiling");
        return result;
    }
    if (evidence.size() > budget_.max_evidence) {
        result.status = RingReleaseStatus::Invalid;
        result.blockers.emplace_back("release evidence count exceeds gate ceiling");
        return result;
    }

    std::map<std::string, RingReleaseEvidence> evidence_by_name;
    for (const auto& item : evidence) {
        if (!valid_text(item.name, 128U) || !is_sha256(item.evidence_sha256) ||
            item.detail.size() > budget_.max_detail_bytes) {
            result.status = RingReleaseStatus::Invalid;
            result.blockers.emplace_back("release evidence contains malformed name/hash/detail");
            return result;
        }
        if (!evidence_by_name.emplace(item.name, item).second) {
            result.status = RingReleaseStatus::Invalid;
            result.blockers.emplace_back("duplicate release evidence name: " + item.name);
            return result;
        }
    }

    auto check = [&](bool passed, std::string label) {
        ++result.checks;
        push_bounded(result.trace, budget_.max_blockers,
                     std::string(passed ? "PASS " : "BLOCK ") + label);
        if (!passed) push_bounded(result.blockers, budget_.max_blockers, std::move(label));
    };

    check(snapshot.healthy, "operator aggregate snapshot must be healthy");
    check(snapshot.policy.healthy, "policy registry must be healthy");
    check(snapshot.recovery.healthy, "transaction/recovery journal must be healthy");
    check(snapshot.authority.healthy, "authority ledger must be healthy");
    check(snapshot.identities.healthy, "runtime identity store must be healthy");
    check(snapshot.reviews.healthy, "operator review queue must be healthy");
    check(!snapshot.policy.active_policy_id.empty(), "an active signed policy must exist");
    check(snapshot.active_policy.has_value(), "active policy signer provenance must resolve");
    check(snapshot.recovery.interrupted.empty(), "no interrupted transaction may remain unresolved");
    check(snapshot.reviews.pending == 0U, "no HUMAN_REVIEW ticket may remain pending");

    for (const auto& required : required_evidence_names()) {
        const auto it = evidence_by_name.find(required);
        check(it != evidence_by_name.end(), "required release evidence present: " + required);
        if (it != evidence_by_name.end()) {
            check(it->second.passed, "required release evidence passed: " + required);
        }
    }

    result.release_id = std::string(kReleasePrefix) +
                        sha256(canonical_ring_release_material(snapshot, evidence));
    result.status = result.blockers.empty() ? RingReleaseStatus::Ready
                                            : RingReleaseStatus::Blocked;
    return result;
}

const RingReleaseBudget& RingReleaseGate::budget() const noexcept {
    return budget_;
}

std::vector<std::string> RingReleaseGate::required_evidence_names() {
    return {
        "cross-platform-ci",
        "mutation-corpus",
        "operator-cli",
        "regression-suite",
        "storage-failure-injection",
    };
}

std::string canonical_ring_release_material(
    const OperatorConsoleSnapshot& snapshot,
    const std::vector<RingReleaseEvidence>& evidence) {
    std::ostringstream out;
    out << "GOLF-GUFF-RING-V1\n"
        << (snapshot.healthy ? 1 : 0) << '\n'
        << snapshot.policy.active_policy_id << '\n'
        << snapshot.policy.active_package_id << '\n'
        << snapshot.policy.activation_generation << '\n'
        << snapshot.policy.records << '\n'
        << snapshot.recovery.records << '\n'
        << snapshot.recovery.head_sha256 << '\n'
        << snapshot.recovery.interrupted.size() << '\n'
        << snapshot.authority.records << '\n'
        << snapshot.authority.trusted_keys << '\n'
        << snapshot.authority.consumed_receipts << '\n'
        << snapshot.identities.records << '\n'
        << snapshot.identities.devices << '\n'
        << snapshot.identities.executables << '\n'
        << snapshot.identities.processes << '\n'
        << snapshot.reviews.records << '\n'
        << snapshot.reviews.pending << '\n';

    if (snapshot.active_policy) {
        out << snapshot.active_policy->policy_id << '\n'
            << snapshot.active_policy->package_id << '\n'
            << snapshot.active_policy->signer_id << '\n'
            << snapshot.active_policy->algorithm << '\n'
            << snapshot.active_policy->signed_at_unix_ms << '\n';
    } else {
        out << "NO-ACTIVE-PROVENANCE\n";
    }

    const auto sorted = sorted_evidence(evidence);
    out << sorted.size() << '\n';
    for (const auto& item : sorted) {
        out << item.name.size() << ':' << item.name << '\n'
            << (item.passed ? 1 : 0) << '\n'
            << item.evidence_sha256 << '\n'
            << item.detail.size() << ':' << item.detail << '\n';
    }
    return out.str();
}

std::string_view to_string(RingReleaseStatus status) noexcept {
    switch (status) {
    case RingReleaseStatus::Ready: return "READY";
    case RingReleaseStatus::Blocked: return "BLOCKED";
    case RingReleaseStatus::Invalid: return "INVALID";
    }
    return "INVALID";
}

} // namespace guff
