#include "guff/release_gate.hpp"
#include "guff/sha256.hpp"

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "CHECK failed: " #expression << " @ " << __FILE__ << ':' << __LINE__ << '\n'; return 1; } } while (false)

namespace {

guff::OperatorConsoleSnapshot healthy_snapshot() {
    guff::OperatorConsoleSnapshot s;
    s.healthy = true;
    s.policy.healthy = true;
    s.policy.active_policy_id = "guff:policy:sha256:" + guff::sha256("release-policy");
    s.policy.active_package_id = "guff:policy-package:sha256:" + guff::sha256("release-package");
    s.policy.activation_generation = 7U;
    s.policy.records = 11U;
    s.active_policy = guff::ActivePolicyProvenance{
        .policy_id = s.policy.active_policy_id,
        .package_id = s.policy.active_package_id,
        .signer_id = "policy-author:release",
        .algorithm = "TEST-SHA256",
        .signed_at_unix_ms = 1'725'700'000'000ULL,
    };
    s.recovery.healthy = true;
    s.recovery.records = 23U;
    s.recovery.head_sha256 = guff::sha256("transaction-head");
    s.authority.healthy = true;
    s.authority.records = 31U;
    s.authority.trusted_keys = 2U;
    s.authority.consumed_receipts = 9U;
    s.identities.healthy = true;
    s.identities.records = 17U;
    s.identities.devices = 1U;
    s.identities.executables = 3U;
    s.identities.processes = 4U;
    s.reviews.healthy = true;
    s.reviews.records = 5U;
    s.reviews.pending = 0U;
    return s;
}

std::vector<guff::RingReleaseEvidence> full_evidence() {
    std::vector<guff::RingReleaseEvidence> out;
    for (const auto& name : guff::RingReleaseGate::required_evidence_names()) {
        out.push_back({name, true, guff::sha256("evidence:" + name), "verified"});
    }
    return out;
}

bool has_blocker(const guff::RingReleaseResult& result, const std::string& needle) {
    return std::any_of(result.blockers.begin(), result.blockers.end(),
                       [&](const std::string& value) { return value.find(needle) != std::string::npos; });
}

} // namespace

int main() {
    guff::RingReleaseGate gate;
    auto snapshot = healthy_snapshot();
    auto evidence = full_evidence();

    const auto ready = gate.evaluate(snapshot, evidence);
    CHECK(ready.ready());
    CHECK(ready.status == guff::RingReleaseStatus::Ready);
    CHECK(ready.release_id.starts_with("guff:ring-release:sha256:"));
    CHECK(ready.blockers.empty());
    CHECK(ready.checks == 20U);

    auto reversed = evidence;
    std::reverse(reversed.begin(), reversed.end());
    const auto reordered = gate.evaluate(snapshot, reversed);
    CHECK(reordered.ready());
    CHECK(reordered.release_id == ready.release_id);

    auto failed_evidence = evidence;
    failed_evidence.front().passed = false;
    const auto failed = gate.evaluate(snapshot, failed_evidence);
    CHECK(failed.status == guff::RingReleaseStatus::Blocked);
    CHECK(has_blocker(failed, "required release evidence passed"));

    auto missing = evidence;
    missing.pop_back();
    const auto missing_result = gate.evaluate(snapshot, missing);
    CHECK(missing_result.status == guff::RingReleaseStatus::Blocked);
    CHECK(has_blocker(missing_result, "required release evidence present"));

    auto no_policy = snapshot;
    no_policy.policy.active_policy_id.clear();
    no_policy.active_policy.reset();
    const auto no_policy_result = gate.evaluate(no_policy, evidence);
    CHECK(no_policy_result.status == guff::RingReleaseStatus::Blocked);
    CHECK(has_blocker(no_policy_result, "active signed policy"));

    auto interrupted = snapshot;
    interrupted.recovery.interrupted.push_back({
        .session_id = "guff:session:sha256:" + guff::sha256("interrupted"),
        .correlation_id = "correlation-interrupted",
        .request_sha256 = guff::sha256("request"),
        .begin_record_sha256 = guff::sha256("begin"),
        .recorded_at_utc = "2026-09-06T05:00:00Z",
    });
    const auto interrupted_result = gate.evaluate(interrupted, evidence);
    CHECK(interrupted_result.status == guff::RingReleaseStatus::Blocked);
    CHECK(has_blocker(interrupted_result, "interrupted transaction"));

    auto pending = snapshot;
    pending.reviews.pending = 1U;
    const auto pending_result = gate.evaluate(pending, evidence);
    CHECK(pending_result.status == guff::RingReleaseStatus::Blocked);
    CHECK(has_blocker(pending_result, "HUMAN_REVIEW"));

    auto corrupt = snapshot;
    corrupt.authority.healthy = false;
    corrupt.healthy = false;
    const auto corrupt_result = gate.evaluate(corrupt, evidence);
    CHECK(corrupt_result.status == guff::RingReleaseStatus::Blocked);
    CHECK(has_blocker(corrupt_result, "authority ledger"));

    auto duplicate = evidence;
    duplicate.push_back(duplicate.front());
    CHECK(gate.evaluate(snapshot, duplicate).status == guff::RingReleaseStatus::Invalid);

    auto malformed = evidence;
    malformed.front().evidence_sha256 = "not-a-sha256";
    CHECK(gate.evaluate(snapshot, malformed).status == guff::RingReleaseStatus::Invalid);

    guff::RingReleaseGate tiny({.max_evidence = 1U, .max_blockers = 8U, .max_detail_bytes = 128U});
    CHECK(tiny.evaluate(snapshot, evidence).status == guff::RingReleaseStatus::Invalid);

    guff::RingReleaseGate zero({.max_evidence = 0U, .max_blockers = 8U, .max_detail_bytes = 128U});
    CHECK(zero.evaluate(snapshot, {}).status == guff::RingReleaseStatus::Invalid);

    return 0;
}
