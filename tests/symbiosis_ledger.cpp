#include "guff/symbiosis_ledger.hpp"
#include "guff/sha256.hpp"

#include <cassert>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace {

guff::SourceObservation observation_for(const guff::SymbiosisGrant& grant,
                                        std::string locator,
                                        std::string content,
                                        std::uint64_t size) {
    guff::SourceObservation observation;
    observation.kind = grant.source.kind;
    observation.layer = grant.source.layer;
    observation.locator = std::move(locator);
    observation.size_bytes = size;
    observation.content_sha256 = guff::sha256(content);
    observation.source_id = "guff:source:sha256:" +
        guff::sha256(grant.source.grant_id + "\n" + observation.locator);
    return observation;
}

guff::SymbiosisGrant persistent_grant() {
    guff::SymbiosisGrant grant;
    grant.source.grant_id = "project-tools";
    grant.source.kind = guff::SourceKind::ToolOutput;
    grant.source.scope = guff::GrantScope::Project;
    grant.source.layer = guff::RealityLayer::Runtime;
    grant.source.locator_prefix = "tool://build/";
    grant.source.max_source_bytes = 1024U * 1024U;
    grant.source.max_slice_bytes = 4096U;
    grant.retention.persist_grant = true;
    grant.retention.persist_observation_stamps = true;
    grant.retention.allow_memory_promotion = true;
    grant.retention.max_promotion_bytes = 128U;
    grant.retention.max_observation_stamps = 2U;
    grant.issued_at_unix_ms = 1000U;
    grant.expires_at_unix_ms = 0U;
    return grant;
}

} // namespace

int main() {
    const auto journal = std::filesystem::temp_directory_path() / "guff-l6-symbiosis-ledger.store";
    std::error_code ec;
    std::filesystem::remove(journal, ec);

    auto grant = persistent_grant();
    guff::SymbiosisLedger ledger(journal);

    const auto created = ledger.create_grant(grant);
    assert(created.ok());
    assert(ledger.grant_count() == 1U);
    assert(ledger.grant_state(grant.source.grant_id, 1001U) == guff::GrantState::Active);
    assert(ledger.create_grant(grant).status == guff::LedgerStatus::Duplicate);

    const auto obs1 = observation_for(grant, "tool://build/1", "first", 5U);
    const auto obs2 = observation_for(grant, "tool://build/2", "second", 6U);
    const auto obs3 = observation_for(grant, "tool://build/3", "third", 5U);

    assert(ledger.stamp_observation(grant.source.grant_id, obs1, 1100U).ok());
    assert(ledger.stamp_observation(grant.source.grant_id, obs2, 1200U).ok());
    assert(ledger.stamp_observation(grant.source.grant_id, obs3, 1300U).ok());
    assert(ledger.stamp_count() == 2U);
    assert(ledger.observation_stamps(grant.source.grant_id).front().source_id == obs2.source_id);

    const auto promoted = ledger.promote_memory(
        grant.source.grant_id, obs3, "Compiler output says the C++ target is now green.", 1400U);
    assert(promoted.ok());
    assert(promoted.id.starts_with("guff:memory:sha256:"));
    assert(ledger.promotion_count() == 1U);
    assert(ledger.promotions().size() == 1U);

    auto forged = obs3;
    forged.source_id = "guff:source:sha256:" + guff::sha256("forged");
    assert(ledger.stamp_observation(grant.source.grant_id, forged, 1450U).status ==
           guff::LedgerStatus::Denied);

    assert(ledger.forget_promotion(promoted.id, 1500U).ok());
    assert(ledger.promotions().empty());
    assert(ledger.promotions(true).size() == 1U);

    assert(ledger.revoke_grant(grant.source.grant_id, 1600U, "user disabled project symbiosis").ok());
    assert(ledger.grant_state(grant.source.grant_id, 1601U) == guff::GrantState::Revoked);
    assert(ledger.stamp_observation(grant.source.grant_id, obs3, 1700U).status ==
           guff::LedgerStatus::Inactive);

    guff::SymbiosisLedger replayed(journal);
    std::vector<std::string> replay_errors;
    assert(replayed.replay(&replay_errors));
    assert(replay_errors.empty());
    assert(replayed.grant_count() == 1U);
    assert(replayed.grant_state(grant.source.grant_id, 2000U) == guff::GrantState::Revoked);
    assert(replayed.stamp_count() == 2U);
    assert(replayed.promotions().empty());
    assert(replayed.promotions(true).size() == 1U);
    assert(replayed.promotions(true).front().forgotten);

    guff::SymbiosisGrant expiring = grant;
    expiring.source.grant_id = "session-only";
    expiring.retention.persist_grant = false;
    expiring.retention.persist_observation_stamps = false;
    expiring.retention.allow_memory_promotion = false;
    expiring.issued_at_unix_ms = 10U;
    expiring.expires_at_unix_ms = 20U;

    guff::SymbiosisLedger ephemeral;
    assert(ephemeral.create_grant(expiring).ok());
    assert(ephemeral.grant_state("session-only", 9U) == guff::GrantState::Pending);
    assert(ephemeral.grant_state("session-only", 19U) == guff::GrantState::Active);
    assert(ephemeral.grant_state("session-only", 20U) == guff::GrantState::Expired);

    std::filesystem::remove(journal, ec);
    return 0;
}
