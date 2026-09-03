#include "guff/dojo.hpp"
#include "guff/sha256.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

int main() {
    const auto temp = std::filesystem::temp_directory_path() / "guff-dojo-l8-test.store";
    const auto export_path = std::filesystem::temp_directory_path() / "guff-dojo-l8-test.jsonl";
    std::filesystem::remove(temp);
    std::filesystem::remove(export_path);

    guff::ZenkaiResult success;
    success.final_state = "SECRET RAW CANDIDATE";
    success.stop_reason = guff::ZenkaiStopReason::Verified;
    success.verified = true;
    success.attempts = 2U;
    success.evidence_items = 3U;
    success.tool_events = 3U;

    auto first = guff::make_dojo_episode(
        guff::TaskClass::Coding,
        "cpp-build-repair-v1",
        "guff:hardware:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "guff:model:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "SELECTED",
        success,
        "SECRET ROUTE TRACE",
        "build repaired after bounded retry",
        "2026-09-03T09:30:00Z",
        {"coding", "repair"});

    assert(first.episode_id.starts_with("guff:dojo:sha256:"));
    assert(first.validate().empty());
    assert(first.outcome == guff::DojoOutcome::Success);

    auto reordered = first;
    reordered.episode_id.clear();
    reordered.tags = {"repair", "coding"};
    assert(reordered.immutable_id() == first.immutable_id());

    guff::DojoStore store(temp);
    const auto append_first = store.append(first);
    assert(append_first.ok());
    assert(store.append(first).status == guff::DojoStoreStatus::Duplicate);

    guff::ZenkaiResult failed;
    failed.final_state = "FAILED RAW CANDIDATE";
    failed.stop_reason = guff::ZenkaiStopReason::NoNewInformation;
    failed.verified = false;
    failed.attempts = 1U;
    failed.evidence_items = 1U;
    failed.tool_events = 1U;

    auto second = guff::make_dojo_episode(
        guff::TaskClass::Coding,
        "cpp-build-repair-v1",
        first.hardware_id,
        first.model_id,
        "SELECTED",
        failed,
        "FAILED ROUTE TRACE",
        "repair stalled with no new information",
        "2026-09-03T09:31:00Z",
        {"coding", "failure"});
    assert(second.outcome == guff::DojoOutcome::Failure);
    assert(store.append(second).ok());

    auto third = first;
    third.episode_id.clear();
    third.summary = "second successful repair episode";
    third.recorded_at_utc = "2026-09-03T09:32:00Z";
    third.outcome_sha256 = guff::sha256("different successful outcome");
    third.episode_id = third.immutable_id();
    assert(store.append(third).ok());

    guff::DojoQuery latest_success;
    latest_success.task = guff::TaskClass::Coding;
    latest_success.outcome = guff::DojoOutcome::Success;
    latest_success.verified_only = true;
    latest_success.limit = 1U;
    const auto replayed = store.replay(latest_success);
    assert(replayed.size() == 1U);
    assert(replayed.front().episode_id == third.episode_id);

    std::ifstream raw_input(temp, std::ios::binary);
    const std::string raw((std::istreambuf_iterator<char>(raw_input)), std::istreambuf_iterator<char>());
    assert(raw.find("SECRET RAW CANDIDATE") == std::string::npos);
    assert(raw.find("SECRET ROUTE TRACE") == std::string::npos);
    assert(raw.find("FAILED RAW CANDIDATE") == std::string::npos);

    std::vector<std::string> export_errors;
    guff::DojoQuery export_query;
    export_query.task = guff::TaskClass::Coding;
    export_query.limit = 8U;
    assert(store.export_jsonl(export_path, export_query, &export_errors));
    assert(export_errors.empty());
    std::ifstream export_input(export_path, std::ios::binary);
    const std::string exported((std::istreambuf_iterator<char>(export_input)), std::istreambuf_iterator<char>());
    assert(exported.find("build repaired after bounded retry") != std::string::npos);
    assert(exported.find("SECRET RAW CANDIDATE") == std::string::npos);
    assert(exported.find("route_trace_sha256") != std::string::npos);

    auto invalid = first;
    invalid.episode_id.clear();
    invalid.final_state_sha256 = "not-a-digest";
    assert(store.append(invalid).status == guff::DojoStoreStatus::Invalid);

    {
        std::ofstream corrupt(temp, std::ios::binary | std::ios::app);
        corrupt << "D\tbroken\n";
    }
    std::vector<std::string> replay_errors;
    guff::DojoQuery replay_all;
    replay_all.limit = 8U;
    const auto all = store.replay(replay_all, &replay_errors);
    assert(all.size() == 3U);
    assert(!replay_errors.empty());

    std::filesystem::remove(temp);
    std::filesystem::remove(export_path);
    std::cout << "DOJO L8 regression passed\n";
    return 0;
}
