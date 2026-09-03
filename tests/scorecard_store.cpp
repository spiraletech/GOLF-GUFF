#include "guff/scorecard_store.hpp"
#include "guff/sha256.hpp"

#include <cassert>
#include <filesystem>
#include <string>
#include <vector>

namespace {

guff::BenchmarkRecord make_record(const guff::HardwareProfile& hardware,
                                  std::string run_id,
                                  std::string model_seed,
                                  double accuracy,
                                  double generation_tps,
                                  std::string profile = "cpp-build-repair-v1") {
    guff::BenchmarkRecord record;
    record.run_id = std::move(run_id);
    record.model_id = "guff:model:sha256:" + guff::sha256(model_seed);
    record.hardware_id = hardware.immutable_id();
    record.task = guff::TaskClass::Coding;
    record.profile_name = std::move(profile);
    record.context_tokens = 4096U;
    record.output_tokens = 512U;
    record.recorded_at_utc = "2026-09-03T03:00:00Z";
    record.metrics.prompt_tokens_per_second = generation_tps * 2.0;
    record.metrics.generation_tokens_per_second = generation_tps;
    record.metrics.time_to_first_token_ms = 150.0;
    record.metrics.wall_time_ms = 4000.0;
    record.metrics.peak_ram_mb = 3000.0;
    record.metrics.accuracy = accuracy;
    record.metrics.tool_success_rate = accuracy;
    record.metrics.verification_pass_rate = accuracy;
    record.metrics.energy_wh = 1.0;
    record.metrics.retries = 0U;
    record.metrics.completed = true;
    record.tags = {"persisted", "tab\tnewline\n-safe"};
    return record;
}

} // namespace

int main() {
    guff::HardwareProfile hardware;
    hardware.platform = guff::Platform::Linux;
    hardware.architecture = guff::CpuArchitecture::X86_64;
    hardware.logical_threads = 12U;
    hardware.ram_mb = 16384U;
    hardware.cpu_name = "GOLF L4 TEST CPU";

    const auto path = std::filesystem::temp_directory_path() / "guff-l4-scorecard.store";
    std::error_code ec;
    std::filesystem::remove(path, ec);

    guff::ScorecardStore store(path);
    const auto strong = make_record(hardware, "run-strong", "model-strong", 0.97, 50.0);
    const auto medium = make_record(hardware, "run-medium", "model-medium", 0.84, 35.0);
    const auto weak = make_record(hardware, "run-weak", "model-weak", 0.68, 18.0);
    const auto wrong_profile = make_record(hardware, "run-other", "model-other", 0.99, 90.0, "python-edit-v1");

    assert(store.append(weak).ok());
    assert(store.append(strong).ok());
    assert(store.append(medium).ok());
    assert(store.append(wrong_profile).ok());

    const auto duplicate = store.append(strong);
    assert(duplicate.status == guff::ScorecardAppendStatus::Duplicate);
    assert(!duplicate.ok());

    guff::Scorecard hydrated;
    guff::ScorecardHydrationQuery query;
    query.hardware = hardware;
    query.task = guff::TaskClass::Coding;
    query.profile_name = "cpp-build-repair-v1";
    query.max_records = 2U;

    const auto report = store.hydrate(query, hydrated);
    assert(report.ok);
    assert(report.lines_scanned == 4U);
    assert(report.records_matched == 3U);
    assert(report.records_loaded == 2U);
    assert(report.truncated);
    assert(hydrated.size() == 2U);

    const auto ranked = hydrated.rank(guff::TaskClass::Coding, hardware);
    assert(ranked.size() == 2U);
    assert(ranked.front().record.run_id == "run-strong");
    assert(ranked[1].record.run_id == "run-medium");

    std::filesystem::remove(path, ec);
    return 0;
}
