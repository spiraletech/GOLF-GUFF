#include "guff/hardware_profile.hpp"
#include "guff/scorecard.hpp"
#include "guff/sha256.hpp"

#include <cassert>
#include <string>
#include <utility>
#include <vector>

namespace {

guff::BenchmarkRecord record_for(const guff::HardwareProfile& hardware,
                                  std::string run_id,
                                  std::string model_seed,
                                  double accuracy,
                                  double generation_tps,
                                  double ttft_ms,
                                  double ram_mb,
                                  std::uint32_t retries) {
    guff::BenchmarkRecord record;
    record.run_id = std::move(run_id);
    record.model_id = "guff:model:sha256:" + guff::sha256(model_seed);
    record.hardware_id = hardware.immutable_id();
    record.task = guff::TaskClass::Coding;
    record.profile_name = "cpp-build-repair-v1";
    record.context_tokens = 4096;
    record.output_tokens = 512;
    record.metrics.prompt_tokens_per_second = generation_tps * 2.0;
    record.metrics.generation_tokens_per_second = generation_tps;
    record.metrics.time_to_first_token_ms = ttft_ms;
    record.metrics.wall_time_ms = 5000.0;
    record.metrics.peak_ram_mb = ram_mb;
    record.metrics.accuracy = accuracy;
    record.metrics.tool_success_rate = accuracy;
    record.metrics.verification_pass_rate = accuracy;
    record.metrics.retries = retries;
    record.metrics.completed = true;
    return record;
}

} // namespace

int main() {
    guff::HardwareProfile hardware;
    hardware.platform = guff::Platform::Linux;
    hardware.architecture = guff::CpuArchitecture::X86_64;
    hardware.logical_threads = 12;
    hardware.ram_mb = 16384;
    hardware.cpu_name = "GOLF TEST CPU";

    const auto id_a = hardware.immutable_id();
    const auto id_b = hardware.immutable_id();
    assert(id_a == id_b);
    assert(id_a.starts_with("guff:hardware:sha256:"));

    auto stronger = record_for(hardware, "run-strong", "model-strong", 0.96, 42.0, 180.0, 4200.0, 0);
    auto weaker = record_for(hardware, "run-weak", "model-weak", 0.72, 20.0, 900.0, 7000.0, 2);

    guff::Scorecard scorecard;
    std::vector<std::string> errors;
    assert(scorecard.add(stronger, &errors));
    assert(errors.empty());
    assert(scorecard.add(weaker, &errors));
    assert(scorecard.size() == 2);

    const auto ranked = scorecard.rank(guff::TaskClass::Coding, hardware);
    assert(ranked.size() == 2);
    assert(ranked[0].record.run_id == "run-strong");
    assert(ranked[0].score.total > ranked[1].score.total);

    const auto best = scorecard.best(guff::TaskClass::Coding, hardware);
    assert(best.has_value());
    assert(best->record.model_id == stronger.model_id);

    auto duplicate = stronger;
    assert(!scorecard.add(duplicate, &errors));
    assert(!errors.empty());

    auto invalid = record_for(hardware, "bad", "bad-model", 0.5, 10.0, 100.0, 1000.0, 0);
    invalid.metrics.accuracy = 1.2;
    assert(!scorecard.add(invalid, &errors));

    auto other_hardware = hardware;
    other_hardware.ram_mb = 32768;
    assert(scorecard.rank(guff::TaskClass::Coding, other_hardware).empty());

    return 0;
}
