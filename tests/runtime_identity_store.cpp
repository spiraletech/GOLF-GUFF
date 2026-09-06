#include "guff/runtime_identity_store.hpp"
#include "guff/sha256.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "CHECK failed: " #expression << " @ " << __FILE__ << ':' << __LINE__ << '\n'; return 1; } } while (false)

namespace {

std::uint64_t wall_now_ms() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

guff::RuntimeAttestationRequest request_for(std::string challenge,
                                             std::string slot = "xenon.audio",
                                             std::string session_seed = "l22-session") {
    guff::RuntimeAttestationRequest request;
    request.slot_id = std::move(slot);
    request.session_id = "guff:session:sha256:" + guff::sha256(session_seed);
    request.layer = guff::RealityLayer::Runtime;
    request.challenge_nonce = std::move(challenge);
    request.max_age_ms = 3'000U;
    return request;
}

std::string read_all(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

} // namespace

int main() {
#if !defined(_WIN32) && !defined(__linux__)
    return 0;
#else
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-l22-runtime-identity-store");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);

    const std::uint64_t now = wall_now_ms();
    guff::NativeRuntimeAttestationProvider native([&]() { return now; });
    guff::RuntimeIdentityStore store(root / "identity.journal");
    guff::IdentityTrackingRuntimeAttestationProvider tracked(native, store);

    const auto request_a = request_for("l22-challenge-a");
    auto first = tracked.attest(request_a);
    CHECK(first.ok());
    CHECK(first.evidence);
    CHECK(store.identity_active(*first.evidence));

    auto inspection = store.inspect();
    CHECK(inspection.healthy);
    CHECK(inspection.records == 1U);
    CHECK(inspection.devices == 1U);
    CHECK(inspection.executables == 1U);
    CHECK(inspection.processes == 1U);
    CHECK(inspection.attestations == 1U);

    const auto device_record_id = guff::runtime_device_identity_id(
        first.evidence->provider_id, first.evidence->binding.device_id);
    const auto executable_record_id = guff::runtime_executable_identity_id(
        first.evidence->binding.executable_sha256);
    const auto process_record_id = guff::runtime_process_identity_id(
        first.evidence->provider_id, first.evidence->binding.process_instance_sha256);
    CHECK(store.device(device_record_id));
    CHECK(store.executable(executable_record_id));
    CHECK(store.process(process_record_id));
    CHECK(store.attestation(first.evidence->attestation_id));

    // Exact duplicate evidence is idempotent and does not grow the journal.
    auto duplicate = tracked.attest(request_a);
    CHECK(duplicate.ok());
    CHECK(duplicate.evidence->attestation_id == first.evidence->attestation_id);
    CHECK(store.inspect().records == 1U);
    CHECK(store.inspect().attestations == 1U);

    // New challenge/context creates a new observation, but the native process identity stays one entity.
    const auto request_b = request_for(
        "l22-challenge-b", "xenon.audio", "l22-session-b");
    auto second = tracked.attest(request_b);
    CHECK(second.ok());
    CHECK(second.evidence);
    CHECK(second.evidence->attestation_id != first.evidence->attestation_id);
    CHECK(second.evidence->binding.device_id == first.evidence->binding.device_id);
    CHECK(second.evidence->binding.executable_sha256 == first.evidence->binding.executable_sha256);
    CHECK(second.evidence->binding.process_instance_sha256 ==
          first.evidence->binding.process_instance_sha256);
    CHECK(store.inspect().devices == 1U);
    CHECK(store.inspect().executables == 1U);
    CHECK(store.inspect().processes == 1U);
    CHECK(store.inspect().attestations == 2U);
    CHECK(store.device(device_record_id)->observations == 2U);
    CHECK(store.executable(executable_record_id)->observations == 2U);
    CHECK(store.process(process_record_id)->observations == 2U);

    // Raw challenges are not retained by the cold identity journal.
    const auto journal_text = read_all(root / "identity.journal");
    CHECK(journal_text.find("l22-challenge-a") == std::string::npos);
    CHECK(journal_text.find("l22-challenge-b") == std::string::npos);

    // Process revocation blocks fresh evidence from the same OS process.
    CHECK(store.revoke_process(process_record_id, now + 1U, "operator-revoke").ok());
    CHECK(!store.identity_active(*second.evidence));
    auto after_process_revoke = tracked.attest(request_for("l22-challenge-c"));
    CHECK(!after_process_revoke.ok());
    CHECK(after_process_revoke.status == guff::RuntimeAttestationStatus::EvidenceInvalid);
    CHECK(store.inspect().attestations == 2U);
    CHECK(store.inspect().revoked_processes == 1U);

    // Cold replay preserves identity continuity and revocation state.
    guff::RuntimeIdentityStore reopened(root / "identity.journal");
    CHECK(reopened.inspect().healthy);
    CHECK(reopened.inspect().devices == 1U);
    CHECK(reopened.inspect().executables == 1U);
    CHECK(reopened.inspect().processes == 1U);
    CHECK(reopened.inspect().attestations == 2U);
    CHECK(reopened.inspect().revoked_processes == 1U);
    CHECK(reopened.process(process_record_id)->revoked());
    guff::IdentityTrackingRuntimeAttestationProvider reopened_tracked(native, reopened);
    auto after_restart = reopened_tracked.attest(request_for("l22-challenge-d"));
    CHECK(!after_restart.ok());
    CHECK(after_restart.status == guff::RuntimeAttestationStatus::EvidenceInvalid);

    // Device and executable revocation are independently enforceable identity facts.
    guff::RuntimeIdentityStore device_store(root / "device-revoke.journal");
    guff::IdentityTrackingRuntimeAttestationProvider device_tracked(native, device_store);
    auto device_observation = device_tracked.attest(request_for("l22-device-a"));
    CHECK(device_observation.ok());
    const auto device_id = guff::runtime_device_identity_id(
        device_observation.evidence->provider_id,
        device_observation.evidence->binding.device_id);
    CHECK(device_store.revoke_device(device_id, now + 2U, "device-retired").ok());
    CHECK(!device_tracked.attest(request_for("l22-device-b")).ok());
    CHECK(device_store.inspect().revoked_devices == 1U);

    guff::RuntimeIdentityStore image_store(root / "image-revoke.journal");
    guff::IdentityTrackingRuntimeAttestationProvider image_tracked(native, image_store);
    auto image_observation = image_tracked.attest(request_for("l22-image-a"));
    CHECK(image_observation.ok());
    const auto image_id = guff::runtime_executable_identity_id(
        image_observation.evidence->binding.executable_sha256);
    CHECK(image_store.revoke_executable(image_id, now + 3U, "image-denied").ok());
    CHECK(!image_tracked.attest(request_for("l22-image-b")).ok());
    CHECK(image_store.inspect().revoked_executables == 1U);

    // Provider identity is part of device/process identity; executable content identity is provider-independent.
    CHECK(guff::runtime_device_identity_id("provider-a", first.evidence->binding.device_id) !=
          guff::runtime_device_identity_id("provider-b", first.evidence->binding.device_id));
    CHECK(guff::runtime_process_identity_id("provider-a", first.evidence->binding.process_instance_sha256) !=
          guff::runtime_process_identity_id("provider-b", first.evidence->binding.process_instance_sha256));
    CHECK(guff::runtime_executable_identity_id(first.evidence->binding.executable_sha256) ==
          guff::runtime_executable_identity_id(second.evidence->binding.executable_sha256));

    // Capacity is a hard memory-light boundary and refuses before creating a second observation.
    guff::RuntimeIdentityStoreBudget tiny_budget;
    tiny_budget.max_devices = 1U;
    tiny_budget.max_executables = 1U;
    tiny_budget.max_processes = 1U;
    tiny_budget.max_attestations = 1U;
    guff::RuntimeIdentityStore tiny(root / "tiny.journal", tiny_budget);
    guff::IdentityTrackingRuntimeAttestationProvider tiny_tracked(native, tiny);
    CHECK(tiny_tracked.attest(request_for("l22-tiny-a")).ok());
    auto tiny_second = tiny_tracked.attest(request_for("l22-tiny-b"));
    CHECK(!tiny_second.ok());
    CHECK(tiny.inspect().attestations == 1U);
    CHECK(tiny.inspect().records == 1U);

    // Hash-chain corruption fails closed across restart.
    const auto corrupt_path = root / "corrupt.journal";
    guff::RuntimeIdentityStore corrupt_writer(corrupt_path);
    guff::IdentityTrackingRuntimeAttestationProvider corrupt_tracked(native, corrupt_writer);
    CHECK(corrupt_tracked.attest(request_for("l22-corrupt-a")).ok());
    {
        std::ofstream output(corrupt_path, std::ios::binary | std::ios::app);
        CHECK(output.good());
        output << "tampered-tail\n";
    }
    guff::RuntimeIdentityStore corrupt_reopened(corrupt_path);
    CHECK(!corrupt_reopened.inspect().healthy);
    guff::IdentityTrackingRuntimeAttestationProvider corrupt_provider(native, corrupt_reopened);
    auto corrupt_result = corrupt_provider.attest(request_for("l22-corrupt-b"));
    CHECK(!corrupt_result.ok());
    CHECK(corrupt_result.status == guff::RuntimeAttestationStatus::EvidenceInvalid);

    std::filesystem::remove_all(root, ec);
    return 0;
#endif
}
