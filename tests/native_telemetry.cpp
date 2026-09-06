#include "guff/clubhouse.hpp"
#include "guff/forge.hpp"
#include "guff/native_process.hpp"
#include "guff/sha256.hpp"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string_view>
#include <thread>
#include <vector>

namespace {

bool telemetry_child(int argc, char** argv) {
    return argc > 1 && std::string_view(argv[1]) == "--telemetry-child";
}

guff::SlotManifest telemetry_slot() {
    guff::SlotManifest slot;
    slot.slot_name = "l29.native.telemetry";
    slot.display_name = "L29 Native Telemetry Probe";
    slot.version = "1.0.0";
    slot.kind = guff::SlotKind::Tool;
    slot.transport = guff::SlotTransport::LocalProcess;
    slot.entrypoint = "native://telemetry-probe";
    slot.capabilities = {guff::SlotCapability::GenericTool};
    slot.allowed_layers = {guff::RealityLayer::Application};
    slot.required_permissions = {"device:execute"};
    slot.max_payload_bytes = 4096U;
    return slot;
}

} // namespace

int main(int argc, char** argv) {
    if (telemetry_child(argc, argv)) {
        constexpr std::size_t bytes = 16U * 1024U * 1024U;
        std::vector<unsigned char> resident(bytes, 0U);
        for (std::size_t i = 0U; i < resident.size(); i += 4096U) resident[i] = 0xA5U;
        if (resident.front() != 0xA5U) return 9;
        std::this_thread::sleep_for(std::chrono::milliseconds(35));
        std::cout << "L29_TELEMETRY_OK" << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
        return 0;
    }

    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-l29-native-telemetry");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root);

    guff::ClubhouseRegistry clubhouse;
    const auto slot = telemetry_slot();
    assert(clubhouse.register_slot(slot));

    guff::NativeProcessRegistry processes;
    guff::NativeProcessBinding binding;
    binding.executable = std::filesystem::absolute(argv[0]);
    binding.arguments = {"--telemetry-child"};
    binding.payload_mode = guff::NativePayloadMode::None;
    binding.working_root = root;
    binding.working_directory = root;
    assert(processes.bind(slot, binding));

    guff::ForgeExecutionRequest request;
    request.invocation.invocation_id = "l29-native-telemetry-001";
    request.invocation.slot_id = slot.slot_name;
    request.invocation.capability = guff::SlotCapability::GenericTool;
    request.invocation.layer = guff::RealityLayer::Application;
    request.payload = "measure-child-process";
    request.invocation.input_sha256 = guff::sha256(request.payload);
    request.invocation.payload_bytes = request.payload.size();
    request.invocation.permission_tokens = {"device:execute"};
    request.budget.max_wall_time_ms = 5000U;
    request.budget.max_output_bytes = 4096U;

    guff::NativeLocalProcessExecutor native(processes);
    guff::ForgeAdapter forge(clubhouse);
    const auto result = forge.execute(
        request,
        [&](const guff::SlotManifest& executing_slot,
            const guff::ForgeExecutionRequest& executing_request,
            guff::ForgeOutputSink& output) {
            return native(executing_slot, executing_request, output);
        });

    assert(result.succeeded());
    assert(result.first_output_observed);
    assert(result.time_to_first_output_ms >= 20U);
    assert(result.time_to_first_output_ms <= result.wall_time_ms);
    assert(result.captured_output_sha256 == guff::sha256("L29_TELEMETRY_OK"));

#if defined(_WIN32) || defined(__linux__)
    assert(result.process_memory_observed);
    assert(result.peak_resident_memory_bytes >= 4U * 1024U * 1024U);
#endif

    std::filesystem::remove_all(root, ec);
    return 0;
}
