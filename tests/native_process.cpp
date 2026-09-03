#include "guff/clubhouse.hpp"
#include "guff/forge.hpp"
#include "guff/native_process.hpp"
#include "guff/sha256.hpp"

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

guff::SlotManifest process_slot(std::string name) {
    guff::SlotManifest slot;
    slot.slot_name = std::move(name);
    slot.display_name = "Native Process Test Slot";
    slot.version = "1.0.0";
    slot.kind = guff::SlotKind::Compiler;
    slot.transport = guff::SlotTransport::LocalProcess;
    slot.entrypoint = "native://self-test";
    slot.capabilities = {guff::SlotCapability::CodeBuild};
    slot.allowed_layers = {guff::RealityLayer::Project};
    slot.required_permissions = {"code:build", "device:execute"};
    slot.max_payload_bytes = 16U * 1024U;
    return slot;
}

guff::ForgeExecutionRequest request_for(std::string slot_name,
                                        std::string payload,
                                        std::uint64_t wall_ms = 1000U,
                                        std::size_t output_bytes = 4096U) {
    guff::ForgeExecutionRequest request;
    request.invocation.invocation_id = "native-" + slot_name;
    request.invocation.slot_id = std::move(slot_name);
    request.invocation.capability = guff::SlotCapability::CodeBuild;
    request.invocation.layer = guff::RealityLayer::Project;
    request.invocation.input_sha256 = guff::sha256(payload);
    request.invocation.payload_bytes = payload.size();
    request.invocation.permission_tokens = {"code:build", "device:execute"};
    request.payload = std::move(payload);
    request.budget.max_wall_time_ms = wall_ms;
    request.budget.max_output_bytes = output_bytes;
    return request;
}

guff::NativeProcessBinding binding_for(const std::filesystem::path& executable,
                                       const std::filesystem::path& root,
                                       std::string child_mode,
                                       guff::NativePayloadMode payload_mode = guff::NativePayloadMode::SingleArgument) {
    guff::NativeProcessBinding binding;
    binding.executable = executable;
    binding.arguments = {std::move(child_mode)};
    binding.payload_mode = payload_mode;
    binding.working_root = root;
    binding.working_directory = root / "work";
    binding.environment = {{"GUFF_TEST_ENV", "bounded"}};
    binding.limits.max_arguments = 8U;
    binding.limits.max_argument_bytes = 16U * 1024U;
    binding.limits.max_environment_entries = 8U;
    binding.limits.max_environment_bytes = 4096U;
    return binding;
}

} // namespace

int main(int argc, char** argv) {
    if (argc >= 2) {
        const std::string mode = argv[1];
        if (mode == "--guff-child-echo") {
            const std::string argument = argc >= 3 ? argv[2] : "";
            const char* environment = std::getenv("GUFF_TEST_ENV");
            std::cout << "ARG:" << argument << '\n';
            std::cout << "ENV:" << (environment ? environment : "missing") << '\n';
            std::cout << "CWD:" << std::filesystem::current_path().string() << '\n';
            std::cerr << "STDERR:streamed" << '\n';
            return 0;
        }
        if (mode == "--guff-child-sleep") {
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            std::cout << "late" << '\n';
            return 0;
        }
        if (mode == "--guff-child-fail") {
            std::cerr << "intentional failure" << '\n';
            return 7;
        }
        if (mode == "--guff-child-spam") {
            std::cout << std::string(8192U, 'x');
            return 0;
        }
    }

    const auto executable = std::filesystem::absolute(argv[0]);
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-native-process-regression");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root / "work");

    guff::ClubhouseRegistry clubhouse;
    guff::NativeProcessRegistry processes;

    const auto echo_slot = process_slot("forge.native.echo");
    assert(clubhouse.register_slot(echo_slot));
    std::vector<std::string> errors;
    const auto echo_binding = binding_for(executable, root, "--guff-child-echo");
    assert(echo_binding.validate().empty());
    assert(processes.bind(echo_slot, echo_binding, &errors));
    assert(errors.empty());
    assert(processes.size() == 1U);
    assert(processes.find(echo_slot.immutable_id()).has_value());

    errors.clear();
    assert(!processes.bind(echo_slot, echo_binding, &errors));
    assert(!errors.empty());

    const std::string literal_payload = "literal & | < > ^ % ! \"quoted\" \\ tail";
    auto echo_request = request_for(echo_slot.slot_name, literal_payload);
    guff::NativeLocalProcessExecutor native(processes);

    guff::ForgeOutputSink direct_output(4096U);
    const auto direct_report = native(echo_slot, echo_request, direct_output);
    assert(direct_report.completed);
    assert(direct_report.exit_code == 0);
    const std::string direct_text(direct_output.captured());
    assert(direct_text.find("ARG:" + literal_payload) != std::string::npos);
    assert(direct_text.find("ENV:bounded") != std::string::npos);
    assert(direct_text.find("STDERR:streamed") != std::string::npos);
    assert(direct_text.find("CWD:") != std::string::npos);

    guff::ForgeAdapter forge(clubhouse);
    const auto integrated = forge.execute(echo_request, native);
    assert(integrated.succeeded());
    assert(integrated.status == guff::ForgeStatus::Completed);
    assert(integrated.exit_code == 0);
    assert(guff::is_sha256(integrated.captured_output_sha256));
    assert(integrated.evidence.size() == 1U);
    assert(integrated.evidence.front().kind == guff::EvidenceKind::Build);
    assert(integrated.evidence.front().passed);
    assert(integrated.evidence.front().detail.find(literal_payload) == std::string::npos);

    const auto sleep_slot = process_slot("forge.native.sleep");
    assert(clubhouse.register_slot(sleep_slot));
    assert(processes.bind(
        sleep_slot,
        binding_for(executable, root, "--guff-child-sleep", guff::NativePayloadMode::None)));
    const auto timeout = forge.execute(request_for(sleep_slot.slot_name, "", 40U, 4096U), native);
    assert(timeout.status == guff::ForgeStatus::Timeout);
    assert(!timeout.evidence.empty());
    assert(!timeout.evidence.front().passed);

    const auto fail_slot = process_slot("forge.native.fail");
    assert(clubhouse.register_slot(fail_slot));
    assert(processes.bind(
        fail_slot,
        binding_for(executable, root, "--guff-child-fail", guff::NativePayloadMode::None)));
    const auto failure = forge.execute(request_for(fail_slot.slot_name, ""), native);
    assert(failure.status == guff::ForgeStatus::ExecutionFailed);
    assert(failure.exit_code == 7);

    const auto spam_slot = process_slot("forge.native.spam");
    assert(clubhouse.register_slot(spam_slot));
    assert(processes.bind(
        spam_slot,
        binding_for(executable, root, "--guff-child-spam", guff::NativePayloadMode::None)));
    const auto overflow = forge.execute(request_for(spam_slot.slot_name, "", 1000U, 128U), native);
    assert(overflow.status == guff::ForgeStatus::OutputBudget);
    assert(overflow.output_truncated);
    assert(overflow.captured_output_bytes == 128U);
    assert(overflow.observed_output_bytes > overflow.captured_output_bytes);

    auto escaped = echo_binding;
    escaped.working_directory = std::filesystem::absolute(root / "..");
    const auto escaped_errors = escaped.validate();
    assert(!escaped_errors.empty());

    auto bad_environment = echo_binding;
    bad_environment.environment = {{"NOT VALID", "x"}};
    assert(!bad_environment.validate().empty());

    auto connector_slot = echo_slot;
    connector_slot.slot_name = "forge.connector.invalid";
    connector_slot.transport = guff::SlotTransport::Connector;
    errors.clear();
    assert(!processes.bind(connector_slot, echo_binding, &errors));
    assert(!errors.empty());

    auto argument_limited_slot = process_slot("forge.native.arg-limit");
    assert(clubhouse.register_slot(argument_limited_slot));
    auto argument_limited = binding_for(executable, root, "--guff-child-echo");
    argument_limited.limits.max_argument_bytes = 32U;
    assert(processes.bind(argument_limited_slot, argument_limited));
    const auto too_large = forge.execute(
        request_for(argument_limited_slot.slot_name, std::string(128U, 'a')),
        native);
    assert(too_large.status == guff::ForgeStatus::ExecutorError);

    std::filesystem::remove_all(root, ec);
    return 0;
}
