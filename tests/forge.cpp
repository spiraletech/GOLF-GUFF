#include "guff/clubhouse.hpp"
#include "guff/forge.hpp"
#include "guff/sha256.hpp"

#include <cassert>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

guff::SlotManifest compiler_manifest() {
    guff::SlotManifest slot;
    slot.slot_name = "forge.compiler";
    slot.display_name = "FORGE Compiler Adapter";
    slot.version = "1.0.0";
    slot.kind = guff::SlotKind::Compiler;
    slot.transport = guff::SlotTransport::LocalProcess;
    slot.entrypoint = "forge://compiler";
    slot.capabilities = {guff::SlotCapability::CodeBuild, guff::SlotCapability::CodeTest};
    slot.allowed_layers = {guff::RealityLayer::Project, guff::RealityLayer::Runtime};
    slot.required_permissions = {"code:build", "device:execute"};
    slot.max_payload_bytes = 4096U;
    return slot;
}

guff::ForgeExecutionRequest build_request(std::string payload) {
    guff::ForgeExecutionRequest request;
    request.invocation.invocation_id = "forge-build-1";
    request.invocation.slot_id = "forge.compiler";
    request.invocation.capability = guff::SlotCapability::CodeBuild;
    request.invocation.layer = guff::RealityLayer::Project;
    request.invocation.input_sha256 = guff::sha256(payload);
    request.invocation.payload_bytes = payload.size();
    request.invocation.permission_tokens = {"code:build", "device:execute"};
    request.payload = std::move(payload);
    request.budget.max_wall_time_ms = 1000U;
    request.budget.max_output_bytes = 64U;
    return request;
}

} // namespace

int main() {
    guff::ClubhouseRegistry clubhouse;
    assert(clubhouse.register_slot(compiler_manifest()));
    guff::ForgeAdapter forge(clubhouse);

    auto request = build_request("build target guff_core");
    bool called = false;
    const auto success = forge.execute(
        request,
        [&called](const guff::SlotManifest& slot,
                  const guff::ForgeExecutionRequest& execution,
                  guff::ForgeOutputSink& output) {
            called = true;
            assert(slot.slot_name == "forge.compiler");
            assert(execution.invocation.capability == guff::SlotCapability::CodeBuild);
            assert(output.write("build ok"));
            return guff::ForgeExecutorReport{true, 0, 25U};
        });
    assert(called);
    assert(success.succeeded());
    assert(success.invocation_status == guff::InvocationStatus::Ready);
    assert(success.exit_code == 0);
    assert(success.captured_output_bytes == 8U);
    assert(success.observed_output_bytes == 8U);
    assert(!success.output_truncated);
    assert(guff::is_sha256(success.captured_output_sha256));
    assert(success.evidence.size() == 1U);
    assert(success.evidence.front().kind == guff::EvidenceKind::Build);
    assert(success.evidence.front().passed);
    assert(success.evidence.front().detail.find("build ok") == std::string::npos);

    auto tampered = request;
    tampered.payload = "tampered";
    called = false;
    const auto mismatch = forge.execute(
        tampered,
        [&called](const auto&, const auto&, auto&) {
            called = true;
            return guff::ForgeExecutorReport{true, 0, 1U};
        });
    assert(!called);
    assert(mismatch.status == guff::ForgeStatus::InputMismatch);
    assert(mismatch.evidence.empty());

    auto denied_request = request;
    denied_request.invocation.permission_tokens = {"code:build"};
    called = false;
    const auto denied = forge.execute(
        denied_request,
        [&called](const auto&, const auto&, auto&) {
            called = true;
            return guff::ForgeExecutorReport{true, 0, 1U};
        });
    assert(!called);
    assert(denied.status == guff::ForgeStatus::InvocationRejected);
    assert(denied.invocation_status == guff::InvocationStatus::PermissionMissing);
    assert(denied.evidence.empty());

    const auto failed = forge.execute(
        request,
        [](const auto&, const auto&, guff::ForgeOutputSink& output) {
            assert(output.write("compiler failed"));
            return guff::ForgeExecutorReport{true, 2, 30U};
        });
    assert(failed.status == guff::ForgeStatus::ExecutionFailed);
    assert(failed.evidence.size() == 1U);
    assert(!failed.evidence.front().passed);

    auto tight_output = request;
    tight_output.budget.max_output_bytes = 4U;
    const auto overflow = forge.execute(
        tight_output,
        [](const auto&, const auto&, guff::ForgeOutputSink& output) {
            assert(!output.write("0123456789"));
            return guff::ForgeExecutorReport{true, 0, 10U};
        });
    assert(overflow.status == guff::ForgeStatus::OutputBudget);
    assert(overflow.captured_output_bytes == 4U);
    assert(overflow.observed_output_bytes == 10U);
    assert(overflow.output_truncated);
    assert(overflow.evidence.size() == 1U);
    assert(!overflow.evidence.front().passed);

    auto tight_time = request;
    tight_time.budget.max_wall_time_ms = 5U;
    const auto timeout = forge.execute(
        tight_time,
        [](const auto&, const auto&, guff::ForgeOutputSink& output) {
            assert(output.write("late"));
            return guff::ForgeExecutorReport{true, 0, 6U};
        });
    assert(timeout.status == guff::ForgeStatus::Timeout);
    assert(timeout.evidence.size() == 1U);
    assert(!timeout.evidence.front().passed);

    const auto thrown = forge.execute(
        request,
        [](const auto&, const auto&, guff::ForgeOutputSink&) -> guff::ForgeExecutorReport {
            throw std::runtime_error("synthetic executor fault");
        });
    assert(thrown.status == guff::ForgeStatus::ExecutorError);
    assert(thrown.evidence.empty());

    auto test_request = request;
    test_request.invocation.invocation_id = "forge-test-1";
    test_request.invocation.capability = guff::SlotCapability::CodeTest;
    test_request.invocation.input_sha256 = guff::sha256(test_request.payload);
    const auto test_result = forge.execute(
        test_request,
        [](const auto&, const auto&, guff::ForgeOutputSink& output) {
            assert(output.write("tests pass"));
            return guff::ForgeExecutorReport{true, 0, 12U};
        });
    assert(test_result.succeeded());
    assert(test_result.evidence.front().kind == guff::EvidenceKind::Test);

    auto invalid_budget = request;
    invalid_budget.budget.max_output_bytes = 0U;
    called = false;
    const auto invalid = forge.execute(
        invalid_budget,
        [&called](const auto&, const auto&, auto&) {
            called = true;
            return guff::ForgeExecutorReport{true, 0, 1U};
        });
    assert(!called);
    assert(invalid.status == guff::ForgeStatus::InvalidRequest);

    return 0;
}
