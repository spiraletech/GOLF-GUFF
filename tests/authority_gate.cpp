#include "guff/authority_gate.hpp"
#include "guff/caddy_router.hpp"
#include "guff/clubhouse.hpp"
#include "guff/dojo.hpp"
#include "guff/forge.hpp"
#include "guff/hardware_profile.hpp"
#include "guff/model_registry.hpp"
#include "guff/scorecard.hpp"
#include "guff/sha256.hpp"

#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "CHECK failed: " #expression << " @ " << __FILE__ << ':' << __LINE__ << '\n'; return 1; } } while (false)

namespace {

class TestSigner final : public guff::AuthoritySigner, public guff::AuthorityVerifier {
public:
    std::string signer_id() const override { return "local:l16-test-signer"; }
    std::string algorithm() const override { return "TEST-SHA256"; }
    std::optional<std::string> sign(std::string_view canonical) const override {
        return guff::sha256(std::string("l16-secret\n") + std::string(canonical));
    }
    bool knows(std::string_view signer, std::string_view algorithm_name) const override {
        return signer == signer_id() && algorithm_name == algorithm();
    }
    bool verify(std::string_view signer,
                std::string_view algorithm_name,
                std::string_view canonical,
                std::string_view signature) const override {
        if (!knows(signer, algorithm_name)) return false;
        const auto expected = sign(canonical);
        return expected && *expected == signature;
    }
};

std::optional<guff::AuthorityReceipt> receipt_for(
    const TestSigner& signer,
    guff::AuthorityPurpose purpose,
    std::string subject,
    std::string scope,
    std::string nonce) {
    guff::AuthorityEnvelope envelope;
    envelope.purpose = purpose;
    envelope.subject_id = std::move(subject);
    envelope.actor_reference = "human:l16-regression";
    envelope.signer_id = signer.signer_id();
    envelope.issued_at_utc = "2026-09-05T02:00:00Z";
    envelope.nonce = std::move(nonce);
    envelope.scope_sha256 = std::move(scope);
    return guff::issue_authority_receipt(envelope, signer);
}

guff::SlotManifest destructive_slot() {
    guff::SlotManifest slot;
    slot.slot_name = "forge.destructive.test";
    slot.display_name = "Destructive Test Slot";
    slot.version = "1.0.0";
    slot.kind = guff::SlotKind::Compiler;
    slot.transport = guff::SlotTransport::LocalProcess;
    slot.entrypoint = "native://l16-test";
    slot.capabilities = {guff::SlotCapability::CodeBuild};
    slot.allowed_layers = {guff::RealityLayer::Project};
    slot.required_permissions = {"code:build", "device:execute"};
    slot.max_payload_bytes = 4096U;
    return slot;
}

guff::ExecutionSessionRequest destructive_request() {
    const std::string payload = "delete-and-rebuild-generated-cache";
    guff::ExecutionSessionRequest request;
    request.correlation_id = "l16-destructive-001";
    request.route_request.signal = {
        .intent = "destructive deterministic maintenance",
        .layer = guff::RealityLayer::Project,
        .complexity = 0.10,
        .uncertainty = 0.10,
        .requires_execution = true,
        .destructive = true,
    };
    request.route_request.task = guff::TaskClass::Coding;
    request.route_request.profile_name = "l16-authority-gate";
    request.forge_request.invocation.invocation_id = "l16-destructive-001:attempt:0";
    request.forge_request.invocation.slot_id = "forge.destructive.test";
    request.forge_request.invocation.capability = guff::SlotCapability::CodeBuild;
    request.forge_request.invocation.layer = guff::RealityLayer::Project;
    request.forge_request.invocation.input_sha256 = guff::sha256(payload);
    request.forge_request.invocation.payload_bytes = payload.size();
    request.forge_request.invocation.permission_tokens = {"code:build", "device:execute"};
    request.forge_request.payload = payload;
    request.forge_request.budget.max_wall_time_ms = 1000U;
    request.forge_request.budget.max_output_bytes = 1024U;
    request.zenkai_budget.max_attempts = 1U;
    request.zenkai_policy.retry_authority = guff::RetryAuthority::None;
    request.summary = "l16 destructive gate regression";
    request.recorded_at_utc = "2026-09-05T02:00:00Z";
    return request;
}

guff::SymbiosisGrant persistent_grant() {
    guff::SymbiosisGrant grant;
    grant.source.grant_id = "l16-persistent-grant";
    grant.source.kind = guff::SourceKind::ToolOutput;
    grant.source.scope = guff::GrantScope::Project;
    grant.source.layer = guff::RealityLayer::Runtime;
    grant.source.locator_prefix = "tool://l16/";
    grant.source.max_source_bytes = 4096U;
    grant.source.max_slice_bytes = 1024U;
    grant.retention.persist_grant = true;
    grant.retention.persist_observation_stamps = true;
    grant.retention.allow_memory_promotion = true;
    grant.retention.max_promotion_bytes = 1024U;
    grant.retention.max_observation_stamps = 8U;
    grant.issued_at_unix_ms = 100U;
    return grant;
}

} // namespace

int main() {
    TestSigner signer;
    guff::AuthorityGate gate(signer);

    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-l16-authority-gate");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);

    guff::ClubhouseRegistry clubhouse;
    CHECK(clubhouse.register_slot(destructive_slot()));
    guff::ForgeAdapter forge(clubhouse);
    guff::ModelRegistry models;
    guff::Scorecard scorecard;
    guff::CaddyRouter router(models, scorecard);
    guff::DojoStore dojo(root / "dojo.store");
    guff::ExecutionSessionOrchestrator inner(router, clubhouse, forge, dojo);
    guff::AuthorityGatedExecutionSession guarded(gate, inner);
    const auto hardware = guff::detect_hardware_profile();
    const auto request = destructive_request();

    std::size_t executor_calls = 0U;
    const guff::ForgeAdapter::ExecutorFunction executor =
        [&](const guff::SlotManifest&,
            const guff::ForgeExecutionRequest&,
            guff::ForgeOutputSink& output) {
            ++executor_calls;
            static_cast<void>(output.write("authorized destructive execution"));
            return guff::ForgeExecutorReport{true, 0, 2U};
        };

    const auto missing = guarded.run(request, hardware, std::nullopt, executor);
    CHECK(!missing.executed());
    CHECK(missing.authority.status == guff::AuthorityGateStatus::ReceiptMissing);
    CHECK(executor_calls == 0U);

    auto wrong_scope = receipt_for(
        signer,
        guff::AuthorityPurpose::DestructiveExecution,
        guff::execution_session_id(request, hardware),
        guff::sha256("wrong-scope"),
        "destructive-wrong-scope");
    CHECK(wrong_scope.has_value());
    const auto scoped_out = guarded.run(request, hardware, wrong_scope, executor);
    CHECK(!scoped_out.executed());
    CHECK(scoped_out.authority.status == guff::AuthorityGateStatus::ScopeMismatch);
    CHECK(executor_calls == 0U);

    auto destructive_receipt = receipt_for(
        signer,
        guff::AuthorityPurpose::DestructiveExecution,
        guff::execution_session_id(request, hardware),
        guff::destructive_execution_scope_sha256(request, hardware),
        "destructive-valid");
    CHECK(destructive_receipt.has_value());
    const auto allowed = guarded.run(request, hardware, destructive_receipt, executor);
    CHECK(allowed.executed());
    CHECK(allowed.authority.ok());
    CHECK(allowed.session->succeeded());
    CHECK(executor_calls == 1U);

    guff::SymbiosisLedger ledger(root / "symbiosis.journal");
    guff::AuthorityGatedSymbiosis symbiosis(gate, ledger);
    auto grant = persistent_grant();
    const auto no_memory_auth = symbiosis.create_grant(grant);
    CHECK(no_memory_auth.status == guff::LedgerStatus::Denied);
    CHECK(ledger.grant_count() == 0U);

    auto grant_receipt = receipt_for(
        signer,
        guff::AuthorityPurpose::PersistentSymbiosis,
        grant.source.grant_id,
        guff::persistent_symbiosis_scope_sha256(grant),
        "symbiosis-valid");
    CHECK(grant_receipt.has_value());
    const auto grant_ok = symbiosis.create_grant(grant, grant_receipt);
    CHECK(grant_ok.ok());
    CHECK(ledger.grant_count() == 1U);

    auto ephemeral = grant;
    ephemeral.source.grant_id = "l16-ephemeral-grant";
    ephemeral.retention.persist_grant = false;
    ephemeral.retention.persist_observation_stamps = false;
    ephemeral.retention.allow_memory_promotion = false;
    const auto ephemeral_ok = symbiosis.create_grant(ephemeral);
    CHECK(ephemeral_ok.ok());
    CHECK(ledger.grant_count() == 2U);

    std::filesystem::remove_all(root, ec);
    return 0;
}
