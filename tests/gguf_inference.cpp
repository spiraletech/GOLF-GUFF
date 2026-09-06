#include "guff/clubhouse.hpp"
#include "guff/forge.hpp"
#include "guff/gguf_inference.hpp"
#include "guff/model_manifest.hpp"
#include "guff/model_registry.hpp"
#include "guff/native_process.hpp"
#include "guff/sha256.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

void write_u32_le(std::ofstream& out, std::uint32_t value) {
    for (unsigned shift = 0U; shift < 32U; shift += 8U) {
        out.put(static_cast<char>((value >> shift) & 0xffU));
    }
}

void write_u64_le(std::ofstream& out, std::uint64_t value) {
    for (unsigned shift = 0U; shift < 64U; shift += 8U) {
        out.put(static_cast<char>((value >> shift) & 0xffU));
    }
}

void write_stub_gguf(const std::filesystem::path& path) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    assert(out);
    out.write("GGUF", 4);
    write_u32_le(out, 3U);
    write_u64_le(out, 1U);
    write_u64_le(out, 1U);
    out.write("stub-payload", 12);
}

void write_bad_file(const std::filesystem::path& path) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    assert(out);
    out.write("NOPE", 4);
    write_u32_le(out, 3U);
    write_u64_le(out, 1U);
    write_u64_le(out, 1U);
    out.write("stub-payload", 12);
}

guff::ModelManifest manifest_for(const std::filesystem::path& path,
                                 std::string display_name) {
    const auto digest = guff::sha256_file(path);
    assert(digest.has_value());

    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    assert(!ec);

    guff::ModelManifest manifest;
    manifest.display_name = std::move(display_name);
    manifest.family = "guff-test";
    manifest.architecture = "test-transformer";
    manifest.variant = "stub";
    manifest.parameter_count = 1U;
    manifest.format = guff::ModelFormat::GGUF;
    manifest.quantization = guff::Quantization::Q4_0;
    manifest.file_name = path.filename().string();
    manifest.file_size_bytes = size;
    manifest.sha256 = *digest;
    manifest.provenance.provider = "guff-test";
    manifest.provenance.repository = "local/test";
    manifest.provenance.revision = "1";
    manifest.provenance.source_filename = path.filename().string();
    manifest.provenance.source_sha256 = *digest;
    manifest.license.spdx_id = "MIT";
    manifest.license.name = "MIT License";
    manifest.license.commercial_use_allowed = true;
    manifest.license.redistribution_allowed = true;
    manifest.hardware.min_ram_mb = 1U;
    manifest.hardware.min_vram_mb = 0U;
    manifest.hardware.recommended_threads = 1U;
    manifest.hardware.cpu_only_supported = true;
    manifest.capabilities = {"text-generation"};
    manifest.tags = {"gguf", "test"};
    return manifest;
}

guff::SlotManifest inference_slot(std::string name, std::size_t max_payload = 4096U) {
    guff::SlotManifest slot;
    slot.slot_name = std::move(name);
    slot.display_name = "GGUF Inference Test Slot";
    slot.version = "1.0.0";
    slot.kind = guff::SlotKind::Model;
    slot.transport = guff::SlotTransport::LocalProcess;
    slot.entrypoint = "llama.cpp://llama-cli";
    slot.capabilities = {guff::SlotCapability::ModelInfer};
    slot.allowed_layers = {guff::RealityLayer::Semantic};
    slot.required_permissions = {"model:infer", "device:execute"};
    slot.max_payload_bytes = max_payload;
    return slot;
}

guff::ForgeExecutionRequest request_for(const guff::SlotManifest& slot,
                                        std::string prompt) {
    guff::ForgeExecutionRequest request;
    request.invocation.invocation_id = "gguf-test-invocation";
    request.invocation.slot_id = slot.slot_name;
    request.invocation.capability = guff::SlotCapability::ModelInfer;
    request.invocation.layer = guff::RealityLayer::Semantic;
    request.invocation.input_sha256 = guff::sha256(prompt);
    request.invocation.payload_bytes = prompt.size();
    request.invocation.permission_tokens = {"model:infer", "device:execute"};
    request.payload = std::move(prompt);
    request.budget.max_wall_time_ms = 5000U;
    request.budget.max_output_bytes = 16U * 1024U;
    return request;
}

std::string argument_after(int argc, char** argv, std::string_view flag) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string_view(argv[i]) == flag) return argv[i + 1];
    }
    return {};
}

bool is_fake_llama_child(int argc, char** argv) {
    return std::any_of(argv + 1, argv + argc, [](const char* value) {
        return std::string_view(value) == "--model";
    });
}

} // namespace

int main(int argc, char** argv) {
    if (is_fake_llama_child(argc, argv)) {
        const auto model = argument_after(argc, argv, "--model");
        const auto prompt = argument_after(argc, argv, "--prompt");
        const auto seed = argument_after(argc, argv, "--seed");
        const auto predicted = argument_after(argc, argv, "--n-predict");
        if (model.empty() || prompt.empty() || seed.empty() || predicted.empty()) return 9;
        std::cout << "FAKE_LLAMA_RESPONSE\n";
        std::cout << "PROMPT:" << prompt << '\n';
        std::cout << "SEED:" << seed << '\n';
        std::cout << "N_PREDICT:" << predicted << '\n';
        return 0;
    }

    const auto executable = std::filesystem::absolute(argv[0]);
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-gguf-inference-regression");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root);

    const auto model_path = root / "model.gguf";
    write_stub_gguf(model_path);

    const auto header = guff::probe_gguf_header(model_path);
    assert(header.valid);
    assert(header.version == 3U);
    assert(header.tensor_count == 1U);
    assert(header.metadata_count == 1U);

    guff::ModelRegistry models;
    auto manifest = manifest_for(model_path, "Stub GGUF");
    const auto model_id = manifest.immutable_id();
    const auto registered = models.register_verified(manifest, model_path);
    assert(registered.ok());
    assert(models.is_verified(model_id));

    guff::ClubhouseRegistry clubhouse;
    const auto slot = inference_slot("model.gguf.stub");
    assert(clubhouse.register_slot(slot));

    guff::NativeProcessRegistry processes;
    guff::GgufInferenceBridge bridge(models, processes);

    guff::LlamaCppBindingConfig config;
    config.executable = executable;
    config.working_root = root;
    config.profile.context_tokens = 1024U;
    config.profile.max_output_tokens = 32U;
    config.profile.threads = 1U;
    config.profile.temperature = 0.25;
    config.profile.top_p = 0.9;
    config.profile.seed = 42;
    config.profile.max_prompt_bytes = 4096U;
    config.profile.disable_logs = true;
    config.profile.display_prompt = false;
    config.profile.verification_mode = guff::GgufVerificationMode::EveryExecution;

    const auto bound = bridge.bind_llama_cpp(slot, model_id, model_path, config);
    assert(bound.ok());
    assert(bound.binding_id.rfind("guff:gguf-binding:sha256:", 0U) == 0U);
    assert(bridge.size() == 1U);
    assert(processes.size() == 1U);

    const auto binding = bridge.find_binding(slot.immutable_id());
    assert(binding.has_value());
    assert(binding->model_id == model_id);
    assert(binding->model_path == std::filesystem::canonical(model_path));
    assert(guff::is_sha256(binding->model_sha256));
    assert(guff::is_sha256(binding->executable_sha256));
    assert(binding->immutable_id() == bound.binding_id);

    const std::string literal_prompt = "literal ; && | < > ^ % ! quoted=\"yes\" path=\\tmp";
    auto request = request_for(slot, literal_prompt);

    guff::ForgeOutputSink direct_output(16U * 1024U);
    const auto direct = bridge(slot, request, direct_output);
    assert(direct.completed);
    assert(direct.exit_code == 0);
    const std::string direct_text(direct_output.captured());
    assert(direct_text.find("FAKE_LLAMA_RESPONSE") != std::string::npos);
    assert(direct_text.find("PROMPT:" + literal_prompt) != std::string::npos);
    assert(direct_text.find("SEED:42") != std::string::npos);
    assert(direct_text.find("N_PREDICT:32") != std::string::npos);

    guff::ForgeAdapter forge(clubhouse);
    const auto integrated = forge.execute(request, bridge);
    assert(integrated.succeeded());
    assert(integrated.status == guff::ForgeStatus::Completed);
    assert(integrated.exit_code == 0);
    assert(guff::is_sha256(integrated.captured_output_sha256));
    assert(integrated.evidence.size() == 1U);
    assert(integrated.evidence.front().passed);
    assert(integrated.evidence.front().detail.find(literal_prompt) == std::string::npos);

    auto oversized = request_for(slot, std::string(5000U, 'x'));
    guff::ForgeOutputSink oversized_output(4096U);
    const auto oversized_report = bridge(slot, oversized, oversized_output);
    assert(!oversized_report.completed);

    std::string nul_prompt{"abc\0def", 7U};
    auto nul_request = request_for(slot, nul_prompt);
    guff::ForgeOutputSink nul_output(4096U);
    const auto nul_report = bridge(slot, nul_request, nul_output);
    assert(!nul_report.completed);

    const auto bad_path = root / "bad.gguf";
    write_bad_file(bad_path);
    const auto bad_header = guff::probe_gguf_header(bad_path);
    assert(!bad_header.valid);

    auto bad_manifest = manifest_for(bad_path, "Bad GGUF");
    const auto bad_id = bad_manifest.immutable_id();
    assert(models.register_verified(bad_manifest, bad_path).ok());
    const auto bad_slot = inference_slot("model.gguf.bad");
    assert(clubhouse.register_slot(bad_slot));
    const auto bad_bind = bridge.bind_llama_cpp(bad_slot, bad_id, bad_path, config);
    assert(!bad_bind.ok());
    assert(!bad_bind.errors.empty());

    const auto unverified_path = root / "unverified.gguf";
    write_stub_gguf(unverified_path);
    auto unverified_manifest = manifest_for(unverified_path, "Unverified GGUF");
    const auto unverified_id = unverified_manifest.immutable_id();
    assert(models.register_manifest(unverified_manifest).ok());
    const auto unverified_slot = inference_slot("model.gguf.unverified");
    assert(clubhouse.register_slot(unverified_slot));
    const auto unverified_bind = bridge.bind_llama_cpp(
        unverified_slot, unverified_id, unverified_path, config);
    assert(!unverified_bind.ok());

    {
        std::ofstream tamper(model_path, std::ios::binary | std::ios::app);
        tamper.put('x');
    }
    guff::ForgeOutputSink tampered_output(4096U);
    const auto tampered_report = bridge(slot, request, tampered_output);
    assert(!tampered_report.completed);
    assert(tampered_output.captured().empty());

    std::filesystem::remove_all(root, ec);
    return 0;
}
