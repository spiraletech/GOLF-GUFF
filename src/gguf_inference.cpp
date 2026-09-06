#include "guff/gguf_inference.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <locale>
#include <sstream>
#include <system_error>

namespace guff {
namespace {

constexpr std::size_t kGgufHeaderBytes = 24U;
constexpr std::uint32_t kMinSupportedGgufVersion = 2U;
constexpr std::uint32_t kMaxSupportedGgufVersion = 3U;
constexpr std::size_t kMaxPromptBytes = 8U * 1024U * 1024U;

void append_field(std::ostringstream& out,
                  std::string_view key,
                  std::string_view value) {
    out << key.size() << ':' << key
        << '=' << value.size() << ':' << value
        << ';';
}

template <typename T>
void append_number(std::ostringstream& out,
                   std::string_view key,
                   T value) {
    append_field(out, key, std::to_string(value));
}

std::uint32_t read_u32_le(const unsigned char* data) noexcept {
    return static_cast<std::uint32_t>(data[0]) |
           (static_cast<std::uint32_t>(data[1]) << 8U) |
           (static_cast<std::uint32_t>(data[2]) << 16U) |
           (static_cast<std::uint32_t>(data[3]) << 24U);
}

std::uint64_t read_u64_le(const unsigned char* data) noexcept {
    std::uint64_t value = 0U;
    for (std::size_t i = 0U; i < 8U; ++i) {
        value |= static_cast<std::uint64_t>(data[i]) << (8U * i);
    }
    return value;
}

std::optional<std::filesystem::path> canonical_regular_file(
    const std::filesystem::path& path) {
    std::error_code ec;
    if (path.empty() || !path.is_absolute() ||
        !std::filesystem::is_regular_file(path, ec) || ec) {
        return std::nullopt;
    }
    auto canonical = std::filesystem::canonical(path, ec);
    if (ec) return std::nullopt;
    return canonical;
}

std::optional<std::filesystem::path> canonical_directory(
    const std::filesystem::path& path) {
    std::error_code ec;
    if (path.empty() || !path.is_absolute() ||
        !std::filesystem::is_directory(path, ec) || ec) {
        return std::nullopt;
    }
    auto canonical = std::filesystem::canonical(path, ec);
    if (ec) return std::nullopt;
    return canonical;
}

std::string format_double(double value) {
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << std::setprecision(8) << value;
    return out.str();
}

std::size_t argument_bytes(const std::vector<std::string>& arguments) noexcept {
    std::size_t total = 0U;
    for (const auto& argument : arguments) {
        if (argument.size() > std::numeric_limits<std::size_t>::max() - total) {
            return std::numeric_limits<std::size_t>::max();
        }
        total += argument.size();
    }
    return total;
}

bool contains_nul(std::string_view value) noexcept {
    return value.find('\0') != std::string_view::npos;
}

} // namespace

GgufHeaderInfo probe_gguf_header(const std::filesystem::path& path) {
    GgufHeaderInfo info;
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        info.errors.emplace_back("unable to open GGUF file");
        return info;
    }

    std::array<unsigned char, kGgufHeaderBytes> header{};
    file.read(reinterpret_cast<char*>(header.data()),
              static_cast<std::streamsize>(header.size()));
    if (file.gcount() != static_cast<std::streamsize>(header.size())) {
        info.errors.emplace_back("GGUF file is smaller than the fixed header");
        return info;
    }

    if (!(header[0] == 'G' && header[1] == 'G' &&
          header[2] == 'U' && header[3] == 'F')) {
        info.errors.emplace_back("GGUF magic mismatch");
        return info;
    }

    info.version = read_u32_le(header.data() + 4U);
    info.tensor_count = read_u64_le(header.data() + 8U);
    info.metadata_count = read_u64_le(header.data() + 16U);

    if (info.version < kMinSupportedGgufVersion ||
        info.version > kMaxSupportedGgufVersion) {
        info.errors.emplace_back("unsupported GGUF version");
    }
    if (info.tensor_count == 0U) {
        info.errors.emplace_back("GGUF tensor count must be non-zero");
    }
    if (info.metadata_count == 0U) {
        info.errors.emplace_back("GGUF metadata count must be non-zero");
    }

    info.valid = info.errors.empty();
    return info;
}

std::vector<std::string> GgufInferenceProfile::validate() const {
    std::vector<std::string> errors;
    if (context_tokens < 128U || context_tokens > 1'048'576U) {
        errors.emplace_back("context_tokens must be between 128 and 1048576");
    }
    if (max_output_tokens == 0U || max_output_tokens > context_tokens) {
        errors.emplace_back("max_output_tokens must be non-zero and fit inside context_tokens");
    }
    if (threads == 0U || threads > 1024U) {
        errors.emplace_back("threads must be between 1 and 1024");
    }
    if (!std::isfinite(temperature) || temperature < 0.0 || temperature > 5.0) {
        errors.emplace_back("temperature must be finite and between 0 and 5");
    }
    if (!std::isfinite(top_p) || top_p <= 0.0 || top_p > 1.0) {
        errors.emplace_back("top_p must be finite and in the interval (0, 1]");
    }
    if (seed < 0) {
        errors.emplace_back("seed must be non-negative; use an explicit seed for replayable inference");
    }
    if (max_prompt_bytes == 0U || max_prompt_bytes > kMaxPromptBytes) {
        errors.emplace_back("max_prompt_bytes must be between 1 byte and 8 MiB");
    }
    return errors;
}

std::string GgufInferenceBinding::canonical_identity_payload() const {
    std::ostringstream out;
    append_field(out, "slot_immutable_id", slot_immutable_id);
    append_field(out, "model_id", model_id);
    append_field(out, "model_path", model_path.generic_string());
    append_field(out, "model_sha256", model_sha256);
    append_field(out, "executable", executable.generic_string());
    append_field(out, "executable_sha256", executable_sha256);
    append_number(out, "context_tokens", profile.context_tokens);
    append_number(out, "max_output_tokens", profile.max_output_tokens);
    append_number(out, "threads", profile.threads);
    append_field(out, "temperature", format_double(profile.temperature));
    append_field(out, "top_p", format_double(profile.top_p));
    append_number(out, "seed", profile.seed);
    append_number(out, "max_prompt_bytes", profile.max_prompt_bytes);
    append_number(out, "disable_logs", profile.disable_logs ? 1 : 0);
    append_number(out, "display_prompt", profile.display_prompt ? 1 : 0);
    append_field(out, "verification_mode", to_string(profile.verification_mode));
    return out.str();
}

std::string GgufInferenceBinding::immutable_id() const {
    return "guff:gguf-binding:sha256:" + sha256(canonical_identity_payload());
}

bool GgufBindResult::ok() const noexcept {
    return bound && errors.empty() && !binding_id.empty();
}

GgufInferenceBridge::GgufInferenceBridge(const ModelRegistry& models,
                                         NativeProcessRegistry& processes) noexcept
    : models_(models), processes_(processes) {}

GgufBindResult GgufInferenceBridge::bind_llama_cpp(
    const SlotManifest& slot,
    std::string_view model_id,
    const std::filesystem::path& model_path,
    LlamaCppBindingConfig config) {
    GgufBindResult result;

    if (!slot.validate().empty()) {
        result.errors.emplace_back("slot manifest is invalid");
    }
    if (slot.kind != SlotKind::Model) {
        result.errors.emplace_back("GGUF inference requires a MODEL slot");
    }
    if (slot.transport != SlotTransport::LocalProcess) {
        result.errors.emplace_back("GGUF llama.cpp bridge requires LOCAL_PROCESS transport");
    }
    if (!slot.supports(SlotCapability::ModelInfer)) {
        result.errors.emplace_back("GGUF inference slot must expose MODEL_INFER");
    }

    auto profile_errors = config.profile.validate();
    result.errors.insert(result.errors.end(),
                         profile_errors.begin(), profile_errors.end());
    if (config.profile.max_prompt_bytes > slot.max_payload_bytes) {
        result.errors.emplace_back("profile max_prompt_bytes exceeds the slot payload ceiling");
    }
    if (model_id.empty()) {
        result.errors.emplace_back("model_id is required");
    }

    const auto slot_key = slot.immutable_id();
    if (bindings_.contains(slot_key)) {
        result.errors.emplace_back("slot already has a GGUF inference binding");
    }

    const auto manifest = models_.find(model_id);
    if (!manifest) {
        result.errors.emplace_back("model_id is not registered");
    } else {
        if (!models_.is_verified(model_id)) {
            result.errors.emplace_back("model_id is registered but not verified");
        }
        if (manifest->format != ModelFormat::GGUF) {
            result.errors.emplace_back("model manifest format is not GGUF");
        }
    }

    const auto canonical_model = canonical_regular_file(model_path);
    if (!canonical_model) {
        result.errors.emplace_back("model_path must be an existing absolute regular file");
    }
    const auto canonical_executable = canonical_regular_file(config.executable);
    if (!canonical_executable) {
        result.errors.emplace_back("llama.cpp executable must be an existing absolute regular file");
    }

    std::optional<std::filesystem::path> canonical_root;
    if (canonical_model) {
        const auto requested_root = config.working_root.empty()
            ? canonical_model->parent_path()
            : config.working_root;
        canonical_root = canonical_directory(requested_root);
        if (!canonical_root) {
            result.errors.emplace_back("working_root must be an existing absolute directory");
        }
    }

    std::string executable_sha;
    if (canonical_executable) {
        const auto digest = sha256_file(*canonical_executable);
        if (!digest) result.errors.emplace_back("unable to hash llama.cpp executable");
        else executable_sha = *digest;
    }

    if (manifest && canonical_model) {
        const auto verification = manifest->verify_file(*canonical_model);
        if (!verification.ok()) {
            result.errors.emplace_back("GGUF model bytes do not match the verified manifest");
        }
        const auto header = probe_gguf_header(*canonical_model);
        if (!header.valid) {
            result.errors.emplace_back("GGUF header preflight failed");
            result.errors.insert(result.errors.end(), header.errors.begin(), header.errors.end());
        }
    }

    if (!result.errors.empty()) return result;

    GgufInferenceBinding binding;
    binding.slot_immutable_id = slot_key;
    binding.model_id = std::string(model_id);
    binding.model_path = *canonical_model;
    binding.model_sha256 = manifest->sha256;
    binding.executable = *canonical_executable;
    binding.executable_sha256 = std::move(executable_sha);
    binding.profile = config.profile;

    NativeProcessBinding native;
    native.executable = binding.executable;
    native.arguments = {
        "--model", binding.model_path.string(),
        "--ctx-size", std::to_string(binding.profile.context_tokens),
        "--threads", std::to_string(binding.profile.threads),
        "--n-predict", std::to_string(binding.profile.max_output_tokens),
        "--temp", format_double(binding.profile.temperature),
        "--top-p", format_double(binding.profile.top_p),
        "--seed", std::to_string(binding.profile.seed)
    };
    if (!binding.profile.display_prompt) native.arguments.emplace_back("--no-display-prompt");
    if (binding.profile.disable_logs) native.arguments.emplace_back("--log-disable");
    native.arguments.emplace_back("--prompt");
    native.payload_mode = NativePayloadMode::SingleArgument;
    native.working_root = *canonical_root;
    native.working_directory = *canonical_root;
    native.environment = std::move(config.environment);
    native.limits.max_arguments = 32U;
    native.limits.max_environment_entries = 64U;
    native.limits.max_environment_bytes = 64U * 1024U;

    const auto fixed_bytes = argument_bytes(native.arguments);
    if (fixed_bytes == std::numeric_limits<std::size_t>::max() ||
        binding.profile.max_prompt_bytes >
            std::numeric_limits<std::size_t>::max() - fixed_bytes - 1024U) {
        result.errors.emplace_back("native argument byte ceiling overflow");
        return result;
    }
    native.limits.max_argument_bytes = fixed_bytes + binding.profile.max_prompt_bytes + 1024U;

    auto native_errors = native.validate();
    if (!native_errors.empty()) {
        result.errors.emplace_back("generated llama.cpp native binding is invalid");
        result.errors.insert(result.errors.end(), native_errors.begin(), native_errors.end());
        return result;
    }

    std::vector<std::string> process_errors;
    if (!processes_.bind(slot, std::move(native), &process_errors)) {
        result.errors.emplace_back("unable to install llama.cpp native process binding");
        result.errors.insert(result.errors.end(), process_errors.begin(), process_errors.end());
        return result;
    }

    result.binding_id = binding.immutable_id();
    bindings_.emplace(slot_key, std::move(binding));
    result.bound = true;
    return result;
}

GgufBindResult GgufInferenceBridge::bind_llama_cpp(
    const SlotManifest& slot,
    std::string_view model_id,
    const ResolvedArtifact& artifact,
    LlamaCppBindingConfig config) {
    GgufBindResult result;
    if (!artifact.ok()) {
        result.errors.emplace_back("artifact resolver did not produce a verified local artifact");
        result.errors.insert(result.errors.end(), artifact.errors.begin(), artifact.errors.end());
        return result;
    }
    if (artifact.model_id != model_id) {
        result.errors.emplace_back("resolved artifact belongs to a different model identity");
        return result;
    }
    const auto manifest = models_.find(model_id);
    if (!manifest) {
        result.errors.emplace_back("model_id is not registered");
        return result;
    }
    if (artifact.file_size_bytes != manifest->file_size_bytes ||
        artifact.sha256 != manifest->sha256) {
        result.errors.emplace_back("resolved artifact identity does not match the registered model manifest");
        return result;
    }
    return bind_llama_cpp(slot, model_id, artifact.local_path, std::move(config));
}

std::optional<GgufInferenceBinding> GgufInferenceBridge::find_binding(
    std::string_view slot_immutable_id) const {
    const auto found = bindings_.find(std::string(slot_immutable_id));
    if (found == bindings_.end()) return std::nullopt;
    return found->second;
}

std::size_t GgufInferenceBridge::size() const noexcept {
    return bindings_.size();
}

bool GgufInferenceBridge::verify_runtime_binding(
    const GgufInferenceBinding& binding) const {
    const auto manifest = models_.find(binding.model_id);
    if (!manifest || !models_.is_verified(binding.model_id) ||
        manifest->format != ModelFormat::GGUF) {
        return false;
    }

    const auto model_report = manifest->verify_file(binding.model_path);
    if (!model_report.ok() || model_report.actual_sha256 != binding.model_sha256) {
        return false;
    }
    if (!probe_gguf_header(binding.model_path).valid) return false;

    const auto executable_digest = sha256_file(binding.executable);
    return executable_digest && *executable_digest == binding.executable_sha256;
}

ForgeExecutorReport GgufInferenceBridge::operator()(
    const SlotManifest& slot,
    const ForgeExecutionRequest& request,
    ForgeOutputSink& output) const {
    ForgeExecutorReport failure;
    if (slot.kind != SlotKind::Model ||
        slot.transport != SlotTransport::LocalProcess ||
        !slot.supports(SlotCapability::ModelInfer) ||
        request.invocation.capability != SlotCapability::ModelInfer) {
        return failure;
    }

    const auto binding = find_binding(slot.immutable_id());
    if (!binding) return failure;
    if (request.payload.empty() ||
        request.payload.size() > binding->profile.max_prompt_bytes ||
        contains_nul(request.payload)) {
        return failure;
    }

    if (binding->profile.verification_mode == GgufVerificationMode::EveryExecution &&
        !verify_runtime_binding(*binding)) {
        return failure;
    }

    NativeLocalProcessExecutor native(processes_);
    return native(slot, request, output);
}

std::string_view to_string(GgufVerificationMode mode) noexcept {
    switch (mode) {
    case GgufVerificationMode::EveryExecution: return "EVERY_EXECUTION";
    case GgufVerificationMode::BindOnly: return "BIND_ONLY";
    }
    return "EVERY_EXECUTION";
}

} // namespace guff
