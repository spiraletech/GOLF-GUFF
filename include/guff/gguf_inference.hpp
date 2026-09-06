#pragma once

#include "guff/clubhouse.hpp"
#include "guff/forge.hpp"
#include "guff/model_registry.hpp"
#include "guff/native_process.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace guff {

enum class GgufVerificationMode : std::uint8_t {
    EveryExecution,
    BindOnly
};

struct GgufHeaderInfo {
    bool valid{false};
    std::uint32_t version{0U};
    std::uint64_t tensor_count{0U};
    std::uint64_t metadata_count{0U};
    std::vector<std::string> errors;
};

[[nodiscard]] GgufHeaderInfo probe_gguf_header(const std::filesystem::path& path);

struct GgufInferenceProfile {
    std::uint32_t context_tokens{4096U};
    std::uint32_t max_output_tokens{256U};
    std::uint32_t threads{1U};
    double temperature{0.7};
    double top_p{0.95};
    std::int32_t seed{0};
    std::size_t max_prompt_bytes{64U * 1024U};
    bool disable_logs{true};
    bool display_prompt{false};
    GgufVerificationMode verification_mode{GgufVerificationMode::EveryExecution};

    [[nodiscard]] std::vector<std::string> validate() const;
};

struct LlamaCppBindingConfig {
    std::filesystem::path executable;
    std::filesystem::path working_root;
    std::vector<std::pair<std::string, std::string>> environment;
    GgufInferenceProfile profile{};
};

struct GgufInferenceBinding {
    std::string slot_immutable_id;
    std::string model_id;
    std::filesystem::path model_path;
    std::string model_sha256;
    std::filesystem::path executable;
    std::string executable_sha256;
    GgufInferenceProfile profile{};

    [[nodiscard]] std::string canonical_identity_payload() const;
    [[nodiscard]] std::string immutable_id() const;
};

struct GgufBindResult {
    bool bound{false};
    std::string binding_id;
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

class GgufInferenceBridge {
public:
    GgufInferenceBridge(const ModelRegistry& models,
                        NativeProcessRegistry& processes) noexcept;

    [[nodiscard]] GgufBindResult bind_llama_cpp(
        const SlotManifest& slot,
        std::string_view model_id,
        const std::filesystem::path& model_path,
        LlamaCppBindingConfig config);

    [[nodiscard]] std::optional<GgufInferenceBinding> find_binding(
        std::string_view slot_immutable_id) const;

    [[nodiscard]] std::size_t size() const noexcept;

    [[nodiscard]] ForgeExecutorReport operator()(
        const SlotManifest& slot,
        const ForgeExecutionRequest& request,
        ForgeOutputSink& output) const;

private:
    [[nodiscard]] bool verify_runtime_binding(const GgufInferenceBinding& binding) const;

    const ModelRegistry& models_;
    NativeProcessRegistry& processes_;
    std::unordered_map<std::string, GgufInferenceBinding> bindings_;
};

[[nodiscard]] std::string_view to_string(GgufVerificationMode mode) noexcept;

} // namespace guff
