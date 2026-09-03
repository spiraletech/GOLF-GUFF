#pragma once

#include "guff/clubhouse.hpp"
#include "guff/forge.hpp"

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

enum class NativePayloadMode : std::uint8_t {
    None,
    SingleArgument
};

struct NativeProcessLimits {
    std::size_t max_arguments{64U};
    std::size_t max_argument_bytes{32U * 1024U};
    std::size_t max_environment_entries{64U};
    std::size_t max_environment_bytes{32U * 1024U};
};

struct NativeProcessBinding {
    std::filesystem::path executable;
    std::vector<std::string> arguments;
    NativePayloadMode payload_mode{NativePayloadMode::None};
    std::filesystem::path working_root;
    std::filesystem::path working_directory;
    std::vector<std::pair<std::string, std::string>> environment;
    NativeProcessLimits limits{};

    [[nodiscard]] std::vector<std::string> validate() const;
};

class NativeProcessRegistry {
public:
    [[nodiscard]] bool bind(const SlotManifest& slot,
                            NativeProcessBinding binding,
                            std::vector<std::string>* errors = nullptr);
    [[nodiscard]] std::optional<NativeProcessBinding> find(std::string_view slot_immutable_id) const;
    [[nodiscard]] std::size_t size() const noexcept;

private:
    std::unordered_map<std::string, NativeProcessBinding> bindings_;
};

class NativeLocalProcessExecutor {
public:
    explicit NativeLocalProcessExecutor(const NativeProcessRegistry& registry) noexcept;

    [[nodiscard]] ForgeExecutorReport operator()(
        const SlotManifest& slot,
        const ForgeExecutionRequest& request,
        ForgeOutputSink& output) const;

private:
    const NativeProcessRegistry& registry_;
};

[[nodiscard]] std::string_view to_string(NativePayloadMode mode) noexcept;

} // namespace guff
