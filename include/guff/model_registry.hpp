#pragma once

#include "guff/model_manifest.hpp"

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace guff {

enum class RegisterStatus : std::uint8_t {
    Registered,
    Duplicate,
    Invalid,
    VerificationFailed
};

struct RegisterResult {
    RegisterStatus status{RegisterStatus::Invalid};
    std::string immutable_id;
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

class ModelRegistry {
public:
    [[nodiscard]] RegisterResult register_manifest(ModelManifest manifest);
    [[nodiscard]] RegisterResult register_verified(
        ModelManifest manifest,
        const std::filesystem::path& model_path);

    [[nodiscard]] std::optional<ModelManifest> find(std::string_view immutable_id) const;
    [[nodiscard]] std::vector<std::string> ids() const;
    [[nodiscard]] std::size_t size() const noexcept;

private:
    std::unordered_map<std::string, ModelManifest> models_;
};

[[nodiscard]] std::string_view to_string(RegisterStatus status) noexcept;

} // namespace guff
