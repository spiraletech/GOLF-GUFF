#include "guff/model_registry.hpp"

#include <algorithm>
#include <utility>

namespace guff {

bool RegisterResult::ok() const noexcept {
    return status == RegisterStatus::Registered;
}

RegisterResult ModelRegistry::register_manifest(ModelManifest manifest) {
    RegisterResult result;
    result.errors = manifest.validate();

    if (!result.errors.empty()) {
        result.status = RegisterStatus::Invalid;
        return result;
    }

    result.immutable_id = manifest.immutable_id();
    if (models_.contains(result.immutable_id)) {
        result.status = RegisterStatus::Duplicate;
        return result;
    }

    models_.emplace(result.immutable_id, std::move(manifest));
    result.status = RegisterStatus::Registered;
    return result;
}

RegisterResult ModelRegistry::register_verified(
    ModelManifest manifest,
    const std::filesystem::path& model_path) {
    const auto verification = manifest.verify_file(model_path);
    if (!verification.ok()) {
        RegisterResult result;
        result.status = verification.manifest_valid
            ? RegisterStatus::VerificationFailed
            : RegisterStatus::Invalid;
        result.immutable_id = verification.manifest_valid
            ? manifest.immutable_id()
            : std::string{};
        result.errors = verification.errors;
        return result;
    }

    return register_manifest(std::move(manifest));
}

std::optional<ModelManifest> ModelRegistry::find(std::string_view immutable_id) const {
    const auto it = models_.find(std::string(immutable_id));
    if (it == models_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<std::string> ModelRegistry::ids() const {
    std::vector<std::string> result;
    result.reserve(models_.size());

    for (const auto& [id, manifest] : models_) {
        static_cast<void>(manifest);
        result.push_back(id);
    }

    std::sort(result.begin(), result.end());
    return result;
}

std::size_t ModelRegistry::size() const noexcept {
    return models_.size();
}

std::string_view to_string(RegisterStatus status) noexcept {
    switch (status) {
    case RegisterStatus::Registered: return "REGISTERED";
    case RegisterStatus::Duplicate: return "DUPLICATE";
    case RegisterStatus::Invalid: return "INVALID";
    case RegisterStatus::VerificationFailed: return "VERIFICATION_FAILED";
    }
    return "UNKNOWN";
}

} // namespace guff
