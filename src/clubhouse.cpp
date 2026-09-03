#include "guff/clubhouse.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <sstream>
#include <type_traits>
#include <unordered_set>
#include <utility>

namespace guff {
namespace {

template <typename T>
std::vector<T> sorted_unique(std::vector<T> values) {
    std::sort(values.begin(), values.end(), [](const T& a, const T& b) {
        return static_cast<std::underlying_type_t<T>>(a) < static_cast<std::underlying_type_t<T>>(b);
    });
    values.erase(std::unique(values.begin(), values.end()), values.end());
    return values;
}

std::vector<std::string> sorted_unique_strings(std::vector<std::string> values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    return values;
}

bool valid_permission(std::string_view token) {
    if (token.empty() || token.size() > 128U) {
        return false;
    }
    return std::all_of(token.begin(), token.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
               ch == ':' || ch == '-' || ch == '_' || ch == '.' || ch == '/';
    });
}

std::string canonical_manifest(const SlotManifest& manifest) {
    auto capabilities = sorted_unique(manifest.capabilities);
    auto layers = sorted_unique(manifest.allowed_layers);
    auto permissions = sorted_unique_strings(manifest.required_permissions);
    auto tags = sorted_unique_strings(manifest.tags);

    std::ostringstream out;
    out << manifest.schema_version << '\n'
        << manifest.slot_name << '\n'
        << manifest.display_name << '\n'
        << manifest.version << '\n'
        << static_cast<unsigned>(manifest.kind) << '\n'
        << static_cast<unsigned>(manifest.transport) << '\n'
        << manifest.entrypoint << '\n'
        << manifest.max_payload_bytes << '\n'
        << (manifest.enabled ? 1 : 0) << '\n';

    for (const auto value : capabilities) {
        out << "c:" << static_cast<unsigned>(value) << '\n';
    }
    for (const auto value : layers) {
        out << "l:" << static_cast<unsigned>(value) << '\n';
    }
    for (const auto& value : permissions) {
        out << "p:" << value << '\n';
    }
    for (const auto& value : tags) {
        out << "t:" << value << '\n';
    }
    return out.str();
}

} // namespace

std::vector<std::string> SlotManifest::validate() const {
    std::vector<std::string> errors;
    if (schema_version != 1U) errors.emplace_back("unsupported slot schema version");
    if (slot_name.empty() || slot_name.size() > 96U) errors.emplace_back("slot_name is required and must be <= 96 bytes");
    if (display_name.empty() || display_name.size() > 128U) errors.emplace_back("display_name is required and must be <= 128 bytes");
    if (version.empty() || version.size() > 64U) errors.emplace_back("version is required and must be <= 64 bytes");
    if (entrypoint.empty() || entrypoint.size() > 512U) errors.emplace_back("entrypoint is required and must be <= 512 bytes");
    if (capabilities.empty()) errors.emplace_back("at least one capability is required");
    if (allowed_layers.empty()) errors.emplace_back("at least one reality layer is required");
    if (max_payload_bytes == 0U) errors.emplace_back("max_payload_bytes must be greater than zero");
    if (capabilities.size() > 64U) errors.emplace_back("too many capabilities");
    if (allowed_layers.size() > 16U) errors.emplace_back("too many reality layers");
    if (required_permissions.size() > 64U) errors.emplace_back("too many permission requirements");
    if (tags.size() > 64U) errors.emplace_back("too many slot tags");

    for (const auto& permission : required_permissions) {
        if (!valid_permission(permission)) {
            errors.emplace_back("invalid permission token: " + permission);
        }
    }
    return errors;
}

std::string SlotManifest::immutable_id() const {
    return "guff:slot:sha256:" + sha256(canonical_manifest(*this));
}

bool SlotManifest::supports(SlotCapability capability) const noexcept {
    return std::find(capabilities.begin(), capabilities.end(), capability) != capabilities.end();
}

bool SlotManifest::allows(RealityLayer layer) const noexcept {
    return std::find(allowed_layers.begin(), allowed_layers.end(), layer) != allowed_layers.end();
}

bool SlotResolution::ready() const noexcept {
    return status == InvocationStatus::Ready;
}

bool ClubhouseRegistry::register_slot(SlotManifest manifest,
                                      std::vector<std::string>* errors) {
    auto validation = manifest.validate();
    if (!validation.empty()) {
        if (errors) *errors = std::move(validation);
        return false;
    }

    manifest.capabilities = sorted_unique(std::move(manifest.capabilities));
    manifest.allowed_layers = sorted_unique(std::move(manifest.allowed_layers));
    manifest.required_permissions = sorted_unique_strings(std::move(manifest.required_permissions));
    manifest.tags = sorted_unique_strings(std::move(manifest.tags));

    const auto immutable = manifest.immutable_id();
    if (slots_.contains(immutable) || aliases_.contains(manifest.slot_name)) {
        if (errors) errors->push_back("slot identity or slot_name is already registered");
        return false;
    }

    aliases_.emplace(manifest.slot_name, immutable);
    slots_.emplace(immutable, std::move(manifest));
    return true;
}

std::optional<SlotManifest> ClubhouseRegistry::find(std::string_view slot_id) const {
    std::string key(slot_id);
    if (const auto alias = aliases_.find(key); alias != aliases_.end()) {
        key = alias->second;
    }
    if (const auto found = slots_.find(key); found != slots_.end()) {
        return found->second;
    }
    return std::nullopt;
}

std::vector<SlotManifest> ClubhouseRegistry::list() const {
    std::vector<SlotManifest> result;
    result.reserve(slots_.size());
    for (const auto& [id, slot] : slots_) {
        static_cast<void>(id);
        result.push_back(slot);
    }
    std::sort(result.begin(), result.end(), [](const SlotManifest& a, const SlotManifest& b) {
        return a.slot_name < b.slot_name;
    });
    return result;
}

SlotResolution ClubhouseRegistry::resolve(const SlotInvocation& invocation) const {
    SlotResolution result;
    if (invocation.invocation_id.empty() || invocation.slot_id.empty() ||
        !is_sha256(invocation.input_sha256)) {
        result.status = InvocationStatus::Invalid;
        result.reason = "invocation requires id, slot id, and SHA-256 input identity";
        return result;
    }

    auto slot = find(invocation.slot_id);
    if (!slot) {
        result.status = InvocationStatus::SlotNotFound;
        result.reason = "slot is not registered";
        return result;
    }
    result.slot = slot;

    if (!slot->enabled) {
        result.status = InvocationStatus::SlotDisabled;
        result.reason = "slot is disabled";
        return result;
    }
    if (!slot->supports(invocation.capability)) {
        result.status = InvocationStatus::CapabilityMissing;
        result.reason = "slot does not advertise requested capability";
        return result;
    }
    if (!slot->allows(invocation.layer)) {
        result.status = InvocationStatus::LayerMismatch;
        result.reason = "requested STRATA layer is outside slot contract";
        return result;
    }
    if (invocation.payload_bytes > slot->max_payload_bytes) {
        result.status = InvocationStatus::PayloadTooLarge;
        result.reason = "payload exceeds slot contract";
        return result;
    }

    const std::unordered_set<std::string> supplied(
        invocation.permission_tokens.begin(), invocation.permission_tokens.end());
    for (const auto& required : slot->required_permissions) {
        if (!supplied.contains(required)) {
            result.missing_permissions.push_back(required);
        }
    }
    if (!result.missing_permissions.empty()) {
        result.status = InvocationStatus::PermissionMissing;
        result.reason = "required permission tokens are missing";
        return result;
    }

    result.status = InvocationStatus::Ready;
    result.reason = "slot contract satisfied; executor may receive invocation";
    return result;
}

std::size_t ClubhouseRegistry::size() const noexcept {
    return slots_.size();
}

std::string_view to_string(SlotKind kind) noexcept {
    switch (kind) {
    case SlotKind::Model: return "MODEL";
    case SlotKind::Compiler: return "COMPILER";
    case SlotKind::Repository: return "REPOSITORY";
    case SlotKind::Audio: return "AUDIO";
    case SlotKind::World: return "WORLD";
    case SlotKind::Image: return "IMAGE";
    case SlotKind::Video: return "VIDEO";
    case SlotKind::Language: return "LANGUAGE";
    case SlotKind::Tool: return "TOOL";
    case SlotKind::Generic: return "GENERIC";
    }
    return "GENERIC";
}

std::string_view to_string(SlotTransport transport) noexcept {
    switch (transport) {
    case SlotTransport::InProcess: return "IN_PROCESS";
    case SlotTransport::LocalProcess: return "LOCAL_PROCESS";
    case SlotTransport::Connector: return "CONNECTOR";
    }
    return "IN_PROCESS";
}

std::string_view to_string(SlotCapability capability) noexcept {
    switch (capability) {
    case SlotCapability::ModelInfer: return "MODEL_INFER";
    case SlotCapability::CodeBuild: return "CODE_BUILD";
    case SlotCapability::CodeTest: return "CODE_TEST";
    case SlotCapability::RepositoryRead: return "REPOSITORY_READ";
    case SlotCapability::RepositoryWrite: return "REPOSITORY_WRITE";
    case SlotCapability::AudioAnalyze: return "AUDIO_ANALYZE";
    case SlotCapability::AudioGenerate: return "AUDIO_GENERATE";
    case SlotCapability::WorldObserve: return "WORLD_OBSERVE";
    case SlotCapability::WorldMutate: return "WORLD_MUTATE";
    case SlotCapability::ImageGenerate: return "IMAGE_GENERATE";
    case SlotCapability::VideoRender: return "VIDEO_RENDER";
    case SlotCapability::TranslateRepresentation: return "TRANSLATE_REPRESENTATION";
    case SlotCapability::GenericTool: return "GENERIC_TOOL";
    }
    return "GENERIC_TOOL";
}

std::string_view to_string(InvocationStatus status) noexcept {
    switch (status) {
    case InvocationStatus::Ready: return "READY";
    case InvocationStatus::Invalid: return "INVALID";
    case InvocationStatus::SlotNotFound: return "SLOT_NOT_FOUND";
    case InvocationStatus::SlotDisabled: return "SLOT_DISABLED";
    case InvocationStatus::CapabilityMissing: return "CAPABILITY_MISSING";
    case InvocationStatus::PermissionMissing: return "PERMISSION_MISSING";
    case InvocationStatus::LayerMismatch: return "LAYER_MISMATCH";
    case InvocationStatus::PayloadTooLarge: return "PAYLOAD_TOO_LARGE";
    }
    return "INVALID";
}

} // namespace guff
