#pragma once

#include "guff/reality.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace guff {

enum class SlotKind : std::uint8_t {
    Model,
    Compiler,
    Repository,
    Audio,
    World,
    Image,
    Video,
    Language,
    Tool,
    Generic
};

enum class SlotTransport : std::uint8_t {
    InProcess,
    LocalProcess,
    Connector
};

enum class SlotCapability : std::uint8_t {
    ModelInfer,
    CodeBuild,
    CodeTest,
    RepositoryRead,
    RepositoryWrite,
    AudioAnalyze,
    AudioGenerate,
    WorldObserve,
    WorldMutate,
    ImageGenerate,
    VideoRender,
    TranslateRepresentation,
    GenericTool
};

enum class InvocationStatus : std::uint8_t {
    Ready,
    Invalid,
    SlotNotFound,
    SlotDisabled,
    CapabilityMissing,
    PermissionMissing,
    LayerMismatch,
    PayloadTooLarge
};

struct SlotManifest {
    std::uint32_t schema_version{1U};
    std::string slot_name;
    std::string display_name;
    std::string version;
    SlotKind kind{SlotKind::Generic};
    SlotTransport transport{SlotTransport::InProcess};
    std::string entrypoint;
    std::vector<SlotCapability> capabilities;
    std::vector<RealityLayer> allowed_layers;
    std::vector<std::string> required_permissions;
    std::size_t max_payload_bytes{64U * 1024U};
    bool enabled{true};
    std::vector<std::string> tags;

    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] std::string immutable_id() const;
    [[nodiscard]] bool supports(SlotCapability capability) const noexcept;
    [[nodiscard]] bool allows(RealityLayer layer) const noexcept;
};

struct SlotInvocation {
    std::string invocation_id;
    std::string slot_id;
    SlotCapability capability{SlotCapability::GenericTool};
    RealityLayer layer{RealityLayer::Application};
    std::string input_sha256;
    std::size_t payload_bytes{0U};
    std::vector<std::string> permission_tokens;
};

struct SlotResolution {
    InvocationStatus status{InvocationStatus::Invalid};
    std::optional<SlotManifest> slot;
    std::vector<std::string> missing_permissions;
    std::string reason;

    [[nodiscard]] bool ready() const noexcept;
};

class ClubhouseRegistry {
public:
    [[nodiscard]] bool register_slot(SlotManifest manifest,
                                     std::vector<std::string>* errors = nullptr);
    [[nodiscard]] std::optional<SlotManifest> find(std::string_view slot_id) const;
    [[nodiscard]] std::vector<SlotManifest> list() const;
    [[nodiscard]] SlotResolution resolve(const SlotInvocation& invocation) const;
    [[nodiscard]] std::size_t size() const noexcept;

private:
    std::unordered_map<std::string, SlotManifest> slots_;
    std::unordered_map<std::string, std::string> aliases_;
};

[[nodiscard]] std::string_view to_string(SlotKind kind) noexcept;
[[nodiscard]] std::string_view to_string(SlotTransport transport) noexcept;
[[nodiscard]] std::string_view to_string(SlotCapability capability) noexcept;
[[nodiscard]] std::string_view to_string(InvocationStatus status) noexcept;

} // namespace guff
