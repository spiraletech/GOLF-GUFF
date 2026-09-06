#pragma once

#include "guff/artifact_vault.hpp"
#include "guff/caddy_router.hpp"
#include "guff/data_leech.hpp"
#include "guff/forge.hpp"
#include "guff/gguf_inference.hpp"
#include "guff/hardware_profile.hpp"
#include "guff/model_registry.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace guff {

enum class KernelRole : std::uint8_t {
    Router,
    Fast,
    Code,
    World,
    Media,
    Deep
};

struct KernelCartridge {
    std::uint32_t schema_version{1U};
    KernelRole role{KernelRole::Fast};
    std::string model_id;
    std::string slot_name;
    bool enabled{true};
    std::vector<std::string> tags;

    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] std::string canonical_payload() const;
    [[nodiscard]] std::string immutable_id() const;
};

class KernelRoster {
public:
    [[nodiscard]] bool install(KernelCartridge cartridge,
                               std::vector<std::string>* errors = nullptr);
    [[nodiscard]] std::optional<KernelCartridge> find_model(
        std::string_view model_id) const;
    [[nodiscard]] std::vector<KernelCartridge> list(KernelRole role) const;
    [[nodiscard]] std::size_t size() const noexcept;

private:
    std::unordered_map<std::string, KernelCartridge> by_model_;
};

enum class KernelTaskStatus : std::uint8_t {
    Completed,
    InvalidRequest,
    RouteRejected,
    KernelUnavailable,
    ArtifactUnavailable,
    BindingMismatch,
    ContextRejected,
    InvocationRejected,
    ExecutionFailed,
    VerificationFailed
};

struct KernelVerification {
    bool transport_integrity{false};
    bool semantic_verified{false};
    double confidence{0.0};
    std::string reason;

    [[nodiscard]] bool accepted(bool semantic_required) const noexcept;
};

struct KernelTaskRequest {
    std::string correlation_id;
    std::string instruction;
    ModelRouteRequest route_request;
    std::vector<ContextSlice> context_slices;
    ContextBudget context_budget{};
    ArtifactResolveMode artifact_mode{ArtifactResolveMode::CacheOnly};
    ForgeBudget forge_budget{};
    std::vector<std::string> permission_tokens{"model:infer", "device:execute"};
    bool require_semantic_verification{false};
};

struct KernelTaskProvenance {
    std::uint32_t schema_version{1U};
    std::string correlation_id;
    std::string model_id;
    KernelRole role{KernelRole::Fast};
    std::string cartridge_id;
    std::string artifact_id;
    std::string source_uri;
    std::string binding_id;
    std::string slot_immutable_id;
    std::string hardware_id;
    std::string prompt_sha256;
    std::string context_sha256;
    std::string answer_sha256;
    std::string route_trace_sha256;
    std::size_t context_slices{0U};
    std::size_t context_bytes{0U};
    std::size_t answer_bytes{0U};
    std::uint64_t wall_time_ms{0U};
    bool artifact_from_cache{false};
    bool semantic_verified{false};

    [[nodiscard]] std::string canonical_payload() const;
    [[nodiscard]] std::string immutable_id() const;
};

struct KernelTaskResult {
    KernelTaskStatus status{KernelTaskStatus::InvalidRequest};
    ModelRouteDecision route;
    std::optional<KernelCartridge> cartridge;
    std::optional<ResolvedArtifact> artifact;
    std::optional<ForgeExecutionResult> execution;
    KernelVerification verification;
    std::optional<KernelTaskProvenance> provenance;
    std::string answer;
    std::string reason;

    [[nodiscard]] bool succeeded() const noexcept;
};

class KernelTaskRunner {
public:
    using SemanticVerifier = std::function<KernelVerification(
        const KernelTaskRequest& request,
        std::string_view answer)>;

    KernelTaskRunner(const ModelRegistry& models,
                     const CaddyRouter& router,
                     const ClubhouseRegistry& clubhouse,
                     const KernelRoster& roster,
                     const ArtifactVault& vault,
                     const GgufInferenceBridge& bridge) noexcept;

    [[nodiscard]] KernelTaskResult run(
        const KernelTaskRequest& request,
        const HardwareProfile& hardware,
        const ArtifactVault::FetchFunction& fetcher = {},
        const SemanticVerifier& verifier = {}) const;

private:
    const ModelRegistry& models_;
    const CaddyRouter& router_;
    const ClubhouseRegistry& clubhouse_;
    const KernelRoster& roster_;
    const ArtifactVault& vault_;
    const GgufInferenceBridge& bridge_;
};

[[nodiscard]] std::string_view to_string(KernelRole role) noexcept;
[[nodiscard]] std::string_view to_string(KernelTaskStatus status) noexcept;

} // namespace guff
