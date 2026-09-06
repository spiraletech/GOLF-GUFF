#pragma once

#include "guff/authority_receipt.hpp"
#include "guff/policy_engine.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class PolicyControlAction : std::uint8_t {
    Activate,
    Rollback,
    Revoke
};

enum class PolicyRegistryStatus : std::uint8_t {
    Ready,
    Invalid,
    SignatureRejected,
    PackageNotFound,
    AlreadyRegistered,
    PolicyRevoked,
    ActiveMismatch,
    ReplayRejected,
    CapacityExceeded,
    StorageFailure,
    Corrupt
};

struct SignedPolicyPackage {
    std::uint32_t schema_version{1U};
    std::string policy_id;
    std::string signer_id;
    std::string algorithm;
    std::uint64_t signed_at_unix_ms{0U};
    std::string signature;
    std::string package_id;
};

struct PolicyControlEnvelope {
    std::uint32_t schema_version{1U};
    PolicyControlAction action{PolicyControlAction::Activate};
    std::string package_id;
    std::string policy_id;
    std::string expected_active_policy_id;
    std::string actor_reference;
    std::string signer_id;
    std::uint64_t issued_at_unix_ms{0U};
    std::string nonce;
    std::string reason_sha256;
};

struct SignedPolicyControl {
    PolicyControlEnvelope envelope;
    std::string algorithm;
    std::string envelope_sha256;
    std::string signature;
    std::string control_id;
};

struct PolicyRegistryBudget {
    std::size_t max_policies{256U};
    std::size_t max_records{4096U};
    std::size_t max_actor_bytes{256U};
    std::size_t max_nonce_bytes{128U};
};

struct PolicyRegistryResult {
    PolicyRegistryStatus status{PolicyRegistryStatus::Invalid};
    std::string policy_id;
    std::string package_id;
    std::string active_policy_id;
    std::string record_sha256;
    std::string reason;

    [[nodiscard]] bool ok() const noexcept;
};

struct PolicyRegistrySnapshot {
    bool healthy{true};
    std::size_t records{0U};
    std::size_t registered_policies{0U};
    std::size_t revoked_policies{0U};
    std::size_t activation_generation{0U};
    std::string active_policy_id;
    std::string active_package_id;
    std::vector<std::string> errors;
};

[[nodiscard]] std::string canonical_signed_policy_payload(
    const PolicyDocument& policy,
    std::uint64_t signed_at_unix_ms,
    std::string_view signer_id);
[[nodiscard]] std::optional<SignedPolicyPackage> issue_signed_policy_package(
    const PolicyDocument& policy,
    std::uint64_t signed_at_unix_ms,
    const AuthoritySigner& signer,
    std::vector<std::string>* errors = nullptr);
[[nodiscard]] bool verify_signed_policy_package(
    const PolicyDocument& policy,
    const SignedPolicyPackage& package,
    const AuthorityVerifier& verifier,
    std::vector<std::string>* errors = nullptr);

[[nodiscard]] std::string canonical_policy_control(
    const PolicyControlEnvelope& envelope);
[[nodiscard]] std::optional<SignedPolicyControl> issue_signed_policy_control(
    const PolicyControlEnvelope& envelope,
    const AuthoritySigner& signer,
    std::vector<std::string>* errors = nullptr);
[[nodiscard]] bool verify_signed_policy_control(
    const SignedPolicyControl& control,
    const AuthorityVerifier& verifier,
    std::vector<std::string>* errors = nullptr);

class SignedPolicyRegistry {
public:
    SignedPolicyRegistry(std::filesystem::path journal_path,
                         const AuthorityVerifier& package_verifier,
                         const AuthorityVerifier& control_verifier,
                         PolicyRegistryBudget budget = {});

    [[nodiscard]] PolicyRegistryResult register_policy(
        const PolicyDocument& policy,
        const SignedPolicyPackage& package);
    [[nodiscard]] PolicyRegistryResult apply_control(
        const SignedPolicyControl& control);
    [[nodiscard]] PolicyRegistrySnapshot inspect() const;
    [[nodiscard]] bool is_active(const PolicyDocument& policy) const;
    [[nodiscard]] bool is_policy_active(std::string_view policy_id) const;
    [[nodiscard]] std::string active_policy_id() const;
    [[nodiscard]] std::string active_package_id() const;
    [[nodiscard]] std::optional<SignedPolicyPackage> package(
        std::string_view policy_id) const;
    [[nodiscard]] std::optional<SignedPolicyPackage> active_package() const;
    [[nodiscard]] const std::filesystem::path& path() const noexcept;

private:
    std::filesystem::path journal_path_;
    const AuthorityVerifier& package_verifier_;
    const AuthorityVerifier& control_verifier_;
    PolicyRegistryBudget budget_;
};

class RegistryBackedPolicyEngine {
public:
    RegistryBackedPolicyEngine(const SignedPolicyRegistry& registry,
                               PolicyDocument policy,
                               const RuntimeIdentityStore& identity_store,
                               PolicyEvaluationBudget budget = {});

    [[nodiscard]] PolicyEvaluationResult evaluate(
        const PolicyEvaluationRequest& request) const;
    [[nodiscard]] const PolicyDocument& policy() const noexcept;

private:
    const SignedPolicyRegistry& registry_;
    PolicyDocument policy_;
    const RuntimeIdentityStore& identity_store_;
    PolicyEvaluationBudget budget_;
};

[[nodiscard]] std::string_view to_string(PolicyControlAction action) noexcept;
[[nodiscard]] std::string_view to_string(PolicyRegistryStatus status) noexcept;

} // namespace guff
