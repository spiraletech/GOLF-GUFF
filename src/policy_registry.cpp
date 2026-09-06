#include "guff/policy_registry.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace guff {
namespace {

constexpr std::string_view kPolicyPrefix = "guff:policy:sha256:";
constexpr std::string_view kPackagePrefix = "guff:policy-package:sha256:";
constexpr std::string_view kControlPrefix = "guff:policy-control:sha256:";
constexpr std::size_t kMaxLineBytes = 64U * 1024U;

enum class RecordKind : std::uint8_t { Register, Activate, Rollback, Revoke };

struct RegistryRecord {
    std::uint32_t schema_version{1U};
    std::size_t sequence{0U};
    RecordKind kind{RecordKind::Register};
    std::string policy_id;
    std::string package_id;
    std::string signer_id;
    std::string algorithm;
    std::uint64_t signed_at_unix_ms{0U};
    std::string signature;
    std::string control_id;
    std::string nonce;
    std::string actor_reference;
    std::string expected_active_policy_id;
    std::uint64_t issued_at_unix_ms{0U};
    std::string reason_sha256;
    std::string previous_record_sha256;
    std::string record_sha256;
};

struct StoredPolicy {
    SignedPolicyPackage package;
    bool revoked{false};
    bool ever_active{false};
};

struct ScanState {
    bool healthy{true};
    std::size_t next_sequence{0U};
    std::string head_sha256{std::string(64U, '0')};
    std::map<std::string, StoredPolicy> policies;
    std::unordered_map<std::string, std::string> package_to_policy;
    std::unordered_set<std::string> used_controls;
    std::unordered_map<std::string, std::string> nonce_to_control;
    std::string active_policy_id;
    std::string active_package_id;
    std::size_t activation_generation{0U};
    std::vector<std::string> errors;
};

bool canonical_id(std::string_view value, std::string_view prefix) noexcept {
    return value.starts_with(prefix) && is_sha256(value.substr(prefix.size()));
}

bool valid_text(std::string_view value, std::size_t max_bytes) {
    if (value.empty() || value.size() > max_bytes) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch >= 0x20U && ch != 0x7fU;
    });
}

bool valid_optional_text(std::string_view value, std::size_t max_bytes) {
    return value.empty() || valid_text(value, max_bytes);
}

std::string hex_encode(std::string_view input) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(input.size() * 2U);
    for (const auto ch : input) {
        const auto value = static_cast<unsigned char>(ch);
        out.push_back(digits[(value >> 4U) & 0x0fU]);
        out.push_back(digits[value & 0x0fU]);
    }
    return out;
}

std::optional<std::string> hex_decode(std::string_view input) {
    if ((input.size() % 2U) != 0U) return std::nullopt;
    auto nibble = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(input.size() / 2U);
    for (std::size_t i = 0U; i < input.size(); i += 2U) {
        const int high = nibble(input[i]);
        const int low = nibble(input[i + 1U]);
        if (high < 0 || low < 0) return std::nullopt;
        out.push_back(static_cast<char>((high << 4) | low));
    }
    return out;
}

std::vector<std::string_view> split_tabs(std::string_view line) {
    std::vector<std::string_view> out;
    std::size_t start = 0U;
    while (start <= line.size()) {
        const auto next = line.find('\t', start);
        if (next == std::string_view::npos) {
            out.push_back(line.substr(start));
            break;
        }
        out.push_back(line.substr(start, next - start));
        start = next + 1U;
    }
    return out;
}

template <typename T>
bool parse_unsigned(std::string_view value, T* out) {
    if (!out || value.empty()) return false;
    T parsed{};
    const auto* begin = value.data();
    const auto* end = begin + value.size();
    const auto [ptr, ec] = std::from_chars(begin, end, parsed);
    if (ec != std::errc{} || ptr != end) return false;
    *out = parsed;
    return true;
}

std::string package_id_for(const SignedPolicyPackage& package) {
    std::ostringstream out;
    out << package.schema_version << '\n'
        << package.policy_id << '\n'
        << package.signer_id << '\n'
        << package.algorithm << '\n'
        << package.signed_at_unix_ms << '\n'
        << package.signature;
    return std::string(kPackagePrefix) + sha256(out.str());
}

std::string control_id_for(const SignedPolicyControl& control) {
    std::ostringstream out;
    out << canonical_policy_control(control.envelope) << '\n'
        << control.algorithm << '\n'
        << control.signature;
    return std::string(kControlPrefix) + sha256(out.str());
}

std::string canonical_record(const RegistryRecord& record) {
    std::ostringstream out;
    out << record.schema_version << '\n'
        << record.sequence << '\n'
        << static_cast<unsigned>(record.kind) << '\n'
        << record.policy_id << '\n'
        << record.package_id << '\n'
        << record.signer_id << '\n'
        << record.algorithm << '\n'
        << record.signed_at_unix_ms << '\n'
        << record.signature << '\n'
        << record.control_id << '\n'
        << record.nonce << '\n'
        << record.actor_reference << '\n'
        << record.expected_active_policy_id << '\n'
        << record.issued_at_unix_ms << '\n'
        << record.reason_sha256 << '\n'
        << record.previous_record_sha256;
    return out.str();
}

std::string serialize(const RegistryRecord& record) {
    std::ostringstream out;
    out << "PREG\t"
        << record.schema_version << '\t'
        << record.sequence << '\t'
        << static_cast<unsigned>(record.kind) << '\t'
        << record.policy_id << '\t'
        << record.package_id << '\t'
        << hex_encode(record.signer_id) << '\t'
        << hex_encode(record.algorithm) << '\t'
        << record.signed_at_unix_ms << '\t'
        << hex_encode(record.signature) << '\t'
        << (record.control_id.empty() ? "-" : record.control_id) << '\t'
        << hex_encode(record.nonce) << '\t'
        << hex_encode(record.actor_reference) << '\t'
        << (record.expected_active_policy_id.empty() ? "-" : record.expected_active_policy_id) << '\t'
        << record.issued_at_unix_ms << '\t'
        << (record.reason_sha256.empty() ? "-" : record.reason_sha256) << '\t'
        << record.previous_record_sha256 << '\t'
        << record.record_sha256;
    return out.str();
}

std::optional<RegistryRecord> deserialize(std::string_view line, std::string* error) {
    if (line.empty() || line.size() > kMaxLineBytes) {
        if (error) *error = "policy registry record is empty or exceeds line ceiling";
        return std::nullopt;
    }
    const auto fields = split_tabs(line);
    if (fields.size() != 18U || fields[0] != "PREG") {
        if (error) *error = "policy registry field count/marker is invalid";
        return std::nullopt;
    }

    RegistryRecord record;
    unsigned kind = 0U;
    if (!parse_unsigned(fields[1], &record.schema_version) ||
        !parse_unsigned(fields[2], &record.sequence) ||
        !parse_unsigned(fields[3], &kind) ||
        !parse_unsigned(fields[8], &record.signed_at_unix_ms) ||
        !parse_unsigned(fields[14], &record.issued_at_unix_ms) ||
        record.schema_version != 1U || kind > static_cast<unsigned>(RecordKind::Revoke)) {
        if (error) *error = "policy registry numeric/schema field is invalid";
        return std::nullopt;
    }

    auto signer = hex_decode(fields[6]);
    auto algorithm = hex_decode(fields[7]);
    auto signature = hex_decode(fields[9]);
    auto nonce = hex_decode(fields[11]);
    auto actor = hex_decode(fields[12]);
    if (!signer || !algorithm || !signature || !nonce || !actor) {
        if (error) *error = "policy registry hex field is invalid";
        return std::nullopt;
    }

    record.kind = static_cast<RecordKind>(kind);
    record.policy_id = std::string(fields[4]);
    record.package_id = std::string(fields[5]);
    record.signer_id = std::move(*signer);
    record.algorithm = std::move(*algorithm);
    record.signature = std::move(*signature);
    record.control_id = fields[10] == "-" ? std::string{} : std::string(fields[10]);
    record.nonce = std::move(*nonce);
    record.actor_reference = std::move(*actor);
    record.expected_active_policy_id = fields[13] == "-" ? std::string{} : std::string(fields[13]);
    record.reason_sha256 = fields[15] == "-" ? std::string{} : std::string(fields[15]);
    record.previous_record_sha256 = std::string(fields[16]);
    record.record_sha256 = std::string(fields[17]);

    if (!canonical_id(record.policy_id, kPolicyPrefix) ||
        !canonical_id(record.package_id, kPackagePrefix) ||
        !valid_text(record.signer_id, 256U) || !valid_text(record.algorithm, 128U) ||
        record.signature.empty() || record.signature.size() > 8192U ||
        !is_sha256(record.previous_record_sha256) || !is_sha256(record.record_sha256)) {
        if (error) *error = "policy registry common field validation failed";
        return std::nullopt;
    }

    if (record.kind == RecordKind::Register) {
        if (!record.control_id.empty() || !record.nonce.empty() || !record.actor_reference.empty() ||
            !record.expected_active_policy_id.empty() || record.issued_at_unix_ms != 0U ||
            !record.reason_sha256.empty()) {
            if (error) *error = "REGISTER contains control-only fields";
            return std::nullopt;
        }
        SignedPolicyPackage package;
        package.policy_id = record.policy_id;
        package.signer_id = record.signer_id;
        package.algorithm = record.algorithm;
        package.signed_at_unix_ms = record.signed_at_unix_ms;
        package.signature = record.signature;
        package.package_id = record.package_id;
        if (package_id_for(package) != record.package_id) {
            if (error) *error = "registered package identity mismatch";
            return std::nullopt;
        }
    } else {
        if (!canonical_id(record.control_id, kControlPrefix) ||
            !valid_text(record.nonce, 128U) || !valid_text(record.actor_reference, 256U) ||
            (!record.expected_active_policy_id.empty() &&
             !canonical_id(record.expected_active_policy_id, kPolicyPrefix)) ||
            !is_sha256(record.reason_sha256)) {
            if (error) *error = "control record validation failed";
            return std::nullopt;
        }
        PolicyControlEnvelope envelope;
        envelope.action = record.kind == RecordKind::Activate ? PolicyControlAction::Activate :
                          record.kind == RecordKind::Rollback ? PolicyControlAction::Rollback :
                                                               PolicyControlAction::Revoke;
        envelope.package_id = record.package_id;
        envelope.policy_id = record.policy_id;
        envelope.expected_active_policy_id = record.expected_active_policy_id;
        envelope.actor_reference = record.actor_reference;
        envelope.signer_id = record.signer_id;
        envelope.issued_at_unix_ms = record.issued_at_unix_ms;
        envelope.nonce = record.nonce;
        envelope.reason_sha256 = record.reason_sha256;
        SignedPolicyControl control;
        control.envelope = std::move(envelope);
        control.algorithm = record.algorithm;
        control.signature = record.signature;
        control.envelope_sha256 = sha256(canonical_policy_control(control.envelope));
        control.control_id = record.control_id;
        if (control_id_for(control) != record.control_id) {
            if (error) *error = "control identity mismatch";
            return std::nullopt;
        }
    }

    if (record.record_sha256 != sha256(canonical_record(record))) {
        if (error) *error = "policy registry record hash mismatch";
        return std::nullopt;
    }
    return record;
}

ScanState scan_registry(const std::filesystem::path& path,
                        const PolicyRegistryBudget& budget) {
    ScanState state;
    std::error_code ec;
    const bool exists = std::filesystem::exists(path, ec);
    if (ec) {
        state.healthy = false;
        state.errors.emplace_back("failed to inspect policy registry path");
        return state;
    }
    if (!exists) return state;

    std::ifstream input(path);
    if (!input) {
        state.healthy = false;
        state.errors.emplace_back("failed to open policy registry journal");
        return state;
    }

    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (state.next_sequence >= budget.max_records) {
            state.healthy = false;
            state.errors.emplace_back("policy registry record ceiling exceeded");
            break;
        }
        std::string error;
        auto record = deserialize(line, &error);
        if (!record) {
            state.healthy = false;
            state.errors.push_back("record " + std::to_string(state.next_sequence) + ": " + error);
            break;
        }
        if (record->sequence != state.next_sequence) {
            state.healthy = false;
            state.errors.emplace_back("policy registry sequence discontinuity");
            break;
        }
        if (record->previous_record_sha256 != state.head_sha256) {
            state.healthy = false;
            state.errors.emplace_back("policy registry hash-chain discontinuity");
            break;
        }

        if (record->kind == RecordKind::Register) {
            if (state.policies.size() >= budget.max_policies) {
                state.healthy = false;
                state.errors.emplace_back("registered policy ceiling exceeded during replay");
                break;
            }
            if (state.policies.contains(record->policy_id) ||
                state.package_to_policy.contains(record->package_id)) {
                state.healthy = false;
                state.errors.emplace_back("duplicate immutable policy/package registration");
                break;
            }
            SignedPolicyPackage package;
            package.policy_id = record->policy_id;
            package.signer_id = record->signer_id;
            package.algorithm = record->algorithm;
            package.signed_at_unix_ms = record->signed_at_unix_ms;
            package.signature = record->signature;
            package.package_id = record->package_id;
            state.package_to_policy.emplace(record->package_id, record->policy_id);
            state.policies.emplace(record->policy_id, StoredPolicy{std::move(package), false, false});
        } else {
            if (record->expected_active_policy_id != state.active_policy_id) {
                state.healthy = false;
                state.errors.emplace_back("control record expected-active compare-and-swap mismatch");
                break;
            }
            if (!state.used_controls.emplace(record->control_id).second) {
                state.healthy = false;
                state.errors.emplace_back("duplicate policy control identity in journal");
                break;
            }
            const std::string nonce_key = record->signer_id + "\n" + record->nonce;
            const auto [nonce_it, inserted] = state.nonce_to_control.emplace(nonce_key, record->control_id);
            if (!inserted && nonce_it->second != record->control_id) {
                state.healthy = false;
                state.errors.emplace_back("policy control signer/nonce replay collision");
                break;
            }
            const auto package_it = state.package_to_policy.find(record->package_id);
            if (package_it == state.package_to_policy.end() || package_it->second != record->policy_id) {
                state.healthy = false;
                state.errors.emplace_back("control references unknown or mismatched package");
                break;
            }
            auto policy_it = state.policies.find(record->policy_id);
            if (policy_it == state.policies.end()) {
                state.healthy = false;
                state.errors.emplace_back("control references unknown policy");
                break;
            }

            if (record->kind == RecordKind::Revoke) {
                if (policy_it->second.revoked) {
                    state.healthy = false;
                    state.errors.emplace_back("policy revoked more than once");
                    break;
                }
                policy_it->second.revoked = true;
                if (state.active_policy_id == record->policy_id) {
                    state.active_policy_id.clear();
                    state.active_package_id.clear();
                    ++state.activation_generation;
                }
            } else {
                if (policy_it->second.revoked) {
                    state.healthy = false;
                    state.errors.emplace_back("revoked policy activated during replay");
                    break;
                }
                if (record->kind == RecordKind::Rollback && !policy_it->second.ever_active) {
                    state.healthy = false;
                    state.errors.emplace_back("rollback target was never previously active");
                    break;
                }
                if (state.active_policy_id == record->policy_id) {
                    state.healthy = false;
                    state.errors.emplace_back("activation target is already active");
                    break;
                }
                state.active_policy_id = record->policy_id;
                state.active_package_id = record->package_id;
                policy_it->second.ever_active = true;
                ++state.activation_generation;
            }
        }

        state.head_sha256 = record->record_sha256;
        ++state.next_sequence;
    }
    if (!input.eof() && input.fail()) {
        state.healthy = false;
        state.errors.emplace_back("policy registry read failed before EOF");
    }
    return state;
}

PolicyRegistryResult append_record(const std::filesystem::path& path,
                                   RegistryRecord record) {
    PolicyRegistryResult result;
    const auto parent = path.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            result.status = PolicyRegistryStatus::StorageFailure;
            result.reason = "failed to create policy registry parent directory";
            return result;
        }
    }

    record.record_sha256 = sha256(canonical_record(record));
    const auto line = serialize(record);
    if (line.size() > kMaxLineBytes) {
        result.status = PolicyRegistryStatus::Invalid;
        result.reason = "serialized policy registry record exceeds line ceiling";
        return result;
    }
    std::ofstream output(path, std::ios::app);
    if (!output) {
        result.status = PolicyRegistryStatus::StorageFailure;
        result.reason = "failed to open policy registry for append";
        return result;
    }
    output << line << '\n';
    output.flush();
    if (!output) {
        result.status = PolicyRegistryStatus::StorageFailure;
        result.reason = "policy registry append/flush failed";
        return result;
    }
    result.status = PolicyRegistryStatus::Ready;
    result.policy_id = record.policy_id;
    result.package_id = record.package_id;
    result.record_sha256 = record.record_sha256;
    return result;
}

PolicyEvaluationResult inactive_policy_result(const PolicyDocument& policy,
                                              const PolicyEvaluationRequest& request,
                                              std::string reason) {
    PolicyEvaluationResult result;
    result.status = PolicyEvaluationStatus::PolicyInactive;
    result.decision = PolicyDecision::Refuse;
    result.risk = classify_policy_risk(request.operation);
    result.policy_id = policy.immutable_id();
    result.reason = std::move(reason);
    result.trace.push_back({"REFUSE", result.reason});
    return result;
}

} // namespace

bool PolicyRegistryResult::ok() const noexcept {
    return status == PolicyRegistryStatus::Ready;
}

std::string canonical_signed_policy_payload(const PolicyDocument& policy,
                                            std::uint64_t signed_at_unix_ms,
                                            std::string_view signer_id) {
    std::ostringstream out;
    out << "GOLF-POLICY-PACKAGE-V1\n"
        << policy.immutable_id() << '\n'
        << signed_at_unix_ms << '\n'
        << signer_id.size() << ':' << signer_id << '\n'
        << policy.canonical_payload();
    return out.str();
}

std::optional<SignedPolicyPackage> issue_signed_policy_package(
    const PolicyDocument& policy,
    std::uint64_t signed_at_unix_ms,
    const AuthoritySigner& signer,
    std::vector<std::string>* errors) {
    std::vector<std::string> local = policy.validate();
    const auto signer_id = signer.signer_id();
    const auto algorithm = signer.algorithm();
    if (!valid_text(signer_id, 256U)) local.emplace_back("policy signer_id is invalid");
    if (!valid_text(algorithm, 128U)) local.emplace_back("policy signing algorithm is invalid");
    if (signed_at_unix_ms == 0U) local.emplace_back("policy signed_at_unix_ms must be nonzero");
    if (!local.empty()) {
        if (errors) *errors = std::move(local);
        return std::nullopt;
    }
    const auto payload = canonical_signed_policy_payload(policy, signed_at_unix_ms, signer_id);
    auto signature = signer.sign(payload);
    if (!signature || signature->empty()) {
        if (errors) errors->emplace_back("policy signer refused package");
        return std::nullopt;
    }
    SignedPolicyPackage package;
    package.policy_id = policy.immutable_id();
    package.signer_id = signer_id;
    package.algorithm = algorithm;
    package.signed_at_unix_ms = signed_at_unix_ms;
    package.signature = std::move(*signature);
    package.package_id = package_id_for(package);
    return package;
}

bool verify_signed_policy_package(const PolicyDocument& policy,
                                  const SignedPolicyPackage& package,
                                  const AuthorityVerifier& verifier,
                                  std::vector<std::string>* errors) {
    std::vector<std::string> local = policy.validate();
    if (package.schema_version != 1U) local.emplace_back("policy package schema_version must be 1");
    if (package.policy_id != policy.immutable_id()) local.emplace_back("policy package identity does not match document");
    if (!canonical_id(package.package_id, kPackagePrefix) || package.package_id != package_id_for(package))
        local.emplace_back("policy package immutable identity mismatch");
    if (!valid_text(package.signer_id, 256U) || !valid_text(package.algorithm, 128U) ||
        package.signed_at_unix_ms == 0U || package.signature.empty())
        local.emplace_back("policy package signing metadata is invalid");
    if (!local.empty()) {
        if (errors) *errors = std::move(local);
        return false;
    }
    if (!verifier.knows(package.signer_id, package.algorithm)) {
        if (errors) errors->emplace_back("policy package signer is not trusted");
        return false;
    }
    const auto payload = canonical_signed_policy_payload(policy, package.signed_at_unix_ms, package.signer_id);
    if (!verifier.verify(package.signer_id, package.algorithm, payload, package.signature)) {
        if (errors) errors->emplace_back("policy package signature rejected");
        return false;
    }
    return true;
}

std::string canonical_policy_control(const PolicyControlEnvelope& envelope) {
    std::ostringstream out;
    out << envelope.schema_version << '\n'
        << to_string(envelope.action) << '\n'
        << envelope.package_id << '\n'
        << envelope.policy_id << '\n'
        << envelope.expected_active_policy_id << '\n'
        << envelope.actor_reference << '\n'
        << envelope.signer_id << '\n'
        << envelope.issued_at_unix_ms << '\n'
        << envelope.nonce << '\n'
        << envelope.reason_sha256;
    return out.str();
}

std::optional<SignedPolicyControl> issue_signed_policy_control(
    const PolicyControlEnvelope& input,
    const AuthoritySigner& signer,
    std::vector<std::string>* errors) {
    PolicyControlEnvelope envelope = input;
    envelope.signer_id = signer.signer_id();
    std::vector<std::string> local;
    if (envelope.schema_version != 1U) local.emplace_back("policy control schema_version must be 1");
    if (!canonical_id(envelope.package_id, kPackagePrefix)) local.emplace_back("policy control package_id is invalid");
    if (!canonical_id(envelope.policy_id, kPolicyPrefix)) local.emplace_back("policy control policy_id is invalid");
    if (!envelope.expected_active_policy_id.empty() &&
        !canonical_id(envelope.expected_active_policy_id, kPolicyPrefix))
        local.emplace_back("policy control expected_active_policy_id is invalid");
    if (!valid_text(envelope.actor_reference, 256U)) local.emplace_back("policy control actor_reference is invalid");
    if (!valid_text(envelope.signer_id, 256U)) local.emplace_back("policy control signer_id is invalid");
    if (envelope.issued_at_unix_ms == 0U) local.emplace_back("policy control issued_at_unix_ms must be nonzero");
    if (!valid_text(envelope.nonce, 128U)) local.emplace_back("policy control nonce is invalid");
    if (!is_sha256(envelope.reason_sha256)) local.emplace_back("policy control reason_sha256 must be SHA-256");
    if (!valid_text(signer.algorithm(), 128U)) local.emplace_back("policy control algorithm is invalid");
    if (!local.empty()) {
        if (errors) *errors = std::move(local);
        return std::nullopt;
    }
    const auto canonical = canonical_policy_control(envelope);
    auto signature = signer.sign(canonical);
    if (!signature || signature->empty()) {
        if (errors) errors->emplace_back("policy control signer refused request");
        return std::nullopt;
    }
    SignedPolicyControl control;
    control.envelope = std::move(envelope);
    control.algorithm = signer.algorithm();
    control.envelope_sha256 = sha256(canonical);
    control.signature = std::move(*signature);
    control.control_id = control_id_for(control);
    return control;
}

bool verify_signed_policy_control(const SignedPolicyControl& control,
                                  const AuthorityVerifier& verifier,
                                  std::vector<std::string>* errors) {
    std::vector<std::string> local;
    const auto& envelope = control.envelope;
    if (envelope.schema_version != 1U || !canonical_id(envelope.package_id, kPackagePrefix) ||
        !canonical_id(envelope.policy_id, kPolicyPrefix) ||
        (!envelope.expected_active_policy_id.empty() &&
         !canonical_id(envelope.expected_active_policy_id, kPolicyPrefix)) ||
        !valid_text(envelope.actor_reference, 256U) || !valid_text(envelope.signer_id, 256U) ||
        envelope.issued_at_unix_ms == 0U || !valid_text(envelope.nonce, 128U) ||
        !is_sha256(envelope.reason_sha256) || !valid_text(control.algorithm, 128U) ||
        control.signature.empty()) {
        local.emplace_back("policy control is malformed");
    }
    const auto canonical = canonical_policy_control(envelope);
    if (control.envelope_sha256 != sha256(canonical)) local.emplace_back("policy control envelope hash mismatch");
    if (!canonical_id(control.control_id, kControlPrefix) || control.control_id != control_id_for(control))
        local.emplace_back("policy control immutable identity mismatch");
    if (!local.empty()) {
        if (errors) *errors = std::move(local);
        return false;
    }
    if (!verifier.knows(envelope.signer_id, control.algorithm)) {
        if (errors) errors->emplace_back("policy control signer is not trusted");
        return false;
    }
    if (!verifier.verify(envelope.signer_id, control.algorithm, canonical, control.signature)) {
        if (errors) errors->emplace_back("policy control signature rejected");
        return false;
    }
    return true;
}

SignedPolicyRegistry::SignedPolicyRegistry(std::filesystem::path journal_path,
                                           const AuthorityVerifier& package_verifier,
                                           const AuthorityVerifier& control_verifier,
                                           PolicyRegistryBudget budget)
    : journal_path_(std::move(journal_path)),
      package_verifier_(package_verifier),
      control_verifier_(control_verifier),
      budget_(budget) {}

PolicyRegistryResult SignedPolicyRegistry::register_policy(
    const PolicyDocument& policy,
    const SignedPolicyPackage& package) {
    PolicyRegistryResult result;
    std::vector<std::string> errors;
    if (!verify_signed_policy_package(policy, package, package_verifier_, &errors)) {
        result.status = errors.empty() ? PolicyRegistryStatus::Invalid : PolicyRegistryStatus::SignatureRejected;
        result.reason = errors.empty() ? "policy package invalid" : errors.front();
        return result;
    }
    if (budget_.max_policies == 0U || budget_.max_records == 0U ||
        budget_.max_actor_bytes == 0U || budget_.max_nonce_bytes == 0U) {
        result.status = PolicyRegistryStatus::Invalid;
        result.reason = "policy registry budget contains a zero ceiling";
        return result;
    }
    const auto scan = scan_registry(journal_path_, budget_);
    if (!scan.healthy) {
        result.status = PolicyRegistryStatus::Corrupt;
        result.reason = scan.errors.empty() ? "policy registry is unhealthy" : scan.errors.front();
        return result;
    }
    if (scan.next_sequence >= budget_.max_records) {
        result.status = PolicyRegistryStatus::CapacityExceeded;
        result.reason = "policy registry record ceiling reached";
        return result;
    }
    if (scan.policies.contains(package.policy_id) || scan.package_to_policy.contains(package.package_id)) {
        result.status = PolicyRegistryStatus::AlreadyRegistered;
        result.reason = "immutable policy/package is already registered";
        return result;
    }
    if (scan.policies.size() >= budget_.max_policies) {
        result.status = PolicyRegistryStatus::CapacityExceeded;
        result.reason = "registered policy ceiling reached";
        return result;
    }

    RegistryRecord record;
    record.sequence = scan.next_sequence;
    record.kind = RecordKind::Register;
    record.policy_id = package.policy_id;
    record.package_id = package.package_id;
    record.signer_id = package.signer_id;
    record.algorithm = package.algorithm;
    record.signed_at_unix_ms = package.signed_at_unix_ms;
    record.signature = package.signature;
    record.previous_record_sha256 = scan.head_sha256;
    result = append_record(journal_path_, std::move(record));
    result.active_policy_id = scan.active_policy_id;
    return result;
}

PolicyRegistryResult SignedPolicyRegistry::apply_control(
    const SignedPolicyControl& control) {
    PolicyRegistryResult result;
    std::vector<std::string> errors;
    if (!verify_signed_policy_control(control, control_verifier_, &errors)) {
        result.status = PolicyRegistryStatus::SignatureRejected;
        result.reason = errors.empty() ? "policy control invalid" : errors.front();
        return result;
    }
    if (control.envelope.actor_reference.size() > budget_.max_actor_bytes ||
        control.envelope.nonce.size() > budget_.max_nonce_bytes) {
        result.status = PolicyRegistryStatus::Invalid;
        result.reason = "policy control exceeds registry actor/nonce budget";
        return result;
    }
    const auto scan = scan_registry(journal_path_, budget_);
    if (!scan.healthy) {
        result.status = PolicyRegistryStatus::Corrupt;
        result.reason = scan.errors.empty() ? "policy registry is unhealthy" : scan.errors.front();
        return result;
    }
    if (scan.next_sequence >= budget_.max_records) {
        result.status = PolicyRegistryStatus::CapacityExceeded;
        result.reason = "policy registry record ceiling reached";
        return result;
    }
    if (scan.used_controls.contains(control.control_id)) {
        result.status = PolicyRegistryStatus::ReplayRejected;
        result.reason = "policy control identity was already consumed";
        return result;
    }
    const std::string nonce_key = control.envelope.signer_id + "\n" + control.envelope.nonce;
    const auto nonce_it = scan.nonce_to_control.find(nonce_key);
    if (nonce_it != scan.nonce_to_control.end() && nonce_it->second != control.control_id) {
        result.status = PolicyRegistryStatus::ReplayRejected;
        result.reason = "policy control signer/nonce collision";
        return result;
    }
    if (control.envelope.expected_active_policy_id != scan.active_policy_id) {
        result.status = PolicyRegistryStatus::ActiveMismatch;
        result.reason = "policy control expected-active compare-and-swap failed";
        return result;
    }
    const auto package_it = scan.package_to_policy.find(control.envelope.package_id);
    if (package_it == scan.package_to_policy.end() || package_it->second != control.envelope.policy_id) {
        result.status = PolicyRegistryStatus::PackageNotFound;
        result.reason = "policy control references an unknown or mismatched package";
        return result;
    }
    const auto policy_it = scan.policies.find(control.envelope.policy_id);
    if (policy_it == scan.policies.end()) {
        result.status = PolicyRegistryStatus::PackageNotFound;
        result.reason = "policy control references an unknown policy";
        return result;
    }

    RecordKind kind = RecordKind::Activate;
    switch (control.envelope.action) {
    case PolicyControlAction::Activate:
        if (policy_it->second.revoked) {
            result.status = PolicyRegistryStatus::PolicyRevoked;
            result.reason = "revoked policy cannot be activated";
            return result;
        }
        if (scan.active_policy_id == control.envelope.policy_id) {
            result.status = PolicyRegistryStatus::ActiveMismatch;
            result.reason = "policy is already active";
            return result;
        }
        kind = RecordKind::Activate;
        break;
    case PolicyControlAction::Rollback:
        if (policy_it->second.revoked) {
            result.status = PolicyRegistryStatus::PolicyRevoked;
            result.reason = "revoked policy cannot be rollback target";
            return result;
        }
        if (!policy_it->second.ever_active) {
            result.status = PolicyRegistryStatus::Invalid;
            result.reason = "rollback target was never previously active";
            return result;
        }
        if (scan.active_policy_id == control.envelope.policy_id) {
            result.status = PolicyRegistryStatus::ActiveMismatch;
            result.reason = "rollback target is already active";
            return result;
        }
        kind = RecordKind::Rollback;
        break;
    case PolicyControlAction::Revoke:
        if (policy_it->second.revoked) {
            result.status = PolicyRegistryStatus::PolicyRevoked;
            result.reason = "policy is already revoked";
            return result;
        }
        kind = RecordKind::Revoke;
        break;
    }

    RegistryRecord record;
    record.sequence = scan.next_sequence;
    record.kind = kind;
    record.policy_id = control.envelope.policy_id;
    record.package_id = control.envelope.package_id;
    record.signer_id = control.envelope.signer_id;
    record.algorithm = control.algorithm;
    record.signed_at_unix_ms = control.envelope.issued_at_unix_ms;
    record.signature = control.signature;
    record.control_id = control.control_id;
    record.nonce = control.envelope.nonce;
    record.actor_reference = control.envelope.actor_reference;
    record.expected_active_policy_id = control.envelope.expected_active_policy_id;
    record.issued_at_unix_ms = control.envelope.issued_at_unix_ms;
    record.reason_sha256 = control.envelope.reason_sha256;
    record.previous_record_sha256 = scan.head_sha256;
    result = append_record(journal_path_, std::move(record));
    if (!result.ok()) return result;

    if (control.envelope.action == PolicyControlAction::Revoke &&
        scan.active_policy_id == control.envelope.policy_id) {
        result.active_policy_id.clear();
    } else if (control.envelope.action != PolicyControlAction::Revoke) {
        result.active_policy_id = control.envelope.policy_id;
    } else {
        result.active_policy_id = scan.active_policy_id;
    }
    return result;
}

PolicyRegistrySnapshot SignedPolicyRegistry::inspect() const {
    const auto scan = scan_registry(journal_path_, budget_);
    PolicyRegistrySnapshot snapshot;
    snapshot.healthy = scan.healthy;
    snapshot.records = scan.next_sequence;
    snapshot.registered_policies = scan.policies.size();
    snapshot.activation_generation = scan.activation_generation;
    snapshot.active_policy_id = scan.active_policy_id;
    snapshot.active_package_id = scan.active_package_id;
    snapshot.errors = scan.errors;
    for (const auto& [_, policy] : scan.policies) {
        if (policy.revoked) ++snapshot.revoked_policies;
    }
    return snapshot;
}

bool SignedPolicyRegistry::is_active(const PolicyDocument& policy) const {
    return is_policy_active(policy.immutable_id());
}

bool SignedPolicyRegistry::is_policy_active(std::string_view policy_id) const {
    const auto scan = scan_registry(journal_path_, budget_);
    if (!scan.healthy || scan.active_policy_id != policy_id) return false;
    const auto it = scan.policies.find(std::string(policy_id));
    return it != scan.policies.end() && !it->second.revoked;
}

std::string SignedPolicyRegistry::active_policy_id() const {
    const auto scan = scan_registry(journal_path_, budget_);
    return scan.healthy ? scan.active_policy_id : std::string{};
}

std::string SignedPolicyRegistry::active_package_id() const {
    const auto scan = scan_registry(journal_path_, budget_);
    return scan.healthy ? scan.active_package_id : std::string{};
}

const std::filesystem::path& SignedPolicyRegistry::path() const noexcept {
    return journal_path_;
}

RegistryBackedPolicyEngine::RegistryBackedPolicyEngine(
    const SignedPolicyRegistry& registry,
    PolicyDocument policy,
    const RuntimeIdentityStore& identity_store,
    PolicyEvaluationBudget budget)
    : registry_(registry),
      policy_(std::move(policy)),
      identity_store_(identity_store),
      budget_(budget) {}

PolicyEvaluationResult RegistryBackedPolicyEngine::evaluate(
    const PolicyEvaluationRequest& request) const {
    const auto snapshot = registry_.inspect();
    if (!snapshot.healthy) {
        return inactive_policy_result(policy_, request,
                                      "policy registry is unhealthy; evaluation fails closed");
    }
    if (!registry_.is_active(policy_)) {
        return inactive_policy_result(policy_, request,
                                      "policy document is not the currently active registered policy");
    }
    DeclarativePolicyEngine engine(policy_, identity_store_, budget_);
    return engine.evaluate(request);
}

const PolicyDocument& RegistryBackedPolicyEngine::policy() const noexcept {
    return policy_;
}

std::string_view to_string(PolicyControlAction action) noexcept {
    switch (action) {
    case PolicyControlAction::Activate: return "ACTIVATE";
    case PolicyControlAction::Rollback: return "ROLLBACK";
    case PolicyControlAction::Revoke: return "REVOKE";
    }
    return "REVOKE";
}

std::string_view to_string(PolicyRegistryStatus status) noexcept {
    switch (status) {
    case PolicyRegistryStatus::Ready: return "READY";
    case PolicyRegistryStatus::Invalid: return "INVALID";
    case PolicyRegistryStatus::SignatureRejected: return "SIGNATURE_REJECTED";
    case PolicyRegistryStatus::PackageNotFound: return "PACKAGE_NOT_FOUND";
    case PolicyRegistryStatus::AlreadyRegistered: return "ALREADY_REGISTERED";
    case PolicyRegistryStatus::PolicyRevoked: return "POLICY_REVOKED";
    case PolicyRegistryStatus::ActiveMismatch: return "ACTIVE_MISMATCH";
    case PolicyRegistryStatus::ReplayRejected: return "REPLAY_REJECTED";
    case PolicyRegistryStatus::CapacityExceeded: return "CAPACITY_EXCEEDED";
    case PolicyRegistryStatus::StorageFailure: return "STORAGE_FAILURE";
    case PolicyRegistryStatus::Corrupt: return "CORRUPT";
    }
    return "INVALID";
}

} // namespace guff
