#include "guff/runtime_identity_store.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <sstream>
#include <system_error>
#include <utility>

namespace guff {
namespace {

constexpr std::string_view kDeviceRecordPrefix = "guff:identity-device:sha256:";
constexpr std::string_view kExecutableRecordPrefix = "guff:identity-image:sha256:";
constexpr std::string_view kProcessRecordPrefix = "guff:identity-process:sha256:";
constexpr std::string_view kAttestationPrefix = "guff:attestation:sha256:";

std::string hex_encode(std::string_view value) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(value.size() * 2U);
    for (const unsigned char ch : value) {
        out.push_back(kHex[(ch >> 4U) & 0x0fU]);
        out.push_back(kHex[ch & 0x0fU]);
    }
    return out;
}

int hex_value(char ch) noexcept {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
    if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
    return -1;
}

std::optional<std::string> hex_decode(std::string_view value) {
    if ((value.size() % 2U) != 0U) return std::nullopt;
    std::string out;
    out.reserve(value.size() / 2U);
    for (std::size_t i = 0U; i < value.size(); i += 2U) {
        const int hi = hex_value(value[i]);
        const int lo = hex_value(value[i + 1U]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return out;
}

std::vector<std::string_view> split_tabs(std::string_view line) {
    std::vector<std::string_view> fields;
    std::size_t start = 0U;
    while (start <= line.size()) {
        const auto pos = line.find('\t', start);
        if (pos == std::string_view::npos) {
            fields.push_back(line.substr(start));
            break;
        }
        fields.push_back(line.substr(start, pos - start));
        start = pos + 1U;
    }
    return fields;
}

template <typename T>
bool parse_unsigned(std::string_view text, T* out) {
    if (!out || text.empty()) return false;
    T value{};
    const auto* first = text.data();
    const auto* last = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(first, last, value);
    if (ec != std::errc{} || ptr != last) return false;
    *out = value;
    return true;
}

bool valid_token(std::string_view value, std::size_t max_bytes = 256U) {
    if (value.empty() || value.size() > max_bytes) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' ||
               ch == '.' || ch == ':' || ch == '/';
    });
}

bool prefixed_sha256(std::string_view value, std::string_view prefix) {
    return value.starts_with(prefix) && is_sha256(value.substr(prefix.size()));
}

bool valid_reason(std::string_view reason) {
    return valid_token(reason, 128U);
}

RuntimeAttestationTrust stronger_trust(RuntimeAttestationTrust lhs,
                                       RuntimeAttestationTrust rhs) noexcept {
    if (lhs == RuntimeAttestationTrust::NativeOsLocal ||
        rhs == RuntimeAttestationTrust::NativeOsLocal) {
        return RuntimeAttestationTrust::NativeOsLocal;
    }
    return RuntimeAttestationTrust::NativeOsLocalDegraded;
}

bool same_process_record(const RuntimeProcessIdentity& record,
                         const RuntimeAttestationEvidence& evidence,
                         std::string_view device_record_id,
                         std::string_view executable_record_id) {
    return record.provider_id == evidence.provider_id &&
           record.process_instance_sha256 == evidence.binding.process_instance_sha256 &&
           record.device_record_id == device_record_id &&
           record.executable_record_id == executable_record_id &&
           record.device_id == evidence.binding.device_id &&
           record.executable_sha256 == evidence.binding.executable_sha256 &&
           record.process_id == evidence.process_id &&
           record.process_started_unix_ms == evidence.process_started_unix_ms;
}

bool valid_budget(const RuntimeIdentityStoreBudget& budget) noexcept {
    return budget.max_devices > 0U && budget.max_executables > 0U &&
           budget.max_processes > 0U && budget.max_attestations > 0U;
}

} // namespace

bool RuntimeDeviceIdentity::revoked() const noexcept {
    return revoked_at_unix_ms != 0U;
}

bool RuntimeExecutableIdentity::revoked() const noexcept {
    return revoked_at_unix_ms != 0U;
}

bool RuntimeProcessIdentity::revoked() const noexcept {
    return revoked_at_unix_ms != 0U;
}

bool RuntimeIdentityStoreResult::ok() const noexcept {
    return status == RuntimeIdentityStoreStatus::Recorded ||
           status == RuntimeIdentityStoreStatus::AlreadyRecorded;
}

std::string runtime_device_identity_id(std::string_view provider_id,
                                       std::string_view device_id) {
    return std::string(kDeviceRecordPrefix) +
           sha256(std::string(provider_id) + "\n" + std::string(device_id));
}

std::string runtime_executable_identity_id(std::string_view executable_sha256) {
    return std::string(kExecutableRecordPrefix) + sha256(executable_sha256);
}

std::string runtime_process_identity_id(std::string_view provider_id,
                                        std::string_view process_instance_sha256) {
    return std::string(kProcessRecordPrefix) +
           sha256(std::string(provider_id) + "\n" +
                  std::string(process_instance_sha256));
}

RuntimeIdentityStore::RuntimeIdentityStore(
    std::filesystem::path journal_path,
    RuntimeIdentityStoreBudget budget)
    : journal_path_(std::move(journal_path)), budget_(budget) {
    if (!valid_budget(budget_)) {
        healthy_ = false;
        errors_.emplace_back("runtime identity store budget must be non-zero");
        return;
    }
    static_cast<void>(replay());
}

bool RuntimeIdentityStore::append_event(std::string_view body, std::string* error) {
    if (!healthy_) {
        if (error) *error = "runtime identity store is unhealthy";
        return false;
    }
    if (journal_path_.empty()) {
        if (error) *error = "runtime identity store requires a journal path";
        return false;
    }

    std::error_code ec;
    const auto parent = journal_path_.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            if (error) *error = "unable to create runtime identity journal directory";
            return false;
        }
    }

    const auto next_sequence = sequence_ + 1U;
    const std::string previous = last_record_sha256_.empty()
        ? std::string(64U, '0') : last_record_sha256_;
    std::ostringstream canonical;
    canonical << next_sequence << '\t' << previous << '\t' << body;
    const auto canonical_text = canonical.str();
    const auto record_sha = sha256(canonical_text);

    std::ofstream output(journal_path_, std::ios::binary | std::ios::app);
    if (!output) {
        if (error) *error = "unable to open runtime identity journal";
        return false;
    }
    output << canonical_text << '\t' << record_sha << '\n';
    output.flush();
    if (!output) {
        if (error) *error = "unable to append runtime identity journal";
        return false;
    }

    sequence_ = next_sequence;
    last_record_sha256_ = record_sha;
    if (error) error->clear();
    return true;
}

RuntimeIdentityStoreResult RuntimeIdentityStore::record_attestation(
    const RuntimeAttestationEvidence& evidence) {
    RuntimeIdentityStoreResult result;
    result.attestation_id = evidence.attestation_id;

    if (!healthy_) {
        result.status = RuntimeIdentityStoreStatus::Corrupt;
        result.errors = errors_;
        return result;
    }
    if (!validate_runtime_attestation_identity(evidence)) {
        result.status = RuntimeIdentityStoreStatus::InvalidEvidence;
        result.errors.emplace_back("runtime identity store requires canonical attestation evidence");
        return result;
    }

    result.device_record_id = runtime_device_identity_id(
        evidence.provider_id, evidence.binding.device_id);
    result.executable_record_id = runtime_executable_identity_id(
        evidence.binding.executable_sha256);
    result.process_record_id = runtime_process_identity_id(
        evidence.provider_id, evidence.binding.process_instance_sha256);

    if (const auto found = attestations_.find(evidence.attestation_id);
        found != attestations_.end()) {
        const bool same = found->second.canonical_sha256 == evidence.canonical_sha256 &&
                          found->second.device_record_id == result.device_record_id &&
                          found->second.executable_record_id == result.executable_record_id &&
                          found->second.process_record_id == result.process_record_id;
        result.status = same
            ? RuntimeIdentityStoreStatus::AlreadyRecorded
            : RuntimeIdentityStoreStatus::Collision;
        if (!same) {
            result.errors.emplace_back("attestation identity collides with a different stored observation");
        }
        return result;
    }

    if (const auto found = devices_.find(result.device_record_id);
        found != devices_.end() && found->second.revoked()) {
        result.status = RuntimeIdentityStoreStatus::DeviceRevoked;
        result.errors.emplace_back("attested device identity has been revoked");
        return result;
    }
    if (const auto found = executables_.find(result.executable_record_id);
        found != executables_.end() && found->second.revoked()) {
        result.status = RuntimeIdentityStoreStatus::ExecutableRevoked;
        result.errors.emplace_back("attested executable identity has been revoked");
        return result;
    }
    if (const auto found = processes_.find(result.process_record_id);
        found != processes_.end()) {
        if (!same_process_record(found->second,
                                 evidence,
                                 result.device_record_id,
                                 result.executable_record_id)) {
            result.status = RuntimeIdentityStoreStatus::Collision;
            result.errors.emplace_back("process identity collides with different immutable measurements");
            return result;
        }
        if (found->second.revoked()) {
            result.status = RuntimeIdentityStoreStatus::ProcessRevoked;
            result.errors.emplace_back("attested process identity has been revoked");
            return result;
        }
    }

    const bool new_device = !devices_.contains(result.device_record_id);
    const bool new_executable = !executables_.contains(result.executable_record_id);
    const bool new_process = !processes_.contains(result.process_record_id);
    if ((new_device && devices_.size() >= budget_.max_devices) ||
        (new_executable && executables_.size() >= budget_.max_executables) ||
        (new_process && processes_.size() >= budget_.max_processes) ||
        attestations_.size() >= budget_.max_attestations) {
        result.status = RuntimeIdentityStoreStatus::CapacityExceeded;
        result.errors.emplace_back("runtime identity store bounded capacity would be exceeded");
        return result;
    }

    const std::string challenge_sha = sha256(evidence.challenge_nonce);
    std::ostringstream body;
    body << "O\t"
         << hex_encode(evidence.attestation_id) << '\t'
         << evidence.canonical_sha256 << '\t'
         << hex_encode(evidence.provider_id) << '\t'
         << static_cast<unsigned>(evidence.trust) << '\t'
         << hex_encode(result.device_record_id) << '\t'
         << hex_encode(evidence.binding.device_id) << '\t'
         << hex_encode(result.executable_record_id) << '\t'
         << evidence.binding.executable_sha256 << '\t'
         << hex_encode(result.process_record_id) << '\t'
         << evidence.binding.process_instance_sha256 << '\t'
         << evidence.process_id << '\t'
         << evidence.process_started_unix_ms << '\t'
         << hex_encode(evidence.binding.slot_id) << '\t'
         << hex_encode(evidence.binding.session_id) << '\t'
         << static_cast<unsigned>(evidence.binding.layer) << '\t'
         << evidence.observed_at_unix_ms << '\t'
         << evidence.valid_until_unix_ms << '\t'
         << challenge_sha << '\t'
         << evidence.executable_locator_sha256;

    std::string storage_error;
    if (!append_event(body.str(), &storage_error)) {
        result.status = RuntimeIdentityStoreStatus::StorageError;
        result.errors.push_back(std::move(storage_error));
        return result;
    }

    auto [device_it, inserted_device] = devices_.try_emplace(result.device_record_id);
    auto& device = device_it->second;
    if (inserted_device) {
        device.record_id = result.device_record_id;
        device.provider_id = evidence.provider_id;
        device.device_id = evidence.binding.device_id;
        device.strongest_trust = evidence.trust;
        device.first_seen_unix_ms = evidence.observed_at_unix_ms;
    } else {
        device.strongest_trust = stronger_trust(device.strongest_trust, evidence.trust);
        device.first_seen_unix_ms = std::min(device.first_seen_unix_ms,
                                             evidence.observed_at_unix_ms);
    }
    device.last_seen_unix_ms = std::max(device.last_seen_unix_ms,
                                        evidence.observed_at_unix_ms);
    ++device.observations;

    auto [executable_it, inserted_executable] =
        executables_.try_emplace(result.executable_record_id);
    auto& executable = executable_it->second;
    if (inserted_executable) {
        executable.record_id = result.executable_record_id;
        executable.executable_sha256 = evidence.binding.executable_sha256;
        executable.first_seen_unix_ms = evidence.observed_at_unix_ms;
    } else {
        executable.first_seen_unix_ms = std::min(
            executable.first_seen_unix_ms, evidence.observed_at_unix_ms);
    }
    executable.last_seen_unix_ms = std::max(
        executable.last_seen_unix_ms, evidence.observed_at_unix_ms);
    ++executable.observations;

    auto [process_it, inserted_process] = processes_.try_emplace(result.process_record_id);
    auto& process = process_it->second;
    if (inserted_process) {
        process.record_id = result.process_record_id;
        process.provider_id = evidence.provider_id;
        process.process_instance_sha256 = evidence.binding.process_instance_sha256;
        process.device_record_id = result.device_record_id;
        process.executable_record_id = result.executable_record_id;
        process.device_id = evidence.binding.device_id;
        process.executable_sha256 = evidence.binding.executable_sha256;
        process.process_id = evidence.process_id;
        process.process_started_unix_ms = evidence.process_started_unix_ms;
        process.first_seen_unix_ms = evidence.observed_at_unix_ms;
    } else {
        process.first_seen_unix_ms = std::min(
            process.first_seen_unix_ms, evidence.observed_at_unix_ms);
    }
    process.last_seen_unix_ms = std::max(
        process.last_seen_unix_ms, evidence.observed_at_unix_ms);
    ++process.observations;

    RuntimeIdentityObservation observation;
    observation.attestation_id = evidence.attestation_id;
    observation.canonical_sha256 = evidence.canonical_sha256;
    observation.provider_id = evidence.provider_id;
    observation.trust = evidence.trust;
    observation.device_record_id = result.device_record_id;
    observation.executable_record_id = result.executable_record_id;
    observation.process_record_id = result.process_record_id;
    observation.slot_id = evidence.binding.slot_id;
    observation.session_id = evidence.binding.session_id;
    observation.layer = evidence.binding.layer;
    observation.observed_at_unix_ms = evidence.observed_at_unix_ms;
    observation.valid_until_unix_ms = evidence.valid_until_unix_ms;
    observation.challenge_sha256 = challenge_sha;
    observation.executable_locator_sha256 = evidence.executable_locator_sha256;
    attestations_.emplace(observation.attestation_id, std::move(observation));

    result.status = RuntimeIdentityStoreStatus::Recorded;
    return result;
}

RuntimeIdentityStoreResult RuntimeIdentityStore::revoke_impl(
    char kind,
    std::string_view record_id,
    std::uint64_t revoked_at_unix_ms,
    std::string_view reason_code) {
    RuntimeIdentityStoreResult result;
    if (!healthy_) {
        result.status = RuntimeIdentityStoreStatus::Corrupt;
        result.errors = errors_;
        return result;
    }
    if (revoked_at_unix_ms == 0U || !valid_reason(reason_code)) {
        result.status = RuntimeIdentityStoreStatus::InvalidEvidence;
        result.errors.emplace_back("identity revocation requires a timestamp and bounded reason code");
        return result;
    }

    bool exists = false;
    bool already_revoked = false;
    if (kind == 'D') {
        result.device_record_id = std::string(record_id);
        const auto it = devices_.find(std::string(record_id));
        exists = it != devices_.end();
        already_revoked = exists && it->second.revoked();
    } else if (kind == 'E') {
        result.executable_record_id = std::string(record_id);
        const auto it = executables_.find(std::string(record_id));
        exists = it != executables_.end();
        already_revoked = exists && it->second.revoked();
    } else if (kind == 'P') {
        result.process_record_id = std::string(record_id);
        const auto it = processes_.find(std::string(record_id));
        exists = it != processes_.end();
        already_revoked = exists && it->second.revoked();
    }
    if (!exists) {
        result.status = RuntimeIdentityStoreStatus::NotFound;
        result.errors.emplace_back("identity record was not found");
        return result;
    }
    if (already_revoked) {
        result.status = RuntimeIdentityStoreStatus::AlreadyRecorded;
        return result;
    }

    std::ostringstream body;
    body << kind << '\t' << hex_encode(record_id) << '\t'
         << revoked_at_unix_ms << '\t' << hex_encode(reason_code);
    std::string storage_error;
    if (!append_event(body.str(), &storage_error)) {
        result.status = RuntimeIdentityStoreStatus::StorageError;
        result.errors.push_back(std::move(storage_error));
        return result;
    }

    if (kind == 'D') {
        auto& record = devices_.at(std::string(record_id));
        record.revoked_at_unix_ms = revoked_at_unix_ms;
        record.revocation_reason_code = std::string(reason_code);
    } else if (kind == 'E') {
        auto& record = executables_.at(std::string(record_id));
        record.revoked_at_unix_ms = revoked_at_unix_ms;
        record.revocation_reason_code = std::string(reason_code);
    } else {
        auto& record = processes_.at(std::string(record_id));
        record.revoked_at_unix_ms = revoked_at_unix_ms;
        record.revocation_reason_code = std::string(reason_code);
    }
    result.status = RuntimeIdentityStoreStatus::Recorded;
    return result;
}

RuntimeIdentityStoreResult RuntimeIdentityStore::revoke_device(
    std::string_view record_id,
    std::uint64_t revoked_at_unix_ms,
    std::string_view reason_code) {
    return revoke_impl('D', record_id, revoked_at_unix_ms, reason_code);
}

RuntimeIdentityStoreResult RuntimeIdentityStore::revoke_executable(
    std::string_view record_id,
    std::uint64_t revoked_at_unix_ms,
    std::string_view reason_code) {
    return revoke_impl('E', record_id, revoked_at_unix_ms, reason_code);
}

RuntimeIdentityStoreResult RuntimeIdentityStore::revoke_process(
    std::string_view record_id,
    std::uint64_t revoked_at_unix_ms,
    std::string_view reason_code) {
    return revoke_impl('P', record_id, revoked_at_unix_ms, reason_code);
}

std::optional<RuntimeDeviceIdentity> RuntimeIdentityStore::device(
    std::string_view record_id) const {
    const auto it = devices_.find(std::string(record_id));
    if (it == devices_.end()) return std::nullopt;
    return it->second;
}

std::optional<RuntimeExecutableIdentity> RuntimeIdentityStore::executable(
    std::string_view record_id) const {
    const auto it = executables_.find(std::string(record_id));
    if (it == executables_.end()) return std::nullopt;
    return it->second;
}

std::optional<RuntimeProcessIdentity> RuntimeIdentityStore::process(
    std::string_view record_id) const {
    const auto it = processes_.find(std::string(record_id));
    if (it == processes_.end()) return std::nullopt;
    return it->second;
}

std::optional<RuntimeIdentityObservation> RuntimeIdentityStore::attestation(
    std::string_view attestation_id) const {
    const auto it = attestations_.find(std::string(attestation_id));
    if (it == attestations_.end()) return std::nullopt;
    return it->second;
}

bool RuntimeIdentityStore::identity_active(
    const RuntimeAttestationEvidence& evidence) const noexcept {
    if (!healthy_ || !validate_runtime_attestation_identity(evidence)) return false;
    const auto device_id = runtime_device_identity_id(
        evidence.provider_id, evidence.binding.device_id);
    const auto executable_id = runtime_executable_identity_id(
        evidence.binding.executable_sha256);
    const auto process_id = runtime_process_identity_id(
        evidence.provider_id, evidence.binding.process_instance_sha256);
    const auto device_it = devices_.find(device_id);
    const auto executable_it = executables_.find(executable_id);
    const auto process_it = processes_.find(process_id);
    return device_it != devices_.end() && !device_it->second.revoked() &&
           executable_it != executables_.end() && !executable_it->second.revoked() &&
           process_it != processes_.end() && !process_it->second.revoked();
}

bool RuntimeIdentityStore::replay(std::vector<std::string>* errors) {
    devices_.clear();
    executables_.clear();
    processes_.clear();
    attestations_.clear();
    sequence_ = 0U;
    last_record_sha256_.clear();
    errors_.clear();
    healthy_ = valid_budget(budget_);
    if (!healthy_) {
        errors_.emplace_back("runtime identity store budget must be non-zero");
        if (errors) *errors = errors_;
        return false;
    }

    std::error_code ec;
    if (!std::filesystem::exists(journal_path_, ec)) {
        if (errors) errors->clear();
        return true;
    }
    if (ec) {
        healthy_ = false;
        errors_.emplace_back("unable to inspect runtime identity journal");
        if (errors) *errors = errors_;
        return false;
    }

    std::ifstream input(journal_path_, std::ios::binary);
    if (!input) {
        healthy_ = false;
        errors_.emplace_back("unable to open runtime identity journal");
        if (errors) *errors = errors_;
        return false;
    }

    std::string line;
    std::size_t line_number = 0U;
    while (std::getline(input, line)) {
        ++line_number;
        if (line.empty()) continue;
        const auto last_tab = line.rfind('\t');
        if (last_tab == std::string::npos) {
            healthy_ = false;
            errors_.emplace_back("runtime identity journal record missing hash at line " +
                                 std::to_string(line_number));
            break;
        }
        const std::string_view canonical(line.data(), last_tab);
        const std::string_view record_sha(line.data() + last_tab + 1U,
                                          line.size() - last_tab - 1U);
        if (!is_sha256(record_sha) || sha256(canonical) != record_sha) {
            healthy_ = false;
            errors_.emplace_back("runtime identity journal hash mismatch at line " +
                                 std::to_string(line_number));
            break;
        }
        const auto fields = split_tabs(canonical);
        if (fields.size() < 3U) {
            healthy_ = false;
            errors_.emplace_back("runtime identity journal record is truncated");
            break;
        }
        std::size_t seq = 0U;
        if (!parse_unsigned(fields[0], &seq) || seq != sequence_ + 1U) {
            healthy_ = false;
            errors_.emplace_back("runtime identity journal sequence mismatch");
            break;
        }
        const std::string expected_previous = last_record_sha256_.empty()
            ? std::string(64U, '0') : last_record_sha256_;
        if (fields[1] != expected_previous) {
            healthy_ = false;
            errors_.emplace_back("runtime identity journal previous-hash mismatch");
            break;
        }

        const auto event = fields[2];
        if (event == "O") {
            if (fields.size() != 22U) {
                healthy_ = false;
                errors_.emplace_back("runtime identity observation record has invalid field count");
                break;
            }
            auto attestation_id = hex_decode(fields[3]);
            auto provider_id = hex_decode(fields[5]);
            auto device_record_id = hex_decode(fields[7]);
            auto device_id = hex_decode(fields[8]);
            auto executable_record_id = hex_decode(fields[9]);
            auto process_record_id = hex_decode(fields[11]);
            auto slot_id = hex_decode(fields[15]);
            auto session_id = hex_decode(fields[16]);
            unsigned trust_value = 0U;
            unsigned layer_value = 0U;
            std::uint64_t process_id = 0U;
            std::uint64_t process_started = 0U;
            std::uint64_t observed = 0U;
            std::uint64_t valid_until = 0U;
            if (!attestation_id || !provider_id || !device_record_id || !device_id ||
                !executable_record_id || !process_record_id || !slot_id || !session_id ||
                !parse_unsigned(fields[6], &trust_value) || trust_value > 1U ||
                !parse_unsigned(fields[13], &process_id) ||
                !parse_unsigned(fields[14], &process_started) ||
                !parse_unsigned(fields[17], &layer_value) || layer_value > 9U ||
                !parse_unsigned(fields[18], &observed) ||
                !parse_unsigned(fields[19], &valid_until) ||
                !prefixed_sha256(*attestation_id, kAttestationPrefix) ||
                !is_sha256(fields[4]) ||
                !is_sha256(fields[10]) || !is_sha256(fields[12]) ||
                !is_sha256(fields[20]) || !is_sha256(fields[21]) ||
                observed == 0U || valid_until <= observed || process_id == 0U ||
                process_started == 0U) {
                healthy_ = false;
                errors_.emplace_back("runtime identity observation record is malformed");
                break;
            }
            if (*device_record_id != runtime_device_identity_id(*provider_id, *device_id) ||
                *executable_record_id != runtime_executable_identity_id(fields[10]) ||
                *process_record_id != runtime_process_identity_id(*provider_id, fields[12])) {
                healthy_ = false;
                errors_.emplace_back("runtime identity record IDs do not match observation content");
                break;
            }
            if (const auto existing = attestations_.find(*attestation_id);
                existing != attestations_.end()) {
                healthy_ = false;
                errors_.emplace_back("duplicate attestation ID found during identity replay");
                break;
            }
            const bool new_device = !devices_.contains(*device_record_id);
            const bool new_executable = !executables_.contains(*executable_record_id);
            const bool new_process = !processes_.contains(*process_record_id);
            if ((new_device && devices_.size() >= budget_.max_devices) ||
                (new_executable && executables_.size() >= budget_.max_executables) ||
                (new_process && processes_.size() >= budget_.max_processes) ||
                attestations_.size() >= budget_.max_attestations) {
                healthy_ = false;
                errors_.emplace_back("runtime identity journal exceeds configured bounded capacity");
                break;
            }

            const auto trust = static_cast<RuntimeAttestationTrust>(trust_value);
            auto [device_it, inserted_device] = devices_.try_emplace(*device_record_id);
            auto& device = device_it->second;
            if (inserted_device) {
                device.record_id = *device_record_id;
                device.provider_id = *provider_id;
                device.device_id = *device_id;
                device.strongest_trust = trust;
                device.first_seen_unix_ms = observed;
            } else if (device.provider_id != *provider_id || device.device_id != *device_id) {
                healthy_ = false;
                errors_.emplace_back("runtime device record collision during replay");
                break;
            } else {
                device.strongest_trust = stronger_trust(device.strongest_trust, trust);
                device.first_seen_unix_ms = std::min(device.first_seen_unix_ms, observed);
            }
            device.last_seen_unix_ms = std::max(device.last_seen_unix_ms, observed);
            ++device.observations;

            auto [executable_it, inserted_executable] =
                executables_.try_emplace(*executable_record_id);
            auto& executable = executable_it->second;
            if (inserted_executable) {
                executable.record_id = *executable_record_id;
                executable.executable_sha256 = std::string(fields[10]);
                executable.first_seen_unix_ms = observed;
            } else if (executable.executable_sha256 != fields[10]) {
                healthy_ = false;
                errors_.emplace_back("runtime executable record collision during replay");
                break;
            } else {
                executable.first_seen_unix_ms = std::min(executable.first_seen_unix_ms, observed);
            }
            executable.last_seen_unix_ms = std::max(executable.last_seen_unix_ms, observed);
            ++executable.observations;

            auto [process_it, inserted_process] = processes_.try_emplace(*process_record_id);
            auto& process = process_it->second;
            if (inserted_process) {
                process.record_id = *process_record_id;
                process.provider_id = *provider_id;
                process.process_instance_sha256 = std::string(fields[12]);
                process.device_record_id = *device_record_id;
                process.executable_record_id = *executable_record_id;
                process.device_id = *device_id;
                process.executable_sha256 = std::string(fields[10]);
                process.process_id = process_id;
                process.process_started_unix_ms = process_started;
                process.first_seen_unix_ms = observed;
            } else if (process.provider_id != *provider_id ||
                       process.process_instance_sha256 != fields[12] ||
                       process.device_record_id != *device_record_id ||
                       process.executable_record_id != *executable_record_id ||
                       process.device_id != *device_id ||
                       process.executable_sha256 != fields[10] ||
                       process.process_id != process_id ||
                       process.process_started_unix_ms != process_started) {
                healthy_ = false;
                errors_.emplace_back("runtime process record collision during replay");
                break;
            } else {
                process.first_seen_unix_ms = std::min(process.first_seen_unix_ms, observed);
            }
            process.last_seen_unix_ms = std::max(process.last_seen_unix_ms, observed);
            ++process.observations;

            RuntimeIdentityObservation observation;
            observation.attestation_id = *attestation_id;
            observation.canonical_sha256 = std::string(fields[4]);
            observation.provider_id = *provider_id;
            observation.trust = trust;
            observation.device_record_id = *device_record_id;
            observation.executable_record_id = *executable_record_id;
            observation.process_record_id = *process_record_id;
            observation.slot_id = *slot_id;
            observation.session_id = *session_id;
            observation.layer = static_cast<RealityLayer>(layer_value);
            observation.observed_at_unix_ms = observed;
            observation.valid_until_unix_ms = valid_until;
            observation.challenge_sha256 = std::string(fields[20]);
            observation.executable_locator_sha256 = std::string(fields[21]);
            attestations_.emplace(observation.attestation_id, std::move(observation));
        } else if (event == "D" || event == "E" || event == "P") {
            if (fields.size() != 6U) {
                healthy_ = false;
                errors_.emplace_back("runtime identity revocation record has invalid field count");
                break;
            }
            auto record_id = hex_decode(fields[3]);
            auto reason = hex_decode(fields[5]);
            std::uint64_t revoked_at = 0U;
            if (!record_id || !reason || !parse_unsigned(fields[4], &revoked_at) ||
                revoked_at == 0U || !valid_reason(*reason)) {
                healthy_ = false;
                errors_.emplace_back("runtime identity revocation record is malformed");
                break;
            }
            bool applied = false;
            if (event == "D") {
                auto it = devices_.find(*record_id);
                if (it != devices_.end() && !it->second.revoked()) {
                    it->second.revoked_at_unix_ms = revoked_at;
                    it->second.revocation_reason_code = *reason;
                    applied = true;
                }
            } else if (event == "E") {
                auto it = executables_.find(*record_id);
                if (it != executables_.end() && !it->second.revoked()) {
                    it->second.revoked_at_unix_ms = revoked_at;
                    it->second.revocation_reason_code = *reason;
                    applied = true;
                }
            } else {
                auto it = processes_.find(*record_id);
                if (it != processes_.end() && !it->second.revoked()) {
                    it->second.revoked_at_unix_ms = revoked_at;
                    it->second.revocation_reason_code = *reason;
                    applied = true;
                }
            }
            if (!applied) {
                healthy_ = false;
                errors_.emplace_back("runtime identity revocation references missing/already-revoked record");
                break;
            }
        } else {
            healthy_ = false;
            errors_.emplace_back("runtime identity journal contains unknown event type");
            break;
        }

        sequence_ = seq;
        last_record_sha256_ = std::string(record_sha);
    }

    if (errors) *errors = errors_;
    return healthy_;
}

RuntimeIdentityStoreInspection RuntimeIdentityStore::inspect() const {
    RuntimeIdentityStoreInspection result;
    result.healthy = healthy_;
    result.records = sequence_;
    result.devices = devices_.size();
    result.executables = executables_.size();
    result.processes = processes_.size();
    result.attestations = attestations_.size();
    result.errors = errors_;
    result.revoked_devices = static_cast<std::size_t>(std::count_if(
        devices_.begin(), devices_.end(), [](const auto& item) { return item.second.revoked(); }));
    result.revoked_executables = static_cast<std::size_t>(std::count_if(
        executables_.begin(), executables_.end(), [](const auto& item) { return item.second.revoked(); }));
    result.revoked_processes = static_cast<std::size_t>(std::count_if(
        processes_.begin(), processes_.end(), [](const auto& item) { return item.second.revoked(); }));
    return result;
}

const RuntimeIdentityStoreBudget& RuntimeIdentityStore::budget() const noexcept {
    return budget_;
}

const std::filesystem::path& RuntimeIdentityStore::journal_path() const noexcept {
    return journal_path_;
}

IdentityTrackingRuntimeAttestationProvider::IdentityTrackingRuntimeAttestationProvider(
    const RuntimeAttestationProvider& inner,
    RuntimeIdentityStore& store) noexcept
    : inner_(inner), store_(store) {}

std::string IdentityTrackingRuntimeAttestationProvider::provider_id() const {
    return inner_.provider_id();
}

RuntimeAttestationTrust IdentityTrackingRuntimeAttestationProvider::trust() const noexcept {
    return inner_.trust();
}

RuntimeAttestationResult IdentityTrackingRuntimeAttestationProvider::attest(
    const RuntimeAttestationRequest& request) const {
    auto result = inner_.attest(request);
    if (!result.ok() || !result.evidence) return result;

    auto stored = store_.record_attestation(*result.evidence);
    if (!stored.ok()) {
        result.status = RuntimeAttestationStatus::EvidenceInvalid;
        result.errors.insert(result.errors.end(), stored.errors.begin(), stored.errors.end());
        result.evidence.reset();
    }
    return result;
}

std::string_view to_string(RuntimeIdentityStoreStatus status) noexcept {
    switch (status) {
    case RuntimeIdentityStoreStatus::Recorded: return "RECORDED";
    case RuntimeIdentityStoreStatus::AlreadyRecorded: return "ALREADY_RECORDED";
    case RuntimeIdentityStoreStatus::InvalidEvidence: return "INVALID_EVIDENCE";
    case RuntimeIdentityStoreStatus::DeviceRevoked: return "DEVICE_REVOKED";
    case RuntimeIdentityStoreStatus::ExecutableRevoked: return "EXECUTABLE_REVOKED";
    case RuntimeIdentityStoreStatus::ProcessRevoked: return "PROCESS_REVOKED";
    case RuntimeIdentityStoreStatus::Collision: return "COLLISION";
    case RuntimeIdentityStoreStatus::CapacityExceeded: return "CAPACITY_EXCEEDED";
    case RuntimeIdentityStoreStatus::NotFound: return "NOT_FOUND";
    case RuntimeIdentityStoreStatus::StorageError: return "STORAGE_ERROR";
    case RuntimeIdentityStoreStatus::Corrupt: return "CORRUPT";
    }
    return "UNKNOWN";
}

} // namespace guff
