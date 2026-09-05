#include "guff/runtime_lease.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <fstream>
#include <sstream>
#include <system_error>
#include <utility>

namespace guff {
namespace {

constexpr std::string_view kLeasePrefix = "guff:lease:sha256:";
constexpr std::string_view kHardwarePrefix = "guff:hardware:sha256:";
constexpr std::string_view kSessionPrefix = "guff:session:sha256:";

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

bool valid_binding(const RuntimeBinding& binding) {
    return prefixed_sha256(binding.device_id, kHardwarePrefix) &&
           is_sha256(binding.executable_sha256) &&
           is_sha256(binding.process_instance_sha256) &&
           valid_token(binding.slot_id, 192U) &&
           prefixed_sha256(binding.session_id, kSessionPrefix);
}

bool same_binding(const RuntimeBinding& lhs, const RuntimeBinding& rhs) {
    return lhs.device_id == rhs.device_id &&
           lhs.executable_sha256 == rhs.executable_sha256 &&
           lhs.process_instance_sha256 == rhs.process_instance_sha256 &&
           lhs.slot_id == rhs.slot_id &&
           lhs.session_id == rhs.session_id &&
           lhs.layer == rhs.layer;
}

bool capability_present(const std::vector<std::string>& capabilities,
                        std::string_view capability) {
    return std::find(capabilities.begin(), capabilities.end(), capability) != capabilities.end();
}

std::uint64_t system_now_ms() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

RuntimeLeaseResult validate_lease(
    const RuntimeCapabilityLease& lease,
    const SessionKeyBundle& bundle,
    const SessionKeyVerifier& verifier) {
    RuntimeLeaseResult result;
    result.lease_id = lease.lease_id;

    if (lease.schema_version != 1U ||
        lease.session_key_receipt_id != bundle.receipt.receipt_id ||
        lease.certificate_id != bundle.certificate.certificate_id ||
        lease.signer_id != bundle.receipt.signer_id ||
        lease.key_id != bundle.receipt.key_id ||
        lease.algorithm != bundle.receipt.algorithm ||
        lease.key_fingerprint_sha256 != bundle.receipt.key_fingerprint_sha256 ||
        lease.purpose != bundle.receipt.purpose ||
        lease.subject_id != bundle.receipt.subject_id ||
        lease.scope_path != bundle.receipt.scope_path ||
        lease.scope_sha256 != bundle.receipt.scope_sha256) {
        result.status = RuntimeLeaseStatus::SessionKeyMismatch;
        result.errors.emplace_back("runtime lease does not match its session-key branch");
        return result;
    }
    if (!valid_binding(lease.binding) || !valid_token(lease.capability, 192U) ||
        !valid_token(lease.nonce, 128U) || !is_sha256(lease.scope_sha256) ||
        !is_sha256(lease.key_fingerprint_sha256) ||
        lease.issued_at_unix_ms < bundle.receipt.issued_at_unix_ms ||
        lease.expires_at_unix_ms > bundle.receipt.expires_at_unix_ms ||
        lease.expires_at_unix_ms <= lease.issued_at_unix_ms ||
        lease.max_uses == 0U || lease.max_uses > bundle.receipt.max_uses ||
        !capability_present(bundle.receipt.capabilities, lease.capability)) {
        result.status = RuntimeLeaseStatus::Invalid;
        result.errors.emplace_back("runtime lease policy exceeds or violates its session-key branch");
        return result;
    }

    const auto canonical = canonical_runtime_capability_lease(lease);
    if (lease.canonical_sha256 != sha256(canonical) ||
        lease.lease_id != runtime_capability_lease_id(lease, lease.signature)) {
        result.status = RuntimeLeaseStatus::SignatureRejected;
        result.errors.emplace_back("runtime lease canonical identity is invalid");
        return result;
    }
    if (!verifier.knows_key(lease.signer_id, lease.key_id, lease.algorithm)) {
        result.status = RuntimeLeaseStatus::KeyMismatch;
        result.errors.emplace_back("runtime lease signer key is unknown");
        return result;
    }
    const auto fingerprint = verifier.key_fingerprint_sha256(
        lease.signer_id, lease.key_id, lease.algorithm);
    if (!fingerprint || *fingerprint != lease.key_fingerprint_sha256) {
        result.status = RuntimeLeaseStatus::KeyMismatch;
        result.errors.emplace_back("runtime lease signer fingerprint mismatch");
        return result;
    }
    if (!verifier.verify_key(lease.signer_id,
                             lease.key_id,
                             lease.algorithm,
                             canonical,
                             lease.signature)) {
        result.status = RuntimeLeaseStatus::SignatureRejected;
        result.errors.emplace_back("runtime lease signature rejected");
        return result;
    }

    result.status = RuntimeLeaseStatus::Allowed;
    return result;
}

} // namespace

bool RuntimeLeaseResult::ok() const noexcept {
    return status == RuntimeLeaseStatus::Allowed;
}

std::string canonical_runtime_binding(const RuntimeBinding& binding) {
    std::ostringstream out;
    out << binding.device_id << '\n'
        << binding.executable_sha256 << '\n'
        << binding.process_instance_sha256 << '\n'
        << binding.slot_id << '\n'
        << binding.session_id << '\n'
        << static_cast<unsigned>(binding.layer);
    return out.str();
}

std::string runtime_binding_sha256(const RuntimeBinding& binding) {
    return sha256(canonical_runtime_binding(binding));
}

std::string canonical_runtime_capability_lease(const RuntimeCapabilityLease& lease) {
    std::ostringstream out;
    out << lease.schema_version << '\n'
        << lease.session_key_receipt_id << '\n'
        << lease.certificate_id << '\n'
        << lease.signer_id << '\n'
        << lease.key_id << '\n'
        << lease.algorithm << '\n'
        << lease.key_fingerprint_sha256 << '\n'
        << static_cast<unsigned>(lease.purpose) << '\n'
        << lease.subject_id << '\n'
        << lease.scope_path << '\n'
        << lease.scope_sha256 << '\n'
        << lease.capability << '\n'
        << canonical_runtime_binding(lease.binding) << '\n'
        << lease.issued_at_unix_ms << '\n'
        << lease.expires_at_unix_ms << '\n'
        << lease.max_uses << '\n'
        << lease.nonce;
    return out.str();
}

std::string runtime_capability_lease_id(const RuntimeCapabilityLease& lease,
                                        std::string_view signature) {
    return std::string(kLeasePrefix) +
           sha256(canonical_runtime_capability_lease(lease) + "\n" + std::string(signature));
}

std::string runtime_process_instance_sha256(
    std::string_view device_id,
    std::string_view executable_sha256,
    std::uint64_t process_id,
    std::uint64_t process_started_unix_ms,
    std::string_view runtime_nonce) {
    std::ostringstream canonical;
    canonical << device_id << '\n'
              << executable_sha256 << '\n'
              << process_id << '\n'
              << process_started_unix_ms << '\n'
              << runtime_nonce;
    return sha256(canonical.str());
}

std::optional<RuntimeCapabilityLease> RuntimeLeaseIssuer::issue(
    const SessionKeyBundle& bundle,
    const RuntimeLeaseIssueRequest& request,
    const SessionKeySigner& signer,
    std::vector<std::string>* errors) {
    std::vector<std::string> local_errors;
    const auto& receipt = bundle.receipt;

    if (signer.signer_id() != receipt.signer_id ||
        signer.key_id() != receipt.key_id ||
        signer.algorithm() != receipt.algorithm ||
        signer.key_fingerprint_sha256() != receipt.key_fingerprint_sha256) {
        local_errors.emplace_back("runtime lease must be signed by the exact delegated session key");
    }
    if (!valid_binding(request.binding)) {
        local_errors.emplace_back("runtime binding is incomplete or malformed");
    }
    if (!valid_token(request.capability, 192U) ||
        !capability_present(receipt.capabilities, request.capability)) {
        local_errors.emplace_back("runtime lease capability is not present in session-key authority");
    }
    if (request.issued_at_unix_ms < receipt.issued_at_unix_ms ||
        request.expires_at_unix_ms > receipt.expires_at_unix_ms ||
        request.expires_at_unix_ms <= request.issued_at_unix_ms) {
        local_errors.emplace_back("runtime lease lifetime must fit inside session-key lifetime");
    }
    if (request.max_uses == 0U || request.max_uses > receipt.max_uses) {
        local_errors.emplace_back("runtime lease use budget must fit inside session-key budget");
    }
    if (!valid_token(request.nonce, 128U)) {
        local_errors.emplace_back("runtime lease nonce is invalid");
    }
    if (!local_errors.empty()) {
        if (errors) *errors = std::move(local_errors);
        return std::nullopt;
    }

    RuntimeCapabilityLease lease;
    lease.schema_version = 1U;
    lease.session_key_receipt_id = receipt.receipt_id;
    lease.certificate_id = bundle.certificate.certificate_id;
    lease.signer_id = receipt.signer_id;
    lease.key_id = receipt.key_id;
    lease.algorithm = receipt.algorithm;
    lease.key_fingerprint_sha256 = receipt.key_fingerprint_sha256;
    lease.purpose = receipt.purpose;
    lease.subject_id = receipt.subject_id;
    lease.scope_path = receipt.scope_path;
    lease.scope_sha256 = receipt.scope_sha256;
    lease.capability = request.capability;
    lease.binding = request.binding;
    lease.issued_at_unix_ms = request.issued_at_unix_ms;
    lease.expires_at_unix_ms = request.expires_at_unix_ms;
    lease.max_uses = request.max_uses;
    lease.nonce = request.nonce;

    const auto canonical = canonical_runtime_capability_lease(lease);
    lease.canonical_sha256 = sha256(canonical);
    auto signature = signer.sign(canonical);
    if (!signature || signature->empty()) {
        if (errors) errors->assign({"session key failed to sign runtime capability lease"});
        return std::nullopt;
    }
    lease.signature = std::move(*signature);
    lease.lease_id = runtime_capability_lease_id(lease, lease.signature);
    if (errors) errors->clear();
    return lease;
}

RuntimeLeaseLedger::RuntimeLeaseLedger(std::filesystem::path journal_path,
                                       Clock clock)
    : journal_path_(std::move(journal_path)),
      clock_(clock ? std::move(clock) : Clock{system_now_ms}) {
    static_cast<void>(replay());
}

std::uint64_t RuntimeLeaseLedger::now_ms() const {
    return clock_ ? clock_() : system_now_ms();
}

bool RuntimeLeaseLedger::append_event(std::string_view body, std::string* error) {
    if (!healthy_) {
        if (error) *error = "runtime lease ledger is unhealthy";
        return false;
    }
    if (journal_path_.empty()) {
        if (error) *error = "runtime lease ledger requires a journal path";
        return false;
    }

    std::error_code ec;
    const auto parent = journal_path_.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            if (error) *error = "unable to create runtime lease journal directory";
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
        if (error) *error = "unable to open runtime lease journal";
        return false;
    }
    output << canonical_text << '\t' << record_sha << '\n';
    output.flush();
    if (!output) {
        if (error) *error = "unable to append runtime lease journal";
        return false;
    }

    sequence_ = next_sequence;
    last_record_sha256_ = record_sha;
    if (error) error->clear();
    return true;
}

RuntimeLeaseResult RuntimeLeaseLedger::register_lease(
    const RuntimeCapabilityLease& lease,
    const SessionKeyBundle& bundle,
    const SessionKeyVerifier& key_verifier) {
    RuntimeLeaseResult result;
    result.lease_id = lease.lease_id;
    if (!healthy_) {
        result.status = RuntimeLeaseStatus::Corrupt;
        result.errors = errors_;
        return result;
    }
    const auto validated = validate_lease(lease, bundle, key_verifier);
    if (!validated.ok()) return validated;
    if (registrations_.contains(lease.lease_id)) {
        result.status = RuntimeLeaseStatus::NotRegistered;
        result.errors.emplace_back("runtime lease is already registered");
        return result;
    }
    if (now_ms() >= lease.expires_at_unix_ms) {
        result.status = RuntimeLeaseStatus::LeaseExpired;
        result.errors.emplace_back("runtime lease is already expired");
        return result;
    }

    const auto binding_sha = runtime_binding_sha256(lease.binding);
    std::ostringstream body;
    body << "L\t" << hex_encode(lease.lease_id)
         << '\t' << hex_encode(lease.session_key_receipt_id)
         << '\t' << hex_encode(lease.certificate_id)
         << '\t' << hex_encode(lease.signer_id)
         << '\t' << hex_encode(lease.key_id)
         << '\t' << hex_encode(lease.key_fingerprint_sha256)
         << '\t' << binding_sha
         << '\t' << lease.expires_at_unix_ms
         << '\t' << lease.max_uses;
    std::string error;
    if (!append_event(body.str(), &error)) {
        result.status = RuntimeLeaseStatus::StorageError;
        result.errors.push_back(std::move(error));
        return result;
    }

    registrations_.emplace(lease.lease_id, Registration{
        lease.session_key_receipt_id,
        lease.certificate_id,
        lease.signer_id,
        lease.key_id,
        lease.key_fingerprint_sha256,
        binding_sha,
        lease.expires_at_unix_ms,
        lease.max_uses,
    });
    result.status = RuntimeLeaseStatus::Allowed;
    return result;
}

RuntimeLeaseResult RuntimeLeaseLedger::preflight(
    const RuntimeCapabilityLease& lease,
    const SessionKeyBundle& bundle,
    const SessionKeyVerifier& key_verifier,
    const RuntimeBinding& observed_binding) const {
    RuntimeLeaseResult result;
    result.lease_id = lease.lease_id;
    if (!healthy_) {
        result.status = RuntimeLeaseStatus::Corrupt;
        result.errors = errors_;
        return result;
    }
    const auto validated = validate_lease(lease, bundle, key_verifier);
    if (!validated.ok()) return validated;
    const auto registration = registrations_.find(lease.lease_id);
    if (registration == registrations_.end()) {
        result.status = RuntimeLeaseStatus::NotRegistered;
        result.errors.emplace_back("runtime lease is not registered");
        return result;
    }
    const auto& stored = registration->second;
    if (stored.session_key_receipt_id != lease.session_key_receipt_id ||
        stored.certificate_id != lease.certificate_id ||
        stored.signer_id != lease.signer_id ||
        stored.key_id != lease.key_id ||
        stored.key_fingerprint_sha256 != lease.key_fingerprint_sha256 ||
        stored.binding_sha256 != runtime_binding_sha256(lease.binding) ||
        stored.expires_at_unix_ms != lease.expires_at_unix_ms ||
        stored.max_uses != lease.max_uses) {
        result.status = RuntimeLeaseStatus::NotRegistered;
        result.errors.emplace_back("runtime lease does not match durable registration");
        return result;
    }
    if (!valid_binding(observed_binding)) {
        result.status = RuntimeLeaseStatus::Invalid;
        result.errors.emplace_back("observed runtime binding is malformed");
        return result;
    }
    if (observed_binding.device_id != lease.binding.device_id) {
        result.status = RuntimeLeaseStatus::DeviceMismatch;
        result.errors.emplace_back("runtime lease device identity mismatch");
        return result;
    }
    if (observed_binding.executable_sha256 != lease.binding.executable_sha256) {
        result.status = RuntimeLeaseStatus::ExecutableMismatch;
        result.errors.emplace_back("runtime lease executable identity mismatch");
        return result;
    }
    if (observed_binding.process_instance_sha256 != lease.binding.process_instance_sha256) {
        result.status = RuntimeLeaseStatus::ProcessMismatch;
        result.errors.emplace_back("runtime lease process-instance identity mismatch");
        return result;
    }
    if (observed_binding.slot_id != lease.binding.slot_id) {
        result.status = RuntimeLeaseStatus::SlotMismatch;
        result.errors.emplace_back("runtime lease CLUBHOUSE slot mismatch");
        return result;
    }
    if (observed_binding.session_id != lease.binding.session_id) {
        result.status = RuntimeLeaseStatus::SessionMismatch;
        result.errors.emplace_back("runtime lease transaction/session mismatch");
        return result;
    }
    if (observed_binding.layer != lease.binding.layer) {
        result.status = RuntimeLeaseStatus::LayerMismatch;
        result.errors.emplace_back("runtime lease STRATA layer mismatch");
        return result;
    }
    if (!same_binding(observed_binding, lease.binding)) {
        result.status = RuntimeLeaseStatus::Invalid;
        result.errors.emplace_back("runtime lease binding mismatch");
        return result;
    }
    if (revoked_leases_.contains(lease.lease_id)) {
        result.status = RuntimeLeaseStatus::LeaseRevoked;
        result.errors.emplace_back("runtime capability lease is revoked");
        return result;
    }
    if (now_ms() >= lease.expires_at_unix_ms) {
        result.status = RuntimeLeaseStatus::LeaseExpired;
        result.errors.emplace_back("runtime capability lease has expired");
        return result;
    }
    const auto used = use_count(lease.lease_id);
    if (used >= lease.max_uses) {
        result.status = RuntimeLeaseStatus::UseLimitReached;
        result.use_count = used;
        result.errors.emplace_back("runtime capability lease use limit reached");
        return result;
    }

    result.status = RuntimeLeaseStatus::Allowed;
    result.use_count = used;
    return result;
}

RuntimeLeaseResult RuntimeLeaseLedger::consume(const RuntimeCapabilityLease& lease) {
    RuntimeLeaseResult result;
    result.lease_id = lease.lease_id;
    if (!healthy_) {
        result.status = RuntimeLeaseStatus::Corrupt;
        result.errors = errors_;
        return result;
    }
    const auto registration = registrations_.find(lease.lease_id);
    if (registration == registrations_.end()) {
        result.status = RuntimeLeaseStatus::NotRegistered;
        result.errors.emplace_back("runtime lease is not registered");
        return result;
    }
    if (revoked_leases_.contains(lease.lease_id)) {
        result.status = RuntimeLeaseStatus::LeaseRevoked;
        result.errors.emplace_back("runtime capability lease is revoked");
        return result;
    }
    const auto now = now_ms();
    if (now >= registration->second.expires_at_unix_ms) {
        result.status = RuntimeLeaseStatus::LeaseExpired;
        result.errors.emplace_back("runtime capability lease has expired");
        return result;
    }
    const auto used = use_count(lease.lease_id);
    if (used >= registration->second.max_uses) {
        result.status = RuntimeLeaseStatus::UseLimitReached;
        result.use_count = used;
        result.errors.emplace_back("runtime capability lease use limit reached");
        return result;
    }

    const auto next_use = used + 1U;
    std::ostringstream body;
    body << "U\t" << hex_encode(lease.lease_id)
         << '\t' << next_use
         << '\t' << now;
    std::string error;
    if (!append_event(body.str(), &error)) {
        result.status = RuntimeLeaseStatus::StorageError;
        result.errors.push_back(std::move(error));
        return result;
    }
    lease_uses_[lease.lease_id] = next_use;
    result.status = RuntimeLeaseStatus::Allowed;
    result.use_count = next_use;
    return result;
}

RuntimeLeaseResult RuntimeLeaseLedger::revoke_lease(
    std::string_view lease_id,
    std::uint64_t revoked_at_unix_ms) {
    RuntimeLeaseResult result;
    result.lease_id = std::string(lease_id);
    if (!prefixed_sha256(lease_id, kLeasePrefix) || revoked_at_unix_ms == 0U) {
        result.status = RuntimeLeaseStatus::Invalid;
        result.errors.emplace_back("runtime lease revocation request is invalid");
        return result;
    }
    if (!registrations_.contains(result.lease_id)) {
        result.status = RuntimeLeaseStatus::NotRegistered;
        result.errors.emplace_back("runtime lease is not registered");
        return result;
    }
    if (revoked_leases_.contains(result.lease_id)) {
        result.status = RuntimeLeaseStatus::LeaseRevoked;
        result.errors.emplace_back("runtime lease is already revoked");
        return result;
    }

    std::ostringstream body;
    body << "X\t" << hex_encode(lease_id) << '\t' << revoked_at_unix_ms;
    std::string error;
    if (!append_event(body.str(), &error)) {
        result.status = RuntimeLeaseStatus::StorageError;
        result.errors.push_back(std::move(error));
        return result;
    }
    revoked_leases_[result.lease_id] = revoked_at_unix_ms;
    result.status = RuntimeLeaseStatus::Allowed;
    return result;
}

bool RuntimeLeaseLedger::replay(std::vector<std::string>* errors) {
    registrations_.clear();
    lease_uses_.clear();
    revoked_leases_.clear();
    sequence_ = 0U;
    last_record_sha256_.clear();
    healthy_ = true;
    errors_.clear();

    if (journal_path_.empty() || !std::filesystem::exists(journal_path_)) {
        if (errors) errors->clear();
        return true;
    }
    std::ifstream input(journal_path_, std::ios::binary);
    if (!input) {
        healthy_ = false;
        errors_.emplace_back("unable to open runtime lease journal for replay");
        if (errors) *errors = errors_;
        return false;
    }

    std::string line;
    std::size_t line_number = 0U;
    while (std::getline(input, line)) {
        ++line_number;
        if (line.empty()) continue;
        const auto fields = split_tabs(line);
        if (fields.size() < 6U) {
            healthy_ = false;
            errors_.push_back("runtime lease journal line " + std::to_string(line_number) + " is malformed");
            break;
        }
        std::size_t sequence = 0U;
        if (!parse_unsigned(fields[0], &sequence) || sequence != sequence_ + 1U) {
            healthy_ = false;
            errors_.push_back("runtime lease sequence discontinuity at line " + std::to_string(line_number));
            break;
        }
        const std::string expected_previous = last_record_sha256_.empty()
            ? std::string(64U, '0') : last_record_sha256_;
        if (fields[1] != expected_previous) {
            healthy_ = false;
            errors_.push_back("runtime lease previous-record hash mismatch at line " + std::to_string(line_number));
            break;
        }
        const auto last_tab = line.rfind('\t');
        if (last_tab == std::string::npos || !is_sha256(fields.back()) ||
            sha256(std::string_view(line).substr(0U, last_tab)) != fields.back()) {
            healthy_ = false;
            errors_.push_back("runtime lease record hash mismatch at line " + std::to_string(line_number));
            break;
        }

        bool event_ok = true;
        const auto type = fields[2];
        if (type == "L" && fields.size() == 13U) {
            auto lease_id = hex_decode(fields[3]);
            auto session_receipt = hex_decode(fields[4]);
            auto certificate_id = hex_decode(fields[5]);
            auto signer_id = hex_decode(fields[6]);
            auto key_id = hex_decode(fields[7]);
            auto fingerprint = hex_decode(fields[8]);
            const auto binding_sha = fields[9];
            std::uint64_t expires_at = 0U;
            std::uint32_t max_uses = 0U;
            event_ok = lease_id && session_receipt && certificate_id && signer_id && key_id && fingerprint &&
                       prefixed_sha256(*lease_id, kLeasePrefix) && is_sha256(*fingerprint) &&
                       is_sha256(binding_sha) && parse_unsigned(fields[10], &expires_at) && expires_at != 0U &&
                       parse_unsigned(fields[11], &max_uses) && max_uses != 0U &&
                       !registrations_.contains(*lease_id);
            if (event_ok) {
                registrations_.emplace(*lease_id, Registration{
                    *session_receipt,
                    *certificate_id,
                    *signer_id,
                    *key_id,
                    *fingerprint,
                    std::string(binding_sha),
                    expires_at,
                    max_uses,
                });
            }
        } else if (type == "U" && fields.size() == 7U) {
            auto lease_id = hex_decode(fields[3]);
            std::size_t use_index = 0U;
            std::uint64_t at = 0U;
            event_ok = lease_id && registrations_.contains(*lease_id) &&
                       parse_unsigned(fields[4], &use_index) && use_index != 0U &&
                       parse_unsigned(fields[5], &at) && at != 0U &&
                       use_index == use_count(*lease_id) + 1U;
            if (event_ok) lease_uses_[*lease_id] = use_index;
        } else if (type == "X" && fields.size() == 6U) {
            auto lease_id = hex_decode(fields[3]);
            std::uint64_t at = 0U;
            event_ok = lease_id && registrations_.contains(*lease_id) &&
                       parse_unsigned(fields[4], &at) && at != 0U &&
                       !revoked_leases_.contains(*lease_id);
            if (event_ok) revoked_leases_[*lease_id] = at;
        } else {
            event_ok = false;
        }

        if (!event_ok) {
            healthy_ = false;
            errors_.push_back("runtime lease event contract failed at line " + std::to_string(line_number));
            break;
        }
        sequence_ = sequence;
        last_record_sha256_ = std::string(fields.back());
    }

    if (errors) *errors = errors_;
    return healthy_;
}

RuntimeLeaseInspection RuntimeLeaseLedger::inspect() const {
    RuntimeLeaseInspection inspection;
    inspection.healthy = healthy_;
    inspection.records = sequence_;
    inspection.registered_leases = registrations_.size();
    inspection.consumed_leases = lease_uses_.size();
    inspection.revoked_leases = revoked_leases_.size();
    inspection.errors = errors_;
    return inspection;
}

std::size_t RuntimeLeaseLedger::use_count(std::string_view lease_id) const noexcept {
    const auto it = lease_uses_.find(std::string(lease_id));
    return it == lease_uses_.end() ? 0U : it->second;
}

bool RuntimeLeaseLedger::lease_registered(std::string_view lease_id) const noexcept {
    return registrations_.contains(std::string(lease_id));
}

bool RuntimeLeaseLedger::lease_revoked(std::string_view lease_id) const noexcept {
    return revoked_leases_.contains(std::string(lease_id));
}

const std::filesystem::path& RuntimeLeaseLedger::journal_path() const noexcept {
    return journal_path_;
}

RuntimeLeaseAuthorityGate::RuntimeLeaseAuthorityGate(
    RuntimeLeaseLedger& lease_ledger,
    const SessionKeyVerifier& key_verifier,
    const SessionKeyAuthorityGate& session_key_gate) noexcept
    : lease_ledger_(lease_ledger),
      key_verifier_(key_verifier),
      session_key_gate_(session_key_gate) {}

RuntimeLeaseResult RuntimeLeaseAuthorityGate::authorize(
    const RuntimeCapabilityLease& lease,
    const SessionKeyBundle& bundle,
    const RuntimeBinding& observed_binding) const {
    auto preflight = lease_ledger_.preflight(lease, bundle, key_verifier_, observed_binding);
    if (!preflight.ok()) return preflight;

    const auto session = session_key_gate_.authorize(
        bundle,
        lease.purpose,
        lease.subject_id,
        lease.scope_sha256,
        lease.capability);
    if (!session.ok()) {
        RuntimeLeaseResult denied;
        denied.status = RuntimeLeaseStatus::SessionKeyRejected;
        denied.session_key_status = session.status;
        denied.backing_ledger_status = session.backing_ledger_status;
        denied.lease_id = lease.lease_id;
        denied.errors = session.errors;
        return denied;
    }

    auto consumed = lease_ledger_.consume(lease);
    consumed.session_key_status = session.status;
    consumed.backing_ledger_status = session.backing_ledger_status;
    if (!consumed.ok()) {
        consumed.errors.emplace_back(
            "session-key authority was consumed, but runtime lease durability failed; side effects must remain blocked");
    }
    return consumed;
}

std::string_view to_string(RuntimeLeaseStatus status) noexcept {
    switch (status) {
    case RuntimeLeaseStatus::Allowed: return "ALLOWED";
    case RuntimeLeaseStatus::Invalid: return "INVALID";
    case RuntimeLeaseStatus::NotRegistered: return "NOT_REGISTERED";
    case RuntimeLeaseStatus::SignatureRejected: return "SIGNATURE_REJECTED";
    case RuntimeLeaseStatus::KeyMismatch: return "KEY_MISMATCH";
    case RuntimeLeaseStatus::SessionKeyMismatch: return "SESSION_KEY_MISMATCH";
    case RuntimeLeaseStatus::DeviceMismatch: return "DEVICE_MISMATCH";
    case RuntimeLeaseStatus::ExecutableMismatch: return "EXECUTABLE_MISMATCH";
    case RuntimeLeaseStatus::ProcessMismatch: return "PROCESS_MISMATCH";
    case RuntimeLeaseStatus::SlotMismatch: return "SLOT_MISMATCH";
    case RuntimeLeaseStatus::SessionMismatch: return "SESSION_MISMATCH";
    case RuntimeLeaseStatus::LayerMismatch: return "LAYER_MISMATCH";
    case RuntimeLeaseStatus::CapabilityMismatch: return "CAPABILITY_MISMATCH";
    case RuntimeLeaseStatus::ScopeMismatch: return "SCOPE_MISMATCH";
    case RuntimeLeaseStatus::LeaseExpired: return "LEASE_EXPIRED";
    case RuntimeLeaseStatus::UseLimitReached: return "USE_LIMIT_REACHED";
    case RuntimeLeaseStatus::LeaseRevoked: return "LEASE_REVOKED";
    case RuntimeLeaseStatus::SessionKeyRejected: return "SESSION_KEY_REJECTED";
    case RuntimeLeaseStatus::StorageError: return "STORAGE_ERROR";
    case RuntimeLeaseStatus::Corrupt: return "CORRUPT";
    }
    return "INVALID";
}

} // namespace guff
