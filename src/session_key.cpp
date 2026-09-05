#include "guff/session_key.hpp"

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

constexpr std::string_view kCertificatePrefix = "guff:key-handoff:sha256:";
constexpr std::string_view kReceiptPrefix = "guff:session-key:sha256:";
constexpr std::string_view kAuthorityReceiptPrefix = "guff:authority:sha256:";

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

bool valid_token(std::string_view value, std::size_t max_bytes = 128U) {
    if (value.empty() || value.size() > max_bytes) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' ||
               ch == '.' || ch == ':' || ch == '/';
    });
}

bool valid_capability(std::string_view value) {
    return valid_token(value, 96U);
}

bool valid_certificate_id(std::string_view value) {
    return value.starts_with(kCertificatePrefix) &&
           is_sha256(value.substr(kCertificatePrefix.size()));
}

bool valid_session_receipt_id(std::string_view value) {
    return value.starts_with(kReceiptPrefix) &&
           is_sha256(value.substr(kReceiptPrefix.size()));
}

bool valid_authority_receipt_id(std::string_view value) {
    return value.starts_with(kAuthorityReceiptPrefix) &&
           is_sha256(value.substr(kAuthorityReceiptPrefix.size()));
}

std::uint64_t system_now_ms() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

std::vector<std::string> canonical_capabilities(std::vector<std::string> values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    return values;
}

bool valid_capabilities(const std::vector<std::string>& capabilities) {
    if (capabilities.empty() || capabilities.size() > 64U) return false;
    return std::all_of(capabilities.begin(), capabilities.end(), [](const auto& capability) {
        return valid_capability(capability);
    });
}

bool contains_capability(const std::vector<std::string>& capabilities,
                         std::string_view capability) {
    return std::find(capabilities.begin(), capabilities.end(), capability) != capabilities.end();
}

bool exact_capabilities(const std::vector<std::string>& lhs,
                        const std::vector<std::string>& rhs) {
    return canonical_capabilities(lhs) == canonical_capabilities(rhs);
}

std::string capabilities_digest(const std::vector<std::string>& capabilities) {
    const auto sorted = canonical_capabilities(capabilities);
    std::ostringstream out;
    for (const auto& capability : sorted) out << capability << '\n';
    return sha256(out.str());
}

SessionKeyResult fail(SessionKeyStatus status, std::string message) {
    SessionKeyResult result;
    result.status = status;
    result.errors.push_back(std::move(message));
    return result;
}

bool verify_certificate(const SessionKeyBundle& bundle,
                        const AuthorityVerifier& parent_verifier,
                        std::vector<std::string>* errors) {
    const auto& voucher = bundle.voucher;
    const auto& certificate = bundle.certificate;
    std::vector<std::string> local;
    if (certificate.schema_version != 1U ||
        certificate.voucher_receipt_id != voucher.receipt_id ||
        !valid_certificate_id(certificate.certificate_id) ||
        !is_sha256(certificate.canonical_sha256) ||
        !is_sha256(certificate.child_key_fingerprint_sha256) ||
        !is_sha256(certificate.scope_sha256) ||
        certificate.scope_sha256 != sha256(certificate.scope_path) ||
        !valid_capabilities(certificate.capabilities) ||
        certificate.issued_at_unix_ms == 0U ||
        certificate.expires_at_unix_ms <= certificate.issued_at_unix_ms ||
        certificate.max_uses == 0U || certificate.max_uses > 1024U ||
        !valid_token(certificate.nonce)) {
        local.emplace_back("session-key certificate fields are invalid");
    }
    const auto canonical = canonical_session_key_certificate(certificate);
    if (certificate.canonical_sha256 != sha256(canonical) ||
        certificate.certificate_id !=
            session_key_certificate_id(certificate, certificate.parent_signature)) {
        local.emplace_back("session-key certificate identity mismatch");
    }
    if (certificate.parent_signer_id != voucher.envelope.signer_id ||
        certificate.parent_key_id != voucher.envelope.signer_key_id ||
        certificate.parent_algorithm != voucher.algorithm) {
        local.emplace_back("session-key certificate parent signer does not match voucher signer");
    }
    if (certificate.purpose != voucher.envelope.purpose ||
        certificate.subject_id != voucher.envelope.subject_id ||
        certificate.scope_path != voucher.envelope.scope_path ||
        certificate.scope_sha256 != voucher.envelope.scope_sha256 ||
        !exact_capabilities(certificate.capabilities, voucher.envelope.capabilities) ||
        certificate.issued_at_unix_ms != voucher.envelope.issued_at_unix_ms ||
        certificate.expires_at_unix_ms != voucher.envelope.expires_at_unix_ms ||
        certificate.max_uses != voucher.envelope.max_uses) {
        local.emplace_back("session-key certificate authority does not exactly match backing voucher");
    }
    if (!parent_verifier.knows(certificate.parent_signer_id,
                               certificate.parent_algorithm) ||
        !parent_verifier.verify(certificate.parent_signer_id,
                                certificate.parent_algorithm,
                                canonical,
                                certificate.parent_signature)) {
        local.emplace_back("session-key certificate parent signature rejected");
    }
    if (errors) *errors = local;
    return local.empty();
}

bool verify_child_receipt(const SessionKeyBundle& bundle,
                          const SessionKeyVerifier& verifier,
                          std::vector<std::string>* errors) {
    const auto& certificate = bundle.certificate;
    const auto& receipt = bundle.receipt;
    std::vector<std::string> local;
    if (receipt.schema_version != 1U ||
        receipt.certificate_id != certificate.certificate_id ||
        receipt.voucher_receipt_id != certificate.voucher_receipt_id ||
        !valid_session_receipt_id(receipt.receipt_id) ||
        !is_sha256(receipt.canonical_sha256) ||
        !is_sha256(receipt.key_fingerprint_sha256) ||
        !is_sha256(receipt.scope_sha256) ||
        receipt.scope_sha256 != sha256(receipt.scope_path) ||
        !valid_capabilities(receipt.capabilities) ||
        !valid_token(receipt.signer_id) || !valid_token(receipt.key_id) ||
        !valid_token(receipt.algorithm, 64U) || !valid_token(receipt.nonce) ||
        receipt.issued_at_unix_ms == 0U ||
        receipt.expires_at_unix_ms <= receipt.issued_at_unix_ms ||
        receipt.max_uses == 0U || receipt.max_uses > 1024U) {
        local.emplace_back("session-key receipt fields are invalid");
    }
    if (receipt.signer_id != certificate.child_signer_id ||
        receipt.key_id != certificate.child_key_id ||
        receipt.algorithm != certificate.child_algorithm ||
        receipt.key_fingerprint_sha256 != certificate.child_key_fingerprint_sha256 ||
        receipt.purpose != certificate.purpose ||
        receipt.subject_id != certificate.subject_id ||
        receipt.scope_path != certificate.scope_path ||
        receipt.scope_sha256 != certificate.scope_sha256 ||
        !exact_capabilities(receipt.capabilities, certificate.capabilities) ||
        receipt.issued_at_unix_ms != certificate.issued_at_unix_ms ||
        receipt.expires_at_unix_ms != certificate.expires_at_unix_ms ||
        receipt.max_uses != certificate.max_uses) {
        local.emplace_back("session-key receipt does not exactly match handoff certificate");
    }
    const auto canonical = canonical_session_key_receipt(receipt);
    if (receipt.canonical_sha256 != sha256(canonical) ||
        receipt.receipt_id != session_key_receipt_id(receipt, receipt.signature)) {
        local.emplace_back("session-key receipt content identity mismatch");
    }
    if (!verifier.knows_key(receipt.signer_id, receipt.key_id, receipt.algorithm)) {
        local.emplace_back("session-key verifier does not know delegated key");
    } else {
        const auto fingerprint = verifier.key_fingerprint_sha256(
            receipt.signer_id, receipt.key_id, receipt.algorithm);
        if (!fingerprint || !is_sha256(*fingerprint) ||
            *fingerprint != receipt.key_fingerprint_sha256) {
            local.emplace_back("session-key fingerprint does not match verifier key material");
        }
        if (!verifier.verify_key(receipt.signer_id,
                                 receipt.key_id,
                                 receipt.algorithm,
                                 canonical,
                                 receipt.signature)) {
            local.emplace_back("session-key receipt signature rejected");
        }
    }
    if (errors) *errors = local;
    return local.empty();
}

} // namespace

bool SessionKeyResult::ok() const noexcept {
    return status == SessionKeyStatus::Allowed;
}

bool SessionKeyHandoffResult::ok() const noexcept {
    return status == SessionKeyHandoffStatus::Issued && bundle.has_value();
}

std::string canonical_session_key_certificate(
    const SessionKeyCertificate& certificate) {
    std::ostringstream out;
    out << certificate.schema_version << '\n'
        << certificate.voucher_receipt_id << '\n'
        << certificate.parent_signer_id << '\n'
        << certificate.parent_key_id << '\n'
        << certificate.parent_algorithm << '\n'
        << certificate.child_signer_id << '\n'
        << certificate.child_key_id << '\n'
        << certificate.child_algorithm << '\n'
        << certificate.child_key_fingerprint_sha256 << '\n'
        << static_cast<unsigned>(certificate.purpose) << '\n'
        << certificate.subject_id << '\n'
        << certificate.scope_path << '\n'
        << certificate.scope_sha256 << '\n'
        << capabilities_digest(certificate.capabilities) << '\n'
        << certificate.issued_at_unix_ms << '\n'
        << certificate.expires_at_unix_ms << '\n'
        << certificate.max_uses << '\n'
        << certificate.nonce;
    return out.str();
}

std::string canonical_session_key_receipt(const SessionKeyReceipt& receipt) {
    std::ostringstream out;
    out << receipt.schema_version << '\n'
        << receipt.certificate_id << '\n'
        << receipt.voucher_receipt_id << '\n'
        << receipt.signer_id << '\n'
        << receipt.key_id << '\n'
        << receipt.algorithm << '\n'
        << receipt.key_fingerprint_sha256 << '\n'
        << static_cast<unsigned>(receipt.purpose) << '\n'
        << receipt.subject_id << '\n'
        << receipt.scope_path << '\n'
        << receipt.scope_sha256 << '\n'
        << capabilities_digest(receipt.capabilities) << '\n'
        << receipt.issued_at_unix_ms << '\n'
        << receipt.expires_at_unix_ms << '\n'
        << receipt.max_uses << '\n'
        << receipt.nonce;
    return out.str();
}

std::string session_key_certificate_id(
    const SessionKeyCertificate& certificate,
    std::string_view parent_signature) {
    std::ostringstream out;
    out << sha256(canonical_session_key_certificate(certificate)) << '\n'
        << parent_signature;
    return std::string(kCertificatePrefix) + sha256(out.str());
}

std::string session_key_receipt_id(
    const SessionKeyReceipt& receipt,
    std::string_view signature) {
    std::ostringstream out;
    out << sha256(canonical_session_key_receipt(receipt)) << '\n'
        << signature;
    return std::string(kReceiptPrefix) + sha256(out.str());
}

SessionKeyLedger::SessionKeyLedger(std::filesystem::path journal_path)
    : journal_path_(std::move(journal_path)) {
    static_cast<void>(replay());
}

std::string SessionKeyLedger::key_map_id(std::string_view signer_id,
                                         std::string_view key_id) const {
    return std::string(signer_id) + "\n" + std::string(key_id);
}

bool SessionKeyLedger::append_event(std::string_view body, std::string* error) {
    if (!healthy_) {
        if (error) *error = "session-key ledger is unhealthy";
        return false;
    }
    if (journal_path_.empty()) {
        if (error) *error = "session-key ledger requires a journal path";
        return false;
    }
    std::error_code ec;
    const auto parent = journal_path_.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            if (error) *error = "unable to create session-key ledger directory";
            return false;
        }
    }
    const std::size_t next_sequence = sequence_ + 1U;
    const std::string previous = last_record_sha256_.empty()
        ? std::string(64U, '0') : last_record_sha256_;
    std::ostringstream canonical;
    canonical << next_sequence << '\t' << previous << '\t' << body;
    const auto text = canonical.str();
    const auto record_sha = sha256(text);
    std::ofstream output(journal_path_, std::ios::binary | std::ios::app);
    if (!output) {
        if (error) *error = "unable to open session-key journal";
        return false;
    }
    output << text << '\t' << record_sha << '\n';
    output.flush();
    if (!output) {
        if (error) *error = "unable to append session-key journal";
        return false;
    }
    sequence_ = next_sequence;
    last_record_sha256_ = record_sha;
    if (error) error->clear();
    return true;
}

SessionKeyResult SessionKeyLedger::register_bundle(const SessionKeyBundle& bundle) {
    SessionKeyResult result;
    result.receipt_id = bundle.receipt.receipt_id;
    if (!healthy_) {
        result.status = SessionKeyStatus::Corrupt;
        result.errors = errors_;
        return result;
    }
    const auto& voucher = bundle.voucher;
    const auto& certificate = bundle.certificate;
    const auto& receipt = bundle.receipt;
    if (!valid_authority_receipt_id(voucher.receipt_id) ||
        !valid_certificate_id(certificate.certificate_id) ||
        !valid_session_receipt_id(receipt.receipt_id) ||
        certificate.voucher_receipt_id != voucher.receipt_id ||
        receipt.voucher_receipt_id != voucher.receipt_id ||
        receipt.certificate_id != certificate.certificate_id ||
        receipt.signer_id != certificate.child_signer_id ||
        receipt.key_id != certificate.child_key_id ||
        receipt.algorithm != certificate.child_algorithm ||
        receipt.key_fingerprint_sha256 != certificate.child_key_fingerprint_sha256 ||
        receipt.max_uses != certificate.max_uses ||
        receipt.expires_at_unix_ms != certificate.expires_at_unix_ms) {
        return fail(SessionKeyStatus::Invalid,
                    "session-key bundle registration fields disagree");
    }
    if (registrations_.contains(receipt.receipt_id)) {
        return fail(SessionKeyStatus::Invalid,
                    "session-key receipt is already registered");
    }
    for (const auto& entry : registrations_) {
        const auto& registration = entry.second;
        if (registration.signer_id == receipt.signer_id &&
            registration.key_id == receipt.key_id) {
            return fail(SessionKeyStatus::Invalid,
                        "an ephemeral delegated key may back only one registered branch");
        }
    }
    std::ostringstream body;
    body << "H\t" << hex_encode(voucher.receipt_id)
         << '\t' << hex_encode(certificate.certificate_id)
         << '\t' << hex_encode(receipt.receipt_id)
         << '\t' << hex_encode(receipt.signer_id)
         << '\t' << hex_encode(receipt.key_id)
         << '\t' << hex_encode(receipt.algorithm)
         << '\t' << receipt.key_fingerprint_sha256
         << '\t' << receipt.expires_at_unix_ms
         << '\t' << receipt.max_uses;
    std::string error;
    if (!append_event(body.str(), &error)) {
        return fail(SessionKeyStatus::StorageError, std::move(error));
    }
    registrations_[receipt.receipt_id] = Registration{
        voucher.receipt_id,
        certificate.certificate_id,
        receipt.receipt_id,
        receipt.signer_id,
        receipt.key_id,
        receipt.algorithm,
        receipt.key_fingerprint_sha256,
        receipt.expires_at_unix_ms,
        receipt.max_uses,
    };
    result.status = SessionKeyStatus::Allowed;
    return result;
}

SessionKeyResult SessionKeyLedger::preflight(
    const SessionKeyBundle& bundle,
    const AuthorityVerifier& parent_verifier,
    const SessionKeyVerifier& key_verifier,
    AuthorityPurpose expected_purpose,
    std::string_view expected_subject_id,
    std::string_view expected_scope_sha256,
    std::string_view expected_capability) const {
    SessionKeyResult result;
    result.receipt_id = bundle.receipt.receipt_id;
    if (!healthy_) {
        result.status = SessionKeyStatus::Corrupt;
        result.errors = errors_;
        return result;
    }
    const auto registration = registrations_.find(bundle.receipt.receipt_id);
    if (registration == registrations_.end()) {
        result.status = SessionKeyStatus::NotRegistered;
        result.errors.emplace_back("session-key receipt is not registered in handoff ledger");
        return result;
    }
    const auto& registered = registration->second;
    if (registered.voucher_receipt_id != bundle.voucher.receipt_id ||
        registered.certificate_id != bundle.certificate.certificate_id ||
        registered.signer_id != bundle.receipt.signer_id ||
        registered.key_id != bundle.receipt.key_id ||
        registered.algorithm != bundle.receipt.algorithm ||
        registered.key_fingerprint_sha256 != bundle.receipt.key_fingerprint_sha256 ||
        registered.max_uses != bundle.receipt.max_uses) {
        result.status = SessionKeyStatus::NotRegistered;
        result.errors.emplace_back("session-key bundle does not match durable handoff registration");
        return result;
    }
    const auto voucher_verified = verify_authority_receipt(
        bundle.voucher,
        parent_verifier,
        expected_purpose,
        expected_subject_id);
    if (!voucher_verified.ok()) {
        result.status = SessionKeyStatus::VoucherRejected;
        result.errors = voucher_verified.errors;
        return result;
    }
    std::vector<std::string> certificate_errors;
    if (!verify_certificate(bundle, parent_verifier, &certificate_errors)) {
        result.status = SessionKeyStatus::CertificateRejected;
        result.errors = std::move(certificate_errors);
        return result;
    }
    std::vector<std::string> receipt_errors;
    if (!verify_child_receipt(bundle, key_verifier, &receipt_errors)) {
        const bool fingerprint = std::any_of(
            receipt_errors.begin(), receipt_errors.end(), [](const std::string& error) {
                return error.find("fingerprint") != std::string::npos;
            });
        result.status = fingerprint ? SessionKeyStatus::FingerprintMismatch
                                    : SessionKeyStatus::ReceiptRejected;
        result.errors = std::move(receipt_errors);
        return result;
    }
    if (!is_sha256(expected_scope_sha256) ||
        bundle.receipt.scope_sha256 != expected_scope_sha256 ||
        bundle.voucher.envelope.scope_sha256 != expected_scope_sha256) {
        result.status = SessionKeyStatus::ScopeMismatch;
        result.errors.emplace_back("session key scope does not match requested operation");
        return result;
    }
    if (bundle.receipt.purpose != expected_purpose ||
        bundle.receipt.subject_id != expected_subject_id) {
        result.status = SessionKeyStatus::ReceiptRejected;
        result.errors.emplace_back("session key purpose or subject does not match requested operation");
        return result;
    }
    if (!valid_capability(expected_capability) ||
        !contains_capability(bundle.receipt.capabilities, expected_capability)) {
        result.status = SessionKeyStatus::CapabilityMismatch;
        result.errors.emplace_back("session key does not contain requested capability");
        return result;
    }
    const auto now = system_now_ms();
    if (now >= bundle.receipt.expires_at_unix_ms) {
        result.status = SessionKeyStatus::ReceiptExpired;
        result.errors.emplace_back("session-key receipt has expired");
        return result;
    }
    const auto revoked_receipt = revoked_receipts_.find(bundle.receipt.receipt_id);
    if (revoked_receipt != revoked_receipts_.end() && now >= revoked_receipt->second) {
        result.status = SessionKeyStatus::ReceiptRevoked;
        result.errors.emplace_back("session-key receipt has been revoked");
        return result;
    }
    const auto key = revoked_keys_.find(key_map_id(bundle.receipt.signer_id,
                                                   bundle.receipt.key_id));
    if (key != revoked_keys_.end() && now >= key->second) {
        result.status = SessionKeyStatus::KeyRevoked;
        result.errors.emplace_back("delegated session key has been revoked");
        return result;
    }
    result.use_count = use_count(bundle.receipt.receipt_id);
    if (result.use_count >= bundle.receipt.max_uses) {
        result.status = SessionKeyStatus::UseLimitReached;
        result.errors.emplace_back("session-key receipt use limit reached");
        return result;
    }
    result.status = SessionKeyStatus::Allowed;
    return result;
}

SessionKeyResult SessionKeyLedger::consume(const SessionKeyReceipt& receipt) {
    SessionKeyResult result;
    result.receipt_id = receipt.receipt_id;
    if (!healthy_) {
        result.status = SessionKeyStatus::Corrupt;
        result.errors = errors_;
        return result;
    }
    const auto registration = registrations_.find(receipt.receipt_id);
    if (registration == registrations_.end()) {
        result.status = SessionKeyStatus::NotRegistered;
        result.errors.emplace_back("session-key receipt is not registered");
        return result;
    }
    const auto current = use_count(receipt.receipt_id);
    if (current >= registration->second.max_uses) {
        result.status = SessionKeyStatus::UseLimitReached;
        result.use_count = current;
        result.errors.emplace_back("session-key receipt use limit reached");
        return result;
    }
    const auto next = current + 1U;
    std::ostringstream body;
    body << "U\t" << hex_encode(receipt.receipt_id)
         << '\t' << next
         << '\t' << system_now_ms();
    std::string error;
    if (!append_event(body.str(), &error)) {
        return fail(SessionKeyStatus::StorageError, std::move(error));
    }
    receipt_uses_[receipt.receipt_id] = next;
    result.status = SessionKeyStatus::Allowed;
    result.use_count = next;
    return result;
}

SessionKeyResult SessionKeyLedger::revoke_key(
    std::string_view signer_id,
    std::string_view key_id,
    std::uint64_t revoked_at_unix_ms) {
    if (!valid_token(signer_id) || !valid_token(key_id) || revoked_at_unix_ms == 0U) {
        return fail(SessionKeyStatus::Invalid,
                    "session-key revocation metadata is invalid");
    }
    const auto map_id = key_map_id(signer_id, key_id);
    if (revoked_keys_.contains(map_id)) {
        return fail(SessionKeyStatus::Invalid,
                    "delegated session key is already revoked");
    }
    bool registered = false;
    for (const auto& entry : registrations_) {
        const auto& item = entry.second;
        if (item.signer_id == signer_id && item.key_id == key_id) {
            registered = true;
            break;
        }
    }
    if (!registered) {
        return fail(SessionKeyStatus::NotRegistered,
                    "delegated session key is not registered");
    }
    std::ostringstream body;
    body << "R\t" << hex_encode(signer_id)
         << '\t' << hex_encode(key_id)
         << '\t' << revoked_at_unix_ms;
    std::string error;
    if (!append_event(body.str(), &error)) {
        return fail(SessionKeyStatus::StorageError, std::move(error));
    }
    revoked_keys_[map_id] = revoked_at_unix_ms;
    SessionKeyResult result;
    result.status = SessionKeyStatus::Allowed;
    return result;
}

SessionKeyResult SessionKeyLedger::revoke_receipt(
    std::string_view receipt_id,
    std::uint64_t revoked_at_unix_ms) {
    if (!valid_session_receipt_id(receipt_id) || revoked_at_unix_ms == 0U) {
        return fail(SessionKeyStatus::Invalid,
                    "session-key receipt revocation metadata is invalid");
    }
    if (!registrations_.contains(std::string(receipt_id))) {
        return fail(SessionKeyStatus::NotRegistered,
                    "session-key receipt is not registered");
    }
    if (revoked_receipts_.contains(std::string(receipt_id))) {
        return fail(SessionKeyStatus::Invalid,
                    "session-key receipt is already revoked");
    }
    std::ostringstream body;
    body << "X\t" << hex_encode(receipt_id)
         << '\t' << revoked_at_unix_ms;
    std::string error;
    if (!append_event(body.str(), &error)) {
        return fail(SessionKeyStatus::StorageError, std::move(error));
    }
    revoked_receipts_[std::string(receipt_id)] = revoked_at_unix_ms;
    SessionKeyResult result;
    result.status = SessionKeyStatus::Allowed;
    result.receipt_id = std::string(receipt_id);
    return result;
}

bool SessionKeyLedger::replay(std::vector<std::string>* errors) {
    registrations_.clear();
    receipt_uses_.clear();
    revoked_keys_.clear();
    revoked_receipts_.clear();
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
        errors_.emplace_back("unable to open session-key journal for replay");
        if (errors) *errors = errors_;
        return false;
    }
    std::string line;
    std::size_t line_number = 0U;
    while (std::getline(input, line)) {
        ++line_number;
        if (line.empty()) continue;
        const auto fields = split_tabs(line);
        if (fields.size() < 5U) {
            healthy_ = false;
            errors_.push_back("session-key ledger line " + std::to_string(line_number) + " is malformed");
            break;
        }
        std::size_t sequence = 0U;
        if (!parse_unsigned(fields[0], &sequence) || sequence != sequence_ + 1U) {
            healthy_ = false;
            errors_.push_back("session-key ledger sequence discontinuity at line " + std::to_string(line_number));
            break;
        }
        const std::string expected_previous = last_record_sha256_.empty()
            ? std::string(64U, '0') : last_record_sha256_;
        if (fields[1] != expected_previous) {
            healthy_ = false;
            errors_.push_back("session-key ledger previous-record hash mismatch at line " + std::to_string(line_number));
            break;
        }
        const auto last_tab = line.rfind('\t');
        if (last_tab == std::string::npos || !is_sha256(fields.back()) ||
            sha256(std::string_view(line).substr(0U, last_tab)) != fields.back()) {
            healthy_ = false;
            errors_.push_back("session-key ledger record hash mismatch at line " + std::to_string(line_number));
            break;
        }

        const auto type = fields[2];
        bool event_ok = true;
        if (type == "H" && fields.size() == 13U) {
            auto voucher = hex_decode(fields[3]);
            auto certificate = hex_decode(fields[4]);
            auto receipt = hex_decode(fields[5]);
            auto signer = hex_decode(fields[6]);
            auto key = hex_decode(fields[7]);
            auto algorithm = hex_decode(fields[8]);
            std::uint64_t expires = 0U;
            std::uint32_t max_uses = 0U;
            event_ok = voucher && certificate && receipt && signer && key && algorithm &&
                       valid_authority_receipt_id(*voucher) &&
                       valid_certificate_id(*certificate) &&
                       valid_session_receipt_id(*receipt) &&
                       is_sha256(fields[9]) &&
                       parse_unsigned(fields[10], &expires) && expires != 0U &&
                       parse_unsigned(fields[11], &max_uses) && max_uses != 0U &&
                       !registrations_.contains(*receipt);
            if (event_ok) {
                for (const auto& entry : registrations_) {
                    const auto& existing = entry.second;
                    if (existing.signer_id == *signer && existing.key_id == *key) {
                        event_ok = false;
                        break;
                    }
                }
            }
            if (event_ok) {
                registrations_[*receipt] = Registration{
                    *voucher,
                    *certificate,
                    *receipt,
                    *signer,
                    *key,
                    *algorithm,
                    std::string(fields[9]),
                    expires,
                    max_uses,
                };
            }
        } else if (type == "U" && fields.size() == 7U) {
            auto receipt = hex_decode(fields[3]);
            std::size_t use_index = 0U;
            std::uint64_t at = 0U;
            event_ok = receipt && valid_session_receipt_id(*receipt) &&
                       registrations_.contains(*receipt) &&
                       parse_unsigned(fields[4], &use_index) && use_index != 0U &&
                       parse_unsigned(fields[5], &at) && at != 0U;
            if (event_ok) {
                const auto expected = use_count(*receipt) + 1U;
                event_ok = use_index == expected &&
                           use_index <= registrations_.at(*receipt).max_uses;
                if (event_ok) receipt_uses_[*receipt] = use_index;
            }
        } else if (type == "R" && fields.size() == 7U) {
            auto signer = hex_decode(fields[3]);
            auto key = hex_decode(fields[4]);
            std::uint64_t at = 0U;
            event_ok = signer && key && parse_unsigned(fields[5], &at) && at != 0U &&
                       !revoked_keys_.contains(key_map_id(*signer, *key));
            if (event_ok) revoked_keys_[key_map_id(*signer, *key)] = at;
        } else if (type == "X" && fields.size() == 6U) {
            auto receipt = hex_decode(fields[3]);
            std::uint64_t at = 0U;
            event_ok = receipt && registrations_.contains(*receipt) &&
                       parse_unsigned(fields[4], &at) && at != 0U &&
                       !revoked_receipts_.contains(*receipt);
            if (event_ok) revoked_receipts_[*receipt] = at;
        } else {
            event_ok = false;
        }
        if (!event_ok) {
            healthy_ = false;
            errors_.push_back("session-key ledger event contract failed at line " + std::to_string(line_number));
            break;
        }
        sequence_ = sequence;
        last_record_sha256_ = std::string(fields.back());
    }
    if (errors) *errors = errors_;
    return healthy_;
}

SessionKeyLedgerInspection SessionKeyLedger::inspect() const {
    SessionKeyLedgerInspection inspection;
    inspection.healthy = healthy_;
    inspection.records = sequence_;
    inspection.registered_handoffs = registrations_.size();
    inspection.consumed_receipts = receipt_uses_.size();
    inspection.revoked_keys = revoked_keys_.size();
    inspection.revoked_receipts = revoked_receipts_.size();
    inspection.errors = errors_;
    return inspection;
}

std::size_t SessionKeyLedger::use_count(std::string_view receipt_id) const noexcept {
    const auto it = receipt_uses_.find(std::string(receipt_id));
    return it == receipt_uses_.end() ? 0U : it->second;
}

bool SessionKeyLedger::bundle_registered(std::string_view receipt_id) const noexcept {
    return registrations_.contains(std::string(receipt_id));
}

const std::filesystem::path& SessionKeyLedger::journal_path() const noexcept {
    return journal_path_;
}

AuthoritySessionKeyHandoff::AuthoritySessionKeyHandoff(
    AuthorityDelegator& delegator,
    SessionKeyLedger& session_ledger,
    const AuthorityVerifier& parent_verifier,
    const SessionKeyVerifier& key_verifier) noexcept
    : delegator_(delegator),
      session_ledger_(session_ledger),
      parent_verifier_(parent_verifier),
      key_verifier_(key_verifier) {}

SessionKeyHandoffResult AuthoritySessionKeyHandoff::issue(
    const SessionKeyHandoffRequest& request,
    const AuthoritySigner& parent_signer,
    const SessionKeySigner& child_signer) const {
    SessionKeyHandoffResult result;
    if (request.parent.envelope.schema_version != 3U ||
        request.actor_reference.empty() || request.actor_reference.size() > 256U ||
        request.issued_at_utc.empty() || request.issued_at_utc.size() > 128U ||
        !valid_token(request.voucher_nonce) ||
        !valid_token(request.certificate_nonce) ||
        !valid_token(request.receipt_nonce) ||
        !valid_capabilities(request.capabilities) ||
        request.issued_at_unix_ms == 0U ||
        request.expires_at_unix_ms <= request.issued_at_unix_ms ||
        request.max_uses == 0U) {
        result.status = SessionKeyHandoffStatus::Invalid;
        result.errors.emplace_back("session-key handoff request is invalid");
        return result;
    }
    if (parent_signer.signer_id() != request.parent.envelope.signer_id ||
        parent_signer.algorithm() != request.parent.algorithm) {
        result.status = SessionKeyHandoffStatus::Invalid;
        result.errors.emplace_back("parent signer does not match parent receipt");
        return result;
    }
    if (!valid_token(child_signer.signer_id()) || !valid_token(child_signer.key_id()) ||
        !valid_token(child_signer.algorithm(), 64U) ||
        !is_sha256(child_signer.key_fingerprint_sha256())) {
        result.status = SessionKeyHandoffStatus::Invalid;
        result.errors.emplace_back("child session-key signer metadata is invalid");
        return result;
    }
    if (child_signer.signer_id() == request.parent.envelope.signer_id &&
        child_signer.key_id() == request.parent.envelope.signer_key_id) {
        result.status = SessionKeyHandoffStatus::SameKey;
        result.errors.emplace_back("session-key handoff requires a different child key identity");
        return result;
    }
    if (!key_verifier_.knows_key(child_signer.signer_id(),
                                 child_signer.key_id(),
                                 child_signer.algorithm())) {
        result.status = SessionKeyHandoffStatus::KeyUnknown;
        result.errors.emplace_back("child key is not resolvable by session-key verifier");
        return result;
    }
    const auto verifier_fingerprint = key_verifier_.key_fingerprint_sha256(
        child_signer.signer_id(), child_signer.key_id(), child_signer.algorithm());
    if (!verifier_fingerprint || !is_sha256(*verifier_fingerprint) ||
        *verifier_fingerprint != child_signer.key_fingerprint_sha256()) {
        result.status = SessionKeyHandoffStatus::FingerprintMismatch;
        result.errors.emplace_back("child signer fingerprint does not match verifier key material");
        return result;
    }

    DelegationRequest voucher_request;
    voucher_request.parent = request.parent;
    voucher_request.actor_reference = request.actor_reference;
    voucher_request.issued_at_utc = request.issued_at_utc;
    voucher_request.nonce = request.voucher_nonce;
    voucher_request.scope_path = request.scope_path;
    voucher_request.capabilities = request.capabilities;
    voucher_request.issued_at_unix_ms = request.issued_at_unix_ms;
    voucher_request.expires_at_unix_ms = request.expires_at_unix_ms;
    voucher_request.max_uses = request.max_uses;
    voucher_request.max_delegation_depth = request.max_delegation_depth;
    auto voucher_result = delegator_.delegate(voucher_request, parent_signer);
    if (!voucher_result.ok()) {
        result.status = SessionKeyHandoffStatus::VoucherRejected;
        result.errors = voucher_result.errors;
        return result;
    }

    SessionKeyCertificate certificate;
    certificate.voucher_receipt_id = voucher_result.child->receipt_id;
    certificate.parent_signer_id = voucher_result.child->envelope.signer_id;
    certificate.parent_key_id = voucher_result.child->envelope.signer_key_id;
    certificate.parent_algorithm = voucher_result.child->algorithm;
    certificate.child_signer_id = child_signer.signer_id();
    certificate.child_key_id = child_signer.key_id();
    certificate.child_algorithm = child_signer.algorithm();
    certificate.child_key_fingerprint_sha256 = child_signer.key_fingerprint_sha256();
    certificate.purpose = voucher_result.child->envelope.purpose;
    certificate.subject_id = voucher_result.child->envelope.subject_id;
    certificate.scope_path = voucher_result.child->envelope.scope_path;
    certificate.scope_sha256 = voucher_result.child->envelope.scope_sha256;
    certificate.capabilities = voucher_result.child->envelope.capabilities;
    certificate.issued_at_unix_ms = voucher_result.child->envelope.issued_at_unix_ms;
    certificate.expires_at_unix_ms = voucher_result.child->envelope.expires_at_unix_ms;
    certificate.max_uses = voucher_result.child->envelope.max_uses;
    certificate.nonce = request.certificate_nonce;
    const auto certificate_canonical = canonical_session_key_certificate(certificate);
    certificate.canonical_sha256 = sha256(certificate_canonical);
    auto parent_signature = parent_signer.sign(certificate_canonical);
    if (!parent_signature || parent_signature->empty() || parent_signature->size() > 2048U) {
        result.status = SessionKeyHandoffStatus::CertificateSigningFailed;
        result.errors.emplace_back("parent signer failed to sign session-key certificate");
        return result;
    }
    certificate.parent_signature = *parent_signature;
    certificate.certificate_id = session_key_certificate_id(
        certificate, certificate.parent_signature);

    SessionKeyReceipt receipt;
    receipt.certificate_id = certificate.certificate_id;
    receipt.voucher_receipt_id = certificate.voucher_receipt_id;
    receipt.signer_id = child_signer.signer_id();
    receipt.key_id = child_signer.key_id();
    receipt.algorithm = child_signer.algorithm();
    receipt.key_fingerprint_sha256 = child_signer.key_fingerprint_sha256();
    receipt.purpose = certificate.purpose;
    receipt.subject_id = certificate.subject_id;
    receipt.scope_path = certificate.scope_path;
    receipt.scope_sha256 = certificate.scope_sha256;
    receipt.capabilities = certificate.capabilities;
    receipt.issued_at_unix_ms = certificate.issued_at_unix_ms;
    receipt.expires_at_unix_ms = certificate.expires_at_unix_ms;
    receipt.max_uses = certificate.max_uses;
    receipt.nonce = request.receipt_nonce;
    const auto receipt_canonical = canonical_session_key_receipt(receipt);
    receipt.canonical_sha256 = sha256(receipt_canonical);
    auto child_signature = child_signer.sign(receipt_canonical);
    if (!child_signature || child_signature->empty() || child_signature->size() > 2048U) {
        result.status = SessionKeyHandoffStatus::ReceiptSigningFailed;
        result.errors.emplace_back("child session key failed to sign delegated receipt");
        return result;
    }
    receipt.signature = *child_signature;
    receipt.receipt_id = session_key_receipt_id(receipt, receipt.signature);

    SessionKeyBundle bundle{*voucher_result.child, certificate, receipt};
    std::vector<std::string> certificate_errors;
    std::vector<std::string> receipt_errors;
    if (!verify_certificate(bundle, parent_verifier_, &certificate_errors)) {
        result.status = SessionKeyHandoffStatus::CertificateSigningFailed;
        result.errors = std::move(certificate_errors);
        return result;
    }
    if (!verify_child_receipt(bundle, key_verifier_, &receipt_errors)) {
        result.status = SessionKeyHandoffStatus::ReceiptSigningFailed;
        result.errors = std::move(receipt_errors);
        return result;
    }
    const auto stored = session_ledger_.register_bundle(bundle);
    if (!stored.ok()) {
        result.status = SessionKeyHandoffStatus::StoreRejected;
        result.errors = stored.errors;
        return result;
    }
    result.status = SessionKeyHandoffStatus::Issued;
    result.bundle = std::move(bundle);
    return result;
}

SessionKeyAuthorityGate::SessionKeyAuthorityGate(
    SessionKeyLedger& session_ledger,
    const AuthorityVerifier& parent_verifier,
    const SessionKeyVerifier& key_verifier,
    const AuthorityGate& backing_gate) noexcept
    : session_ledger_(session_ledger),
      parent_verifier_(parent_verifier),
      key_verifier_(key_verifier),
      backing_gate_(backing_gate) {}

SessionKeyResult SessionKeyAuthorityGate::authorize(
    const SessionKeyBundle& bundle,
    AuthorityPurpose purpose,
    std::string_view subject_id,
    std::string_view scope_sha256,
    std::string_view capability) const {
    auto preflight = session_ledger_.preflight(
        bundle,
        parent_verifier_,
        key_verifier_,
        purpose,
        subject_id,
        scope_sha256,
        capability);
    if (!preflight.ok()) return preflight;

    const auto backing = backing_gate_.authorize(
        bundle.voucher,
        purpose,
        subject_id,
        scope_sha256,
        capability);
    if (!backing.ok()) {
        SessionKeyResult result;
        result.status = SessionKeyStatus::VoucherRejected;
        result.backing_gate_status = backing.status;
        result.backing_ledger_status = backing.ledger_status;
        result.receipt_id = bundle.receipt.receipt_id;
        result.use_count = session_ledger_.use_count(bundle.receipt.receipt_id);
        result.errors = backing.errors;
        return result;
    }

    auto consumed = session_ledger_.consume(bundle.receipt);
    consumed.backing_gate_status = backing.status;
    consumed.backing_ledger_status = backing.ledger_status;
    return consumed;
}

std::string_view to_string(SessionKeyStatus status) noexcept {
    switch (status) {
    case SessionKeyStatus::Allowed: return "ALLOWED";
    case SessionKeyStatus::Invalid: return "INVALID";
    case SessionKeyStatus::VoucherRejected: return "VOUCHER_REJECTED";
    case SessionKeyStatus::KeyUnknown: return "KEY_UNKNOWN";
    case SessionKeyStatus::FingerprintMismatch: return "FINGERPRINT_MISMATCH";
    case SessionKeyStatus::CertificateRejected: return "CERTIFICATE_REJECTED";
    case SessionKeyStatus::ReceiptRejected: return "RECEIPT_REJECTED";
    case SessionKeyStatus::NotRegistered: return "NOT_REGISTERED";
    case SessionKeyStatus::KeyRevoked: return "KEY_REVOKED";
    case SessionKeyStatus::ReceiptRevoked: return "RECEIPT_REVOKED";
    case SessionKeyStatus::ReceiptExpired: return "RECEIPT_EXPIRED";
    case SessionKeyStatus::CapabilityMismatch: return "CAPABILITY_MISMATCH";
    case SessionKeyStatus::ScopeMismatch: return "SCOPE_MISMATCH";
    case SessionKeyStatus::UseLimitReached: return "USE_LIMIT_REACHED";
    case SessionKeyStatus::StorageError: return "STORAGE_ERROR";
    case SessionKeyStatus::Corrupt: return "CORRUPT";
    }
    return "INVALID";
}

std::string_view to_string(SessionKeyHandoffStatus status) noexcept {
    switch (status) {
    case SessionKeyHandoffStatus::Issued: return "ISSUED";
    case SessionKeyHandoffStatus::Invalid: return "INVALID";
    case SessionKeyHandoffStatus::SameKey: return "SAME_KEY";
    case SessionKeyHandoffStatus::VoucherRejected: return "VOUCHER_REJECTED";
    case SessionKeyHandoffStatus::KeyUnknown: return "KEY_UNKNOWN";
    case SessionKeyHandoffStatus::FingerprintMismatch: return "FINGERPRINT_MISMATCH";
    case SessionKeyHandoffStatus::CertificateSigningFailed: return "CERTIFICATE_SIGNING_FAILED";
    case SessionKeyHandoffStatus::ReceiptSigningFailed: return "RECEIPT_SIGNING_FAILED";
    case SessionKeyHandoffStatus::StoreRejected: return "STORE_REJECTED";
    }
    return "INVALID";
}

} // namespace guff
