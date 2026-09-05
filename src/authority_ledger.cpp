#include "guff/authority_ledger.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <fstream>
#include <limits>
#include <sstream>
#include <system_error>
#include <utility>

namespace guff {
namespace {

constexpr std::string_view kReceiptPrefix = "guff:authority:sha256:";

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
    for (std::size_t i = 0; i < value.size(); i += 2U) {
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

bool valid_receipt_id(std::string_view value) {
    return value.starts_with(kReceiptPrefix) && is_sha256(value.substr(kReceiptPrefix.size()));
}

std::uint64_t system_now_ms() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

bool strict_delegation_attenuation(const AuthorityReceipt& parent,
                                   const AuthorityReceipt& child) {
    return child.envelope.scope_path != parent.envelope.scope_path ||
           child.envelope.capabilities.size() < parent.envelope.capabilities.size() ||
           child.envelope.expires_at_unix_ms < parent.envelope.expires_at_unix_ms ||
           child.envelope.max_uses < parent.envelope.max_uses ||
           child.envelope.max_delegation_depth < parent.envelope.max_delegation_depth;
}

} // namespace

bool AuthorityLedgerResult::ok() const noexcept {
    return status == AuthorityLedgerStatus::Allowed;
}

AuthorityLedger::AuthorityLedger(std::filesystem::path journal_path,
                                 const AuthorityVerifier& verifier,
                                 Clock clock)
    : journal_path_(std::move(journal_path)),
      verifier_(verifier),
      clock_(clock ? std::move(clock) : Clock{system_now_ms}) {
    static_cast<void>(replay());
}

std::string AuthorityLedger::key_map_id(std::string_view signer_id,
                                        std::string_view key_id) const {
    return std::string(signer_id) + "\n" + std::string(key_id);
}

std::uint64_t AuthorityLedger::now_ms() const {
    return clock_ ? clock_() : system_now_ms();
}

bool AuthorityLedger::append_event(std::string_view body, std::string* error) {
    if (!healthy_) {
        if (error) *error = "authority ledger is unhealthy";
        return false;
    }
    if (journal_path_.empty()) {
        if (error) *error = "authority ledger requires a journal path";
        return false;
    }

    std::error_code ec;
    const auto parent = journal_path_.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            if (error) *error = "unable to create authority ledger directory";
            return false;
        }
    }

    const std::size_t next_sequence = sequence_ + 1U;
    const std::string previous = last_record_sha256_.empty() ? std::string(64U, '0') : last_record_sha256_;
    std::ostringstream canonical;
    canonical << next_sequence << '\t' << previous << '\t' << body;
    const auto canonical_text = canonical.str();
    const auto record_sha = sha256(canonical_text);

    std::ofstream output(journal_path_, std::ios::binary | std::ios::app);
    if (!output) {
        if (error) *error = "unable to open authority ledger journal";
        return false;
    }
    output << canonical_text << '\t' << record_sha << '\n';
    output.flush();
    if (!output) {
        if (error) *error = "unable to append authority ledger journal";
        return false;
    }

    sequence_ = next_sequence;
    last_record_sha256_ = record_sha;
    if (error) error->clear();
    return true;
}

std::optional<TrustedSignerKey> AuthorityLedger::find_key(
    std::string_view signer_id,
    std::string_view key_id) const {
    const auto it = keys_.find(key_map_id(signer_id, key_id));
    if (it == keys_.end()) return std::nullopt;
    return it->second.key;
}

bool AuthorityLedger::ancestor_revoked(std::string_view receipt_id,
                                       std::uint64_t now,
                                       std::string* revoked_ancestor) const {
    std::string current(receipt_id);
    for (std::size_t depth = 0U; depth < 9U; ++depth) {
        const auto parent = delegation_parent_.find(current);
        if (parent == delegation_parent_.end()) return false;
        const auto revoked = revoked_receipts_.find(parent->second);
        if (revoked != revoked_receipts_.end() && now >= revoked->second) {
            if (revoked_ancestor) *revoked_ancestor = parent->second;
            return true;
        }
        current = parent->second;
    }
    if (revoked_ancestor) *revoked_ancestor = "delegation-lineage-cycle-or-depth-overflow";
    return true;
}

AuthorityLedgerResult AuthorityLedger::trust_key(TrustedSignerKey key) {
    AuthorityLedgerResult result;
    if (!healthy_) {
        result.status = AuthorityLedgerStatus::Corrupt;
        result.errors = errors_;
        return result;
    }
    if (!valid_token(key.signer_id) || !valid_token(key.key_id) ||
        !valid_token(key.algorithm, 64U) || key.valid_from_unix_ms == 0U ||
        (key.valid_until_unix_ms != 0U && key.valid_until_unix_ms <= key.valid_from_unix_ms) ||
        key.revoked_at_unix_ms != 0U) {
        result.status = AuthorityLedgerStatus::Invalid;
        result.errors.emplace_back("trusted signer key metadata is invalid");
        return result;
    }
    const auto map_id = key_map_id(key.signer_id, key.key_id);
    if (keys_.contains(map_id)) {
        result.status = AuthorityLedgerStatus::Duplicate;
        result.errors.emplace_back("signer key already exists");
        return result;
    }

    std::ostringstream body;
    body << "K\t" << hex_encode(key.signer_id)
         << '\t' << hex_encode(key.key_id)
         << '\t' << hex_encode(key.algorithm)
         << '\t' << key.valid_from_unix_ms
         << '\t' << key.valid_until_unix_ms;
    std::string error;
    if (!append_event(body.str(), &error)) {
        result.status = AuthorityLedgerStatus::StorageError;
        result.errors.push_back(std::move(error));
        return result;
    }
    keys_.emplace(map_id, KeyState{std::move(key)});
    result.status = AuthorityLedgerStatus::Allowed;
    return result;
}

AuthorityLedgerResult AuthorityLedger::retire_key(std::string_view signer_id,
                                                   std::string_view key_id,
                                                   std::uint64_t retired_at_unix_ms) {
    AuthorityLedgerResult result;
    const auto map_id = key_map_id(signer_id, key_id);
    const auto it = keys_.find(map_id);
    if (it == keys_.end()) {
        result.status = AuthorityLedgerStatus::NotFound;
        result.errors.emplace_back("signer key not found");
        return result;
    }
    if (retired_at_unix_ms <= it->second.key.valid_from_unix_ms ||
        (it->second.key.valid_until_unix_ms != 0U &&
         retired_at_unix_ms > it->second.key.valid_until_unix_ms)) {
        result.status = AuthorityLedgerStatus::Invalid;
        result.errors.emplace_back("key retirement time is outside the issuance window");
        return result;
    }

    std::ostringstream body;
    body << "T\t" << hex_encode(signer_id) << '\t' << hex_encode(key_id)
         << '\t' << retired_at_unix_ms;
    std::string error;
    if (!append_event(body.str(), &error)) {
        result.status = AuthorityLedgerStatus::StorageError;
        result.errors.push_back(std::move(error));
        return result;
    }
    it->second.key.valid_until_unix_ms = retired_at_unix_ms;
    result.status = AuthorityLedgerStatus::Allowed;
    return result;
}

AuthorityLedgerResult AuthorityLedger::revoke_key(std::string_view signer_id,
                                                   std::string_view key_id,
                                                   std::uint64_t revoked_at_unix_ms) {
    AuthorityLedgerResult result;
    const auto map_id = key_map_id(signer_id, key_id);
    const auto it = keys_.find(map_id);
    if (it == keys_.end()) {
        result.status = AuthorityLedgerStatus::NotFound;
        result.errors.emplace_back("signer key not found");
        return result;
    }
    if (revoked_at_unix_ms == 0U || it->second.key.revoked_at_unix_ms != 0U) {
        result.status = AuthorityLedgerStatus::Invalid;
        result.errors.emplace_back("key revocation time is invalid or key already revoked");
        return result;
    }

    std::ostringstream body;
    body << "R\t" << hex_encode(signer_id) << '\t' << hex_encode(key_id)
         << '\t' << revoked_at_unix_ms;
    std::string error;
    if (!append_event(body.str(), &error)) {
        result.status = AuthorityLedgerStatus::StorageError;
        result.errors.push_back(std::move(error));
        return result;
    }
    it->second.key.revoked_at_unix_ms = revoked_at_unix_ms;
    result.status = AuthorityLedgerStatus::Allowed;
    return result;
}

AuthorityLedgerResult AuthorityLedger::revoke_receipt(std::string_view receipt_id,
                                                       std::uint64_t revoked_at_unix_ms) {
    AuthorityLedgerResult result;
    result.receipt_id = std::string(receipt_id);
    if (!valid_receipt_id(receipt_id) || revoked_at_unix_ms == 0U) {
        result.status = AuthorityLedgerStatus::Invalid;
        result.errors.emplace_back("receipt revocation request is invalid");
        return result;
    }
    if (revoked_receipts_.contains(result.receipt_id)) {
        result.status = AuthorityLedgerStatus::Duplicate;
        result.errors.emplace_back("receipt already revoked");
        return result;
    }

    std::ostringstream body;
    body << "X\t" << hex_encode(receipt_id) << '\t' << revoked_at_unix_ms;
    std::string error;
    if (!append_event(body.str(), &error)) {
        result.status = AuthorityLedgerStatus::StorageError;
        result.errors.push_back(std::move(error));
        return result;
    }
    revoked_receipts_[result.receipt_id] = revoked_at_unix_ms;
    result.status = AuthorityLedgerStatus::Allowed;
    return result;
}

AuthorityLedgerResult AuthorityLedger::register_delegation(
    const AuthorityReceipt& parent,
    const AuthorityReceipt& child) {
    AuthorityLedgerResult result;
    result.receipt_id = child.receipt_id;
    if (!healthy_) {
        result.status = AuthorityLedgerStatus::Corrupt;
        result.errors = errors_;
        return result;
    }
    if (parent.envelope.schema_version != 3U || child.envelope.schema_version != 3U) {
        result.status = AuthorityLedgerStatus::DelegationRejected;
        result.errors.emplace_back("delegation requires schema v3 parent and child receipts");
        return result;
    }
    const auto parent_verified = verify_authority_receipt(
        parent, verifier_, parent.envelope.purpose, parent.envelope.subject_id);
    const auto child_verified = verify_authority_receipt(
        child, verifier_, child.envelope.purpose, child.envelope.subject_id);
    if (!parent_verified.ok() || !child_verified.ok()) {
        result.status = AuthorityLedgerStatus::DelegationRejected;
        result.errors = !parent_verified.ok() ? parent_verified.errors : child_verified.errors;
        return result;
    }
    if (child.envelope.parent_receipt_id != parent.receipt_id ||
        child.envelope.delegation_depth != parent.envelope.delegation_depth + 1U ||
        parent.envelope.delegation_depth >= parent.envelope.max_delegation_depth ||
        child.envelope.delegation_depth > child.envelope.max_delegation_depth ||
        child.envelope.max_delegation_depth > parent.envelope.max_delegation_depth) {
        result.status = AuthorityLedgerStatus::DelegationRejected;
        result.errors.emplace_back("delegation lineage/depth contract is invalid");
        return result;
    }
    if (parent.envelope.purpose != child.envelope.purpose ||
        parent.envelope.subject_id != child.envelope.subject_id ||
        parent.envelope.signer_id != child.envelope.signer_id ||
        parent.envelope.signer_key_id != child.envelope.signer_key_id ||
        parent.algorithm != child.algorithm) {
        result.status = AuthorityLedgerStatus::DelegationRejected;
        result.errors.emplace_back("delegation cannot change purpose, subject, signer key, or algorithm");
        return result;
    }
    if (!authority_scope_contains(parent.envelope.scope_path, child.envelope.scope_path) ||
        !authority_capabilities_contain(parent.envelope.capabilities, child.envelope.capabilities)) {
        result.status = AuthorityLedgerStatus::DelegationRejected;
        result.errors.emplace_back("delegated scope/capabilities would amplify parent authority");
        return result;
    }
    if (child.envelope.issued_at_unix_ms < parent.envelope.issued_at_unix_ms ||
        child.envelope.expires_at_unix_ms > parent.envelope.expires_at_unix_ms ||
        child.envelope.expires_at_unix_ms <= child.envelope.issued_at_unix_ms ||
        !strict_delegation_attenuation(parent, child)) {
        result.status = AuthorityLedgerStatus::DelegationRejected;
        result.errors.emplace_back("delegation must be strictly attenuated in scope, capability, lifetime, uses, or delegation depth");
        return result;
    }
    if (delegation_parent_.contains(child.receipt_id) || use_count(child.receipt_id) != 0U) {
        result.status = AuthorityLedgerStatus::Duplicate;
        result.errors.emplace_back("delegated child receipt is already registered or consumed");
        return result;
    }
    if (!parent.envelope.parent_receipt_id.empty()) {
        const auto registered_parent = delegation_parent_.find(parent.receipt_id);
        if (registered_parent == delegation_parent_.end() ||
            registered_parent->second != parent.envelope.parent_receipt_id) {
            result.status = AuthorityLedgerStatus::DelegationRejected;
            result.errors.emplace_back("delegated parent is not registered in authority lineage");
            return result;
        }
    }

    const auto key = find_key(parent.envelope.signer_id, parent.envelope.signer_key_id);
    if (!key || key->algorithm != parent.algorithm) {
        result.status = AuthorityLedgerStatus::SignerUnknown;
        result.errors.emplace_back("delegation signer key is not trusted");
        return result;
    }
    const auto now = now_ms();
    if (parent.envelope.issued_at_unix_ms > now || child.envelope.issued_at_unix_ms > now ||
        parent.envelope.issued_at_unix_ms < key->valid_from_unix_ms ||
        (key->valid_until_unix_ms != 0U && parent.envelope.issued_at_unix_ms >= key->valid_until_unix_ms) ||
        (key->valid_until_unix_ms != 0U && child.envelope.issued_at_unix_ms >= key->valid_until_unix_ms) ||
        (key->revoked_at_unix_ms != 0U && now >= key->revoked_at_unix_ms)) {
        result.status = AuthorityLedgerStatus::KeyInactive;
        result.errors.emplace_back("delegation signer key is inactive for parent/child issuance");
        return result;
    }
    if (now >= parent.envelope.expires_at_unix_ms || now >= child.envelope.expires_at_unix_ms) {
        result.status = AuthorityLedgerStatus::ReceiptExpired;
        result.errors.emplace_back("parent or child authority has expired");
        return result;
    }
    if (receipt_revoked(parent.receipt_id) || receipt_revoked(child.receipt_id) ||
        ancestor_revoked(parent.receipt_id, now)) {
        result.status = AuthorityLedgerStatus::ReceiptRevoked;
        result.errors.emplace_back("parent, child, or delegation ancestor has been revoked");
        return result;
    }

    const std::string parent_nonce_key = parent.envelope.signer_id + "\n" +
                                         parent.envelope.signer_key_id + "\n" +
                                         parent.envelope.nonce;
    const std::string child_nonce_key = child.envelope.signer_id + "\n" +
                                        child.envelope.signer_key_id + "\n" +
                                        child.envelope.nonce;
    const auto parent_nonce = nonce_receipts_.find(parent_nonce_key);
    const auto child_nonce = nonce_receipts_.find(child_nonce_key);
    if ((parent_nonce != nonce_receipts_.end() && parent_nonce->second != parent.receipt_id) ||
        (child_nonce != nonce_receipts_.end() && child_nonce->second != child.receipt_id)) {
        result.status = AuthorityLedgerStatus::NonceReplay;
        result.errors.emplace_back("delegation parent or child nonce is bound to a different receipt");
        return result;
    }

    const auto used = use_count(parent.receipt_id);
    const auto reserved = delegated_uses(parent.receipt_id);
    const std::size_t needed = 1U + static_cast<std::size_t>(child.envelope.max_uses);
    if (used > parent.envelope.max_uses || reserved > parent.envelope.max_uses ||
        needed > parent.envelope.max_uses ||
        used + reserved > parent.envelope.max_uses - needed) {
        result.status = AuthorityLedgerStatus::UseLimitReached;
        result.use_count = used;
        result.errors.emplace_back("parent has insufficient uncommitted use budget for delegation");
        return result;
    }

    const std::size_t next_parent_use = used + 1U;
    std::ostringstream body;
    body << "D\t" << hex_encode(parent.receipt_id)
         << '\t' << hex_encode(child.receipt_id)
         << '\t' << hex_encode(parent.envelope.signer_id)
         << '\t' << hex_encode(parent.envelope.signer_key_id)
         << '\t' << hex_encode(parent.envelope.nonce)
         << '\t' << hex_encode(child.envelope.nonce)
         << '\t' << next_parent_use
         << '\t' << child.envelope.max_uses
         << '\t' << now;
    std::string error;
    if (!append_event(body.str(), &error)) {
        result.status = AuthorityLedgerStatus::StorageError;
        result.errors.push_back(std::move(error));
        return result;
    }

    receipt_uses_[parent.receipt_id] = next_parent_use;
    delegated_uses_[parent.receipt_id] = reserved + child.envelope.max_uses;
    nonce_receipts_[parent_nonce_key] = parent.receipt_id;
    nonce_receipts_[child_nonce_key] = child.receipt_id;
    delegation_parent_[child.receipt_id] = parent.receipt_id;
    result.status = AuthorityLedgerStatus::Allowed;
    result.use_count = next_parent_use;
    return result;
}

AuthorityLedgerResult AuthorityLedger::authorize_and_consume(
    const AuthorityReceipt& receipt,
    AuthorityPurpose expected_purpose,
    std::string_view expected_subject_id,
    std::string_view expected_scope_sha256) {
    AuthorityLedgerResult result;
    result.receipt_id = receipt.receipt_id;
    if (!healthy_) {
        result.status = AuthorityLedgerStatus::Corrupt;
        result.errors = errors_;
        return result;
    }

    const auto verified = verify_authority_receipt(
        receipt, verifier_, expected_purpose, expected_subject_id);
    if (!verified.ok()) {
        result.status = verified.status == AuthorityReceiptStatus::SignerUnknown
            ? AuthorityLedgerStatus::SignerUnknown
            : AuthorityLedgerStatus::Invalid;
        result.errors = verified.errors;
        return result;
    }
    if (!is_sha256(expected_scope_sha256) || receipt.envelope.scope_sha256 != expected_scope_sha256) {
        result.status = AuthorityLedgerStatus::Invalid;
        result.errors.emplace_back("authority receipt scope does not match requested operation");
        return result;
    }
    if (receipt.envelope.schema_version != 2U && receipt.envelope.schema_version != 3U) {
        result.status = AuthorityLedgerStatus::Invalid;
        result.errors.emplace_back("privileged authority consumption requires receipt schema v2 or v3");
        return result;
    }
    if (receipt.envelope.schema_version == 3U && !receipt.envelope.parent_receipt_id.empty()) {
        const auto lineage = delegation_parent_.find(receipt.receipt_id);
        if (lineage == delegation_parent_.end() || lineage->second != receipt.envelope.parent_receipt_id) {
            result.status = AuthorityLedgerStatus::DelegationRejected;
            result.errors.emplace_back("delegated receipt is not registered in authority lineage");
            return result;
        }
    }

    const auto key = find_key(receipt.envelope.signer_id, receipt.envelope.signer_key_id);
    if (!key || key->algorithm != receipt.algorithm) {
        result.status = AuthorityLedgerStatus::SignerUnknown;
        result.errors.emplace_back("receipt signer key is not trusted by the authority ledger");
        return result;
    }

    const auto now = now_ms();
    if (receipt.envelope.issued_at_unix_ms > now) {
        result.status = AuthorityLedgerStatus::KeyInactive;
        result.errors.emplace_back("authority receipt is not valid yet");
        return result;
    }
    if (receipt.envelope.issued_at_unix_ms < key->valid_from_unix_ms ||
        (key->valid_until_unix_ms != 0U &&
         receipt.envelope.issued_at_unix_ms >= key->valid_until_unix_ms)) {
        result.status = AuthorityLedgerStatus::KeyInactive;
        result.errors.emplace_back("receipt was issued outside the signer key issuance window");
        return result;
    }
    if (key->revoked_at_unix_ms != 0U && now >= key->revoked_at_unix_ms) {
        result.status = AuthorityLedgerStatus::KeyInactive;
        result.errors.emplace_back("receipt signer key has been revoked");
        return result;
    }
    if (now >= receipt.envelope.expires_at_unix_ms) {
        result.status = AuthorityLedgerStatus::ReceiptExpired;
        result.errors.emplace_back("authority receipt has expired");
        return result;
    }
    const auto revoked = revoked_receipts_.find(receipt.receipt_id);
    if (revoked != revoked_receipts_.end() && now >= revoked->second) {
        result.status = AuthorityLedgerStatus::ReceiptRevoked;
        result.errors.emplace_back("authority receipt has been revoked");
        return result;
    }
    std::string revoked_ancestor;
    if (ancestor_revoked(receipt.receipt_id, now, &revoked_ancestor)) {
        result.status = AuthorityLedgerStatus::ReceiptRevoked;
        result.errors.emplace_back("delegation ancestor has been revoked: " + revoked_ancestor);
        return result;
    }

    const std::string nonce_key = receipt.envelope.signer_id + "\n" +
                                  receipt.envelope.signer_key_id + "\n" +
                                  receipt.envelope.nonce;
    const auto nonce = nonce_receipts_.find(nonce_key);
    if (nonce != nonce_receipts_.end() && nonce->second != receipt.receipt_id) {
        result.status = AuthorityLedgerStatus::NonceReplay;
        result.errors.emplace_back("signer key nonce is already bound to a different receipt");
        return result;
    }

    const auto current_uses = use_count(receipt.receipt_id);
    const auto reserved = delegated_uses(receipt.receipt_id);
    if (current_uses > receipt.envelope.max_uses ||
        reserved > receipt.envelope.max_uses ||
        current_uses + reserved >= receipt.envelope.max_uses) {
        result.status = AuthorityLedgerStatus::UseLimitReached;
        result.use_count = current_uses;
        result.errors.emplace_back("authority receipt uncommitted use limit reached");
        return result;
    }

    const std::size_t next_use = current_uses + 1U;
    std::ostringstream body;
    body << "U\t" << hex_encode(receipt.receipt_id)
         << '\t' << hex_encode(receipt.envelope.signer_id)
         << '\t' << hex_encode(receipt.envelope.signer_key_id)
         << '\t' << hex_encode(receipt.envelope.nonce)
         << '\t' << next_use
         << '\t' << now;
    std::string error;
    if (!append_event(body.str(), &error)) {
        result.status = AuthorityLedgerStatus::StorageError;
        result.errors.push_back(std::move(error));
        return result;
    }

    nonce_receipts_[nonce_key] = receipt.receipt_id;
    receipt_uses_[receipt.receipt_id] = next_use;
    result.status = AuthorityLedgerStatus::Allowed;
    result.use_count = next_use;
    return result;
}

bool AuthorityLedger::replay(std::vector<std::string>* errors) {
    keys_.clear();
    receipt_uses_.clear();
    delegated_uses_.clear();
    revoked_receipts_.clear();
    nonce_receipts_.clear();
    delegation_parent_.clear();
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
        errors_.emplace_back("unable to open authority ledger journal for replay");
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
            errors_.push_back("authority ledger line " + std::to_string(line_number) + " is malformed");
            healthy_ = false;
            break;
        }
        std::size_t sequence = 0U;
        if (!parse_unsigned(fields[0], &sequence) || sequence != sequence_ + 1U) {
            errors_.push_back("authority ledger sequence discontinuity at line " + std::to_string(line_number));
            healthy_ = false;
            break;
        }
        const std::string expected_previous = last_record_sha256_.empty() ? std::string(64U, '0') : last_record_sha256_;
        if (fields[1] != expected_previous) {
            errors_.push_back("authority ledger previous-record hash mismatch at line " + std::to_string(line_number));
            healthy_ = false;
            break;
        }
        const auto last_tab = line.rfind('\t');
        if (last_tab == std::string::npos || !is_sha256(fields.back()) ||
            sha256(std::string_view(line).substr(0U, last_tab)) != fields.back()) {
            errors_.push_back("authority ledger record hash mismatch at line " + std::to_string(line_number));
            healthy_ = false;
            break;
        }

        const auto type = fields[2];
        bool event_ok = true;
        if (type == "K" && fields.size() == 9U) {
            auto signer = hex_decode(fields[3]);
            auto key_id = hex_decode(fields[4]);
            auto algorithm = hex_decode(fields[5]);
            std::uint64_t valid_from = 0U;
            std::uint64_t valid_until = 0U;
            event_ok = signer && key_id && algorithm &&
                       parse_unsigned(fields[6], &valid_from) &&
                       parse_unsigned(fields[7], &valid_until) && valid_from != 0U;
            if (event_ok) {
                const auto id = key_map_id(*signer, *key_id);
                event_ok = !keys_.contains(id);
                if (event_ok) {
                    keys_.emplace(id, KeyState{TrustedSignerKey{
                        *signer, *key_id, *algorithm, valid_from, valid_until, 0U}});
                }
            }
        } else if ((type == "T" || type == "R") && fields.size() == 7U) {
            auto signer = hex_decode(fields[3]);
            auto key_id = hex_decode(fields[4]);
            std::uint64_t at = 0U;
            event_ok = signer && key_id && parse_unsigned(fields[5], &at) && at != 0U;
            if (event_ok) {
                const auto it = keys_.find(key_map_id(*signer, *key_id));
                event_ok = it != keys_.end();
                if (event_ok) {
                    if (type == "T") it->second.key.valid_until_unix_ms = at;
                    else it->second.key.revoked_at_unix_ms = at;
                }
            }
        } else if (type == "X" && fields.size() == 6U) {
            auto receipt_id = hex_decode(fields[3]);
            std::uint64_t at = 0U;
            event_ok = receipt_id && valid_receipt_id(*receipt_id) &&
                       parse_unsigned(fields[4], &at) && at != 0U &&
                       !revoked_receipts_.contains(*receipt_id);
            if (event_ok) revoked_receipts_[*receipt_id] = at;
        } else if (type == "U" && fields.size() == 10U) {
            auto receipt_id = hex_decode(fields[3]);
            auto signer = hex_decode(fields[4]);
            auto key_id = hex_decode(fields[5]);
            auto nonce = hex_decode(fields[6]);
            std::size_t use_index = 0U;
            std::uint64_t at = 0U;
            event_ok = receipt_id && signer && key_id && nonce &&
                       valid_receipt_id(*receipt_id) &&
                       parse_unsigned(fields[7], &use_index) && use_index != 0U &&
                       parse_unsigned(fields[8], &at) && at != 0U;
            if (event_ok) {
                const auto expected_use = use_count(*receipt_id) + 1U;
                const std::string nonce_key = *signer + "\n" + *key_id + "\n" + *nonce;
                const auto existing = nonce_receipts_.find(nonce_key);
                event_ok = use_index == expected_use &&
                           (existing == nonce_receipts_.end() || existing->second == *receipt_id);
                if (event_ok) {
                    receipt_uses_[*receipt_id] = use_index;
                    nonce_receipts_[nonce_key] = *receipt_id;
                }
            }
        } else if (type == "D" && fields.size() == 13U) {
            auto parent_id = hex_decode(fields[3]);
            auto child_id = hex_decode(fields[4]);
            auto signer = hex_decode(fields[5]);
            auto key_id = hex_decode(fields[6]);
            auto parent_nonce = hex_decode(fields[7]);
            auto child_nonce = hex_decode(fields[8]);
            std::size_t parent_use = 0U;
            std::size_t reserved_uses = 0U;
            std::uint64_t at = 0U;
            event_ok = parent_id && child_id && signer && key_id && parent_nonce && child_nonce &&
                       valid_receipt_id(*parent_id) && valid_receipt_id(*child_id) &&
                       parse_unsigned(fields[9], &parent_use) && parent_use != 0U &&
                       parse_unsigned(fields[10], &reserved_uses) && reserved_uses != 0U &&
                       parse_unsigned(fields[11], &at) && at != 0U &&
                       !delegation_parent_.contains(*child_id);
            if (event_ok) {
                const auto expected_use = use_count(*parent_id) + 1U;
                const std::string parent_nonce_key = *signer + "\n" + *key_id + "\n" + *parent_nonce;
                const std::string child_nonce_key = *signer + "\n" + *key_id + "\n" + *child_nonce;
                const auto existing_parent_nonce = nonce_receipts_.find(parent_nonce_key);
                const auto existing_child_nonce = nonce_receipts_.find(child_nonce_key);
                event_ok = parent_use == expected_use &&
                           (existing_parent_nonce == nonce_receipts_.end() ||
                            existing_parent_nonce->second == *parent_id) &&
                           (existing_child_nonce == nonce_receipts_.end() ||
                            existing_child_nonce->second == *child_id) &&
                           delegated_uses(*parent_id) <=
                               std::numeric_limits<std::size_t>::max() - reserved_uses;
                if (event_ok) {
                    receipt_uses_[*parent_id] = parent_use;
                    delegated_uses_[*parent_id] = delegated_uses(*parent_id) + reserved_uses;
                    nonce_receipts_[parent_nonce_key] = *parent_id;
                    nonce_receipts_[child_nonce_key] = *child_id;
                    delegation_parent_[*child_id] = *parent_id;
                }
            }
        } else {
            event_ok = false;
        }

        if (!event_ok) {
            errors_.push_back("authority ledger event contract failed at line " + std::to_string(line_number));
            healthy_ = false;
            break;
        }
        sequence_ = sequence;
        last_record_sha256_ = std::string(fields.back());
    }

    if (errors) *errors = errors_;
    return healthy_;
}

AuthorityLedgerInspection AuthorityLedger::inspect() const {
    AuthorityLedgerInspection inspection;
    inspection.healthy = healthy_;
    inspection.records = sequence_;
    inspection.trusted_keys = keys_.size();
    inspection.consumed_receipts = receipt_uses_.size();
    inspection.revoked_receipts = revoked_receipts_.size();
    inspection.delegated_receipts = delegation_parent_.size();
    inspection.errors = errors_;
    return inspection;
}

std::size_t AuthorityLedger::use_count(std::string_view receipt_id) const noexcept {
    const auto it = receipt_uses_.find(std::string(receipt_id));
    return it == receipt_uses_.end() ? 0U : it->second;
}

std::size_t AuthorityLedger::delegated_uses(std::string_view receipt_id) const noexcept {
    const auto it = delegated_uses_.find(std::string(receipt_id));
    return it == delegated_uses_.end() ? 0U : it->second;
}

bool AuthorityLedger::receipt_revoked(std::string_view receipt_id) const noexcept {
    return revoked_receipts_.contains(std::string(receipt_id));
}

bool AuthorityLedger::delegation_registered(std::string_view child_receipt_id) const noexcept {
    return delegation_parent_.contains(std::string(child_receipt_id));
}

std::optional<std::string> AuthorityLedger::delegation_parent(
    std::string_view child_receipt_id) const {
    const auto it = delegation_parent_.find(std::string(child_receipt_id));
    if (it == delegation_parent_.end()) return std::nullopt;
    return it->second;
}

const std::filesystem::path& AuthorityLedger::journal_path() const noexcept {
    return journal_path_;
}

std::string_view to_string(AuthorityLedgerStatus status) noexcept {
    switch (status) {
    case AuthorityLedgerStatus::Allowed: return "ALLOWED";
    case AuthorityLedgerStatus::Invalid: return "INVALID";
    case AuthorityLedgerStatus::Duplicate: return "DUPLICATE";
    case AuthorityLedgerStatus::NotFound: return "NOT_FOUND";
    case AuthorityLedgerStatus::SignerUnknown: return "SIGNER_UNKNOWN";
    case AuthorityLedgerStatus::KeyInactive: return "KEY_INACTIVE";
    case AuthorityLedgerStatus::ReceiptExpired: return "RECEIPT_EXPIRED";
    case AuthorityLedgerStatus::ReceiptRevoked: return "RECEIPT_REVOKED";
    case AuthorityLedgerStatus::NonceReplay: return "NONCE_REPLAY";
    case AuthorityLedgerStatus::UseLimitReached: return "USE_LIMIT_REACHED";
    case AuthorityLedgerStatus::DelegationRejected: return "DELEGATION_REJECTED";
    case AuthorityLedgerStatus::StorageError: return "STORAGE_ERROR";
    case AuthorityLedgerStatus::Corrupt: return "CORRUPT";
    }
    return "INVALID";
}

} // namespace guff
