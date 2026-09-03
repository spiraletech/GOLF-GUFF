#include "guff/symbiosis_ledger.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <sstream>
#include <system_error>
#include <utility>

namespace guff {
namespace {

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

bool parse_bool(std::string_view text, bool* out) {
    if (!out) return false;
    if (text == "0") {
        *out = false;
        return true;
    }
    if (text == "1") {
        *out = true;
        return true;
    }
    return false;
}

template <typename Enum>
bool parse_enum(std::string_view text, std::uint8_t max_value, Enum* out) {
    std::uint32_t raw = 0U;
    if (!parse_unsigned(text, &raw) || raw > max_value) return false;
    *out = static_cast<Enum>(raw);
    return true;
}

bool valid_source_id(std::string_view value) {
    constexpr std::string_view prefix = "guff:source:sha256:";
    return value.starts_with(prefix) && is_sha256(value.substr(prefix.size()));
}

std::string expected_source_id(const SymbiosisGrant& grant,
                               const SourceObservation& observation) {
    return "guff:source:sha256:" +
           sha256(grant.source.grant_id + "\n" + observation.locator);
}

std::string promotion_id(std::string_view grant_id,
                         const SourceObservation& observation,
                         std::string_view summary) {
    std::string payload;
    payload.reserve(grant_id.size() + observation.source_id.size() +
                    observation.content_sha256.size() + summary.size() + 4U);
    payload.append(grant_id);
    payload.push_back('\n');
    payload.append(observation.source_id);
    payload.push_back('\n');
    payload.append(observation.content_sha256);
    payload.push_back('\n');
    payload.append(summary);
    return "guff:memory:sha256:" + sha256(payload);
}

std::string grant_line(const SymbiosisGrant& grant) {
    std::ostringstream out;
    out << "G"
        << '\t' << hex_encode(grant.source.grant_id)
        << '\t' << static_cast<unsigned>(grant.source.kind)
        << '\t' << static_cast<unsigned>(grant.source.scope)
        << '\t' << static_cast<unsigned>(grant.source.layer)
        << '\t' << hex_encode(grant.source.root.generic_string())
        << '\t' << hex_encode(grant.source.locator_prefix)
        << '\t' << (grant.source.recursive ? 1 : 0)
        << '\t' << grant.source.max_source_bytes
        << '\t' << grant.source.max_slice_bytes
        << '\t' << (grant.retention.persist_grant ? 1 : 0)
        << '\t' << (grant.retention.persist_observation_stamps ? 1 : 0)
        << '\t' << (grant.retention.allow_memory_promotion ? 1 : 0)
        << '\t' << grant.retention.max_promotion_bytes
        << '\t' << grant.retention.max_observation_stamps
        << '\t' << grant.issued_at_unix_ms
        << '\t' << grant.expires_at_unix_ms;
    return out.str();
}

std::string revoke_line(std::string_view grant_id,
                        std::uint64_t now_unix_ms,
                        std::string_view reason) {
    std::ostringstream out;
    out << "R"
        << '\t' << hex_encode(grant_id)
        << '\t' << now_unix_ms
        << '\t' << hex_encode(reason);
    return out.str();
}

std::string stamp_line(const ObservationStamp& stamp) {
    std::ostringstream out;
    out << "S"
        << '\t' << hex_encode(stamp.grant_id)
        << '\t' << hex_encode(stamp.source_id)
        << '\t' << stamp.content_sha256
        << '\t' << stamp.size_bytes
        << '\t' << static_cast<unsigned>(stamp.layer)
        << '\t' << stamp.observed_at_unix_ms;
    return out.str();
}

std::string promotion_line(const MemoryPromotion& promotion) {
    std::ostringstream out;
    out << "P"
        << '\t' << hex_encode(promotion.promotion_id)
        << '\t' << hex_encode(promotion.grant_id)
        << '\t' << hex_encode(promotion.source_id)
        << '\t' << promotion.content_sha256
        << '\t' << static_cast<unsigned>(promotion.layer)
        << '\t' << hex_encode(promotion.summary)
        << '\t' << promotion.promoted_at_unix_ms;
    return out.str();
}

std::string forget_line(std::string_view promotion_id,
                        std::uint64_t now_unix_ms) {
    std::ostringstream out;
    out << "F"
        << '\t' << hex_encode(promotion_id)
        << '\t' << now_unix_ms;
    return out.str();
}

} // namespace

std::vector<std::string> SymbiosisGrant::validate() const {
    auto errors = source.validate();
    if (issued_at_unix_ms == 0U) {
        errors.emplace_back("issued_at_unix_ms must be non-zero");
    }
    if (expires_at_unix_ms != 0U && expires_at_unix_ms <= issued_at_unix_ms) {
        errors.emplace_back("expires_at_unix_ms must be zero or later than issued_at_unix_ms");
    }
    if (retention.max_promotion_bytes == 0U) {
        errors.emplace_back("max_promotion_bytes must be non-zero");
    }
    if (retention.max_observation_stamps == 0U) {
        errors.emplace_back("max_observation_stamps must be non-zero");
    }
    if (retention.persist_observation_stamps && !retention.persist_grant) {
        errors.emplace_back("persistent observation stamps require persist_grant");
    }
    return errors;
}

bool SymbiosisGrant::expired(std::uint64_t now_unix_ms) const noexcept {
    return expires_at_unix_ms != 0U && now_unix_ms >= expires_at_unix_ms;
}

bool LedgerResult::ok() const noexcept {
    return status == LedgerStatus::Ok;
}

SymbiosisLedger::SymbiosisLedger(std::filesystem::path journal_path)
    : journal_path_(std::move(journal_path)) {}

bool SymbiosisLedger::append_line(std::string_view line, std::string* error) const {
    if (journal_path_.empty()) {
        if (error) *error = "persistent event requested without a journal path";
        return false;
    }

    std::error_code ec;
    const auto parent = journal_path_.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            if (error) *error = "unable to create ledger journal directory";
            return false;
        }
    }

    std::ofstream output(journal_path_, std::ios::binary | std::ios::app);
    if (!output) {
        if (error) *error = "unable to open ledger journal";
        return false;
    }
    output.write(line.data(), static_cast<std::streamsize>(line.size()));
    output.put('\n');
    output.flush();
    if (!output) {
        if (error) *error = "unable to append ledger journal";
        return false;
    }
    if (error) error->clear();
    return true;
}

LedgerResult SymbiosisLedger::create_grant(SymbiosisGrant grant) {
    LedgerResult result;
    result.id = grant.source.grant_id;
    result.errors = grant.validate();
    if (!result.errors.empty()) {
        result.status = LedgerStatus::Invalid;
        return result;
    }
    if (grants_.contains(grant.source.grant_id)) {
        result.status = LedgerStatus::Duplicate;
        result.errors.emplace_back("grant_id already exists");
        return result;
    }

    if (grant.retention.persist_grant) {
        std::string error;
        if (!append_line(grant_line(grant), &error)) {
            result.status = LedgerStatus::StorageError;
            result.errors.push_back(std::move(error));
            return result;
        }
    }

    const auto id = grant.source.grant_id;
    grants_.emplace(id, GrantRecord{std::move(grant), std::nullopt, {}});
    result.status = LedgerStatus::Ok;
    return result;
}

LedgerResult SymbiosisLedger::revoke_grant(std::string_view grant_id,
                                           std::uint64_t now_unix_ms,
                                           std::string reason) {
    LedgerResult result;
    result.id = std::string(grant_id);
    const auto it = grants_.find(result.id);
    if (it == grants_.end()) {
        result.status = LedgerStatus::NotFound;
        result.errors.emplace_back("grant_id not found");
        return result;
    }
    if (it->second.revoked_at_unix_ms) {
        result.status = LedgerStatus::Duplicate;
        result.errors.emplace_back("grant already revoked");
        return result;
    }
    if (now_unix_ms < it->second.grant.issued_at_unix_ms) {
        result.status = LedgerStatus::Invalid;
        result.errors.emplace_back("revocation time precedes grant issue time");
        return result;
    }

    if (it->second.grant.retention.persist_grant) {
        std::string error;
        if (!append_line(revoke_line(grant_id, now_unix_ms, reason), &error)) {
            result.status = LedgerStatus::StorageError;
            result.errors.push_back(std::move(error));
            return result;
        }
    }

    it->second.revoked_at_unix_ms = now_unix_ms;
    it->second.revocation_reason = std::move(reason);
    result.status = LedgerStatus::Ok;
    return result;
}

GrantState SymbiosisLedger::grant_state(std::string_view grant_id,
                                        std::uint64_t now_unix_ms) const noexcept {
    const auto it = grants_.find(std::string(grant_id));
    if (it == grants_.end()) return GrantState::Missing;
    if (now_unix_ms < it->second.grant.issued_at_unix_ms) return GrantState::Pending;
    if (it->second.revoked_at_unix_ms && now_unix_ms >= *it->second.revoked_at_unix_ms) {
        return GrantState::Revoked;
    }
    if (it->second.grant.expired(now_unix_ms)) return GrantState::Expired;
    return GrantState::Active;
}

std::optional<SymbiosisGrant> SymbiosisLedger::find_grant(std::string_view grant_id) const {
    const auto it = grants_.find(std::string(grant_id));
    if (it == grants_.end()) return std::nullopt;
    return it->second.grant;
}

bool SymbiosisLedger::observation_matches_grant(
    const SymbiosisGrant& grant,
    const SourceObservation& observation,
    std::string* error) const {
    if (!valid_source_id(observation.source_id)) {
        if (error) *error = "observation source_id is not a GOLF source identity";
        return false;
    }
    if (!is_sha256(observation.content_sha256)) {
        if (error) *error = "observation content_sha256 is invalid";
        return false;
    }
    if (observation.kind != grant.source.kind) {
        if (error) *error = "observation source kind does not match grant";
        return false;
    }
    if (observation.layer != grant.source.layer) {
        if (error) *error = "observation reality layer does not match grant";
        return false;
    }
    if (observation.source_id != expected_source_id(grant, observation)) {
        if (error) *error = "observation source_id does not bind to grant_id and locator";
        return false;
    }
    if (error) error->clear();
    return true;
}

void SymbiosisLedger::retain_stamp(ObservationStamp stamp, std::size_t max_stamps) {
    stamps_.push_back(std::move(stamp));
    const auto grant_id = stamps_.back().grant_id;

    std::size_t count = 0U;
    for (const auto& entry : stamps_) {
        if (entry.grant_id == grant_id) ++count;
    }

    while (count > max_stamps) {
        const auto it = std::find_if(stamps_.begin(), stamps_.end(),
            [&](const ObservationStamp& entry) { return entry.grant_id == grant_id; });
        if (it == stamps_.end()) break;
        stamps_.erase(it);
        --count;
    }
}

LedgerResult SymbiosisLedger::stamp_observation(
    std::string_view grant_id,
    const SourceObservation& observation,
    std::uint64_t now_unix_ms) {
    LedgerResult result;
    result.id = observation.source_id;

    const auto it = grants_.find(std::string(grant_id));
    if (it == grants_.end()) {
        result.status = LedgerStatus::NotFound;
        result.errors.emplace_back("grant_id not found");
        return result;
    }
    if (grant_state(grant_id, now_unix_ms) != GrantState::Active) {
        result.status = LedgerStatus::Inactive;
        result.errors.emplace_back("grant is not active");
        return result;
    }

    std::string error;
    if (!observation_matches_grant(it->second.grant, observation, &error)) {
        result.status = LedgerStatus::Denied;
        result.errors.push_back(std::move(error));
        return result;
    }

    const auto duplicate = std::any_of(stamps_.begin(), stamps_.end(),
        [&](const ObservationStamp& stamp) {
            return stamp.grant_id == grant_id &&
                   stamp.source_id == observation.source_id &&
                   stamp.content_sha256 == observation.content_sha256;
        });
    if (duplicate) {
        result.status = LedgerStatus::Duplicate;
        result.errors.emplace_back("observation stamp already exists");
        return result;
    }

    ObservationStamp stamp{
        .grant_id = std::string(grant_id),
        .source_id = observation.source_id,
        .content_sha256 = observation.content_sha256,
        .size_bytes = observation.size_bytes,
        .layer = observation.layer,
        .observed_at_unix_ms = now_unix_ms,
    };

    if (it->second.grant.retention.persist_observation_stamps) {
        if (!append_line(stamp_line(stamp), &error)) {
            result.status = LedgerStatus::StorageError;
            result.errors.push_back(std::move(error));
            return result;
        }
    }

    retain_stamp(std::move(stamp), it->second.grant.retention.max_observation_stamps);
    result.status = LedgerStatus::Ok;
    return result;
}

LedgerResult SymbiosisLedger::promote_memory(
    std::string_view grant_id,
    const SourceObservation& observation,
    std::string summary,
    std::uint64_t now_unix_ms) {
    LedgerResult result;
    const auto it = grants_.find(std::string(grant_id));
    if (it == grants_.end()) {
        result.status = LedgerStatus::NotFound;
        result.errors.emplace_back("grant_id not found");
        return result;
    }
    if (grant_state(grant_id, now_unix_ms) != GrantState::Active) {
        result.status = LedgerStatus::Inactive;
        result.errors.emplace_back("grant is not active");
        return result;
    }
    if (!it->second.grant.retention.allow_memory_promotion) {
        result.status = LedgerStatus::Denied;
        result.errors.emplace_back("grant retention policy does not allow memory promotion");
        return result;
    }
    if (summary.empty()) {
        result.status = LedgerStatus::Invalid;
        result.errors.emplace_back("promotion summary is required");
        return result;
    }
    if (summary.size() > it->second.grant.retention.max_promotion_bytes) {
        result.status = LedgerStatus::Invalid;
        result.errors.emplace_back("promotion summary exceeds max_promotion_bytes");
        return result;
    }

    std::string error;
    if (!observation_matches_grant(it->second.grant, observation, &error)) {
        result.status = LedgerStatus::Denied;
        result.errors.push_back(std::move(error));
        return result;
    }

    const bool stamped = std::any_of(stamps_.begin(), stamps_.end(),
        [&](const ObservationStamp& stamp) {
            return stamp.grant_id == grant_id &&
                   stamp.source_id == observation.source_id &&
                   stamp.content_sha256 == observation.content_sha256;
        });
    if (!stamped) {
        result.status = LedgerStatus::Denied;
        result.errors.emplace_back("memory promotion requires a matching observation stamp");
        return result;
    }

    MemoryPromotion promotion{
        .promotion_id = promotion_id(grant_id, observation, summary),
        .grant_id = std::string(grant_id),
        .source_id = observation.source_id,
        .content_sha256 = observation.content_sha256,
        .layer = RealityLayer::Memory,
        .summary = std::move(summary),
        .promoted_at_unix_ms = now_unix_ms,
        .forgotten = false,
    };
    result.id = promotion.promotion_id;

    const auto duplicate = std::any_of(promotions_.begin(), promotions_.end(),
        [&](const MemoryPromotion& existing) {
            return existing.promotion_id == promotion.promotion_id && !existing.forgotten;
        });
    if (duplicate) {
        result.status = LedgerStatus::Duplicate;
        result.errors.emplace_back("memory promotion already exists");
        return result;
    }

    if (it->second.grant.retention.persist_grant) {
        if (!append_line(promotion_line(promotion), &error)) {
            result.status = LedgerStatus::StorageError;
            result.errors.push_back(std::move(error));
            return result;
        }
    }

    promotions_.push_back(std::move(promotion));
    result.status = LedgerStatus::Ok;
    return result;
}

LedgerResult SymbiosisLedger::forget_promotion(std::string_view promotion_id,
                                               std::uint64_t now_unix_ms) {
    LedgerResult result;
    result.id = std::string(promotion_id);
    auto it = std::find_if(promotions_.begin(), promotions_.end(),
        [&](const MemoryPromotion& promotion) {
            return promotion.promotion_id == promotion_id;
        });
    if (it == promotions_.end()) {
        result.status = LedgerStatus::NotFound;
        result.errors.emplace_back("promotion_id not found");
        return result;
    }
    if (it->forgotten) {
        result.status = LedgerStatus::Duplicate;
        result.errors.emplace_back("promotion already forgotten");
        return result;
    }

    const auto grant = grants_.find(it->grant_id);
    if (grant != grants_.end() && grant->second.grant.retention.persist_grant) {
        std::string error;
        if (!append_line(forget_line(promotion_id, now_unix_ms), &error)) {
            result.status = LedgerStatus::StorageError;
            result.errors.push_back(std::move(error));
            return result;
        }
    }

    it->forgotten = true;
    result.status = LedgerStatus::Ok;
    return result;
}

std::vector<ObservationStamp> SymbiosisLedger::observation_stamps(
    std::string_view grant_id) const {
    std::vector<ObservationStamp> result;
    for (const auto& stamp : stamps_) {
        if (stamp.grant_id == grant_id) result.push_back(stamp);
    }
    return result;
}

std::vector<MemoryPromotion> SymbiosisLedger::promotions(bool include_forgotten) const {
    std::vector<MemoryPromotion> result;
    for (const auto& promotion : promotions_) {
        if (include_forgotten || !promotion.forgotten) {
            result.push_back(promotion);
        }
    }
    return result;
}

bool SymbiosisLedger::replay(std::vector<std::string>* errors) {
    if (errors) errors->clear();
    grants_.clear();
    stamps_.clear();
    promotions_.clear();

    if (journal_path_.empty()) return true;

    std::error_code ec;
    if (!std::filesystem::exists(journal_path_, ec)) {
        return !ec;
    }

    std::ifstream input(journal_path_, std::ios::binary);
    if (!input) {
        if (errors) errors->emplace_back("unable to open ledger journal");
        return false;
    }

    bool clean = true;
    std::string line;
    std::size_t line_number = 0U;
    while (std::getline(input, line)) {
        ++line_number;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        const auto fields = split_tabs(line);
        auto fail = [&](std::string detail) {
            clean = false;
            if (errors) {
                errors->push_back("line " + std::to_string(line_number) + ": " + std::move(detail));
            }
        };

        if (fields[0] == "G") {
            if (fields.size() != 17U) {
                fail("malformed grant event");
                continue;
            }
            const auto grant_id = hex_decode(fields[1]);
            const auto root = hex_decode(fields[5]);
            const auto prefix = hex_decode(fields[6]);
            SourceKind kind{};
            GrantScope scope{};
            RealityLayer layer{};
            bool recursive = false;
            bool persist_grant = false;
            bool persist_stamps = false;
            bool allow_promotion = false;
            std::uint64_t max_source = 0U;
            std::size_t max_slice = 0U;
            std::size_t max_promotion = 0U;
            std::size_t max_stamps = 0U;
            std::uint64_t issued = 0U;
            std::uint64_t expires = 0U;

            if (!grant_id || !root || !prefix ||
                !parse_enum(fields[2], static_cast<std::uint8_t>(SourceKind::ToolOutput), &kind) ||
                !parse_enum(fields[3], static_cast<std::uint8_t>(GrantScope::DeviceLocal), &scope) ||
                !parse_enum(fields[4], static_cast<std::uint8_t>(RealityLayer::Representation), &layer) ||
                !parse_bool(fields[7], &recursive) ||
                !parse_unsigned(fields[8], &max_source) ||
                !parse_unsigned(fields[9], &max_slice) ||
                !parse_bool(fields[10], &persist_grant) ||
                !parse_bool(fields[11], &persist_stamps) ||
                !parse_bool(fields[12], &allow_promotion) ||
                !parse_unsigned(fields[13], &max_promotion) ||
                !parse_unsigned(fields[14], &max_stamps) ||
                !parse_unsigned(fields[15], &issued) ||
                !parse_unsigned(fields[16], &expires)) {
                fail("invalid grant event fields");
                continue;
            }

            SymbiosisGrant grant;
            grant.source.grant_id = *grant_id;
            grant.source.kind = kind;
            grant.source.scope = scope;
            grant.source.layer = layer;
            grant.source.root = std::filesystem::path(*root);
            grant.source.locator_prefix = *prefix;
            grant.source.recursive = recursive;
            grant.source.max_source_bytes = max_source;
            grant.source.max_slice_bytes = max_slice;
            grant.retention.persist_grant = persist_grant;
            grant.retention.persist_observation_stamps = persist_stamps;
            grant.retention.allow_memory_promotion = allow_promotion;
            grant.retention.max_promotion_bytes = max_promotion;
            grant.retention.max_observation_stamps = max_stamps;
            grant.issued_at_unix_ms = issued;
            grant.expires_at_unix_ms = expires;

            if (!grant.validate().empty() || !persist_grant || grants_.contains(*grant_id)) {
                fail("invalid or duplicate persisted grant");
                continue;
            }
            grants_.emplace(*grant_id, GrantRecord{std::move(grant), std::nullopt, {}});
            continue;
        }

        if (fields[0] == "R") {
            if (fields.size() != 4U) {
                fail("malformed revoke event");
                continue;
            }
            const auto grant_id = hex_decode(fields[1]);
            const auto reason = hex_decode(fields[3]);
            std::uint64_t when = 0U;
            if (!grant_id || !reason || !parse_unsigned(fields[2], &when)) {
                fail("invalid revoke event fields");
                continue;
            }
            const auto it = grants_.find(*grant_id);
            if (it == grants_.end() || it->second.revoked_at_unix_ms) {
                fail("revoke references missing or already revoked grant");
                continue;
            }
            it->second.revoked_at_unix_ms = when;
            it->second.revocation_reason = *reason;
            continue;
        }

        if (fields[0] == "S") {
            if (fields.size() != 7U) {
                fail("malformed stamp event");
                continue;
            }
            const auto grant_id = hex_decode(fields[1]);
            const auto source_id = hex_decode(fields[2]);
            std::uint64_t size = 0U;
            RealityLayer layer{};
            std::uint64_t observed = 0U;
            if (!grant_id || !source_id || !is_sha256(fields[3]) ||
                !parse_unsigned(fields[4], &size) ||
                !parse_enum(fields[5], static_cast<std::uint8_t>(RealityLayer::Representation), &layer) ||
                !parse_unsigned(fields[6], &observed)) {
                fail("invalid stamp event fields");
                continue;
            }
            const auto grant = grants_.find(*grant_id);
            if (grant == grants_.end() ||
                !grant->second.grant.retention.persist_observation_stamps) {
                fail("stamp references grant without persistent stamp authority");
                continue;
            }
            retain_stamp(ObservationStamp{
                .grant_id = *grant_id,
                .source_id = *source_id,
                .content_sha256 = std::string(fields[3]),
                .size_bytes = size,
                .layer = layer,
                .observed_at_unix_ms = observed,
            }, grant->second.grant.retention.max_observation_stamps);
            continue;
        }

        if (fields[0] == "P") {
            if (fields.size() != 8U) {
                fail("malformed promotion event");
                continue;
            }
            const auto promotion = hex_decode(fields[1]);
            const auto grant_id = hex_decode(fields[2]);
            const auto source_id = hex_decode(fields[3]);
            const auto summary = hex_decode(fields[6]);
            RealityLayer layer{};
            std::uint64_t promoted = 0U;
            if (!promotion || !grant_id || !source_id || !summary ||
                !is_sha256(fields[4]) ||
                !parse_enum(fields[5], static_cast<std::uint8_t>(RealityLayer::Representation), &layer) ||
                !parse_unsigned(fields[7], &promoted)) {
                fail("invalid promotion event fields");
                continue;
            }
            if (!grants_.contains(*grant_id)) {
                fail("promotion references missing grant");
                continue;
            }
            promotions_.push_back(MemoryPromotion{
                .promotion_id = *promotion,
                .grant_id = *grant_id,
                .source_id = *source_id,
                .content_sha256 = std::string(fields[4]),
                .layer = layer,
                .summary = *summary,
                .promoted_at_unix_ms = promoted,
                .forgotten = false,
            });
            continue;
        }

        if (fields[0] == "F") {
            if (fields.size() != 3U) {
                fail("malformed forget event");
                continue;
            }
            const auto promotion_id_value = hex_decode(fields[1]);
            std::uint64_t when = 0U;
            if (!promotion_id_value || !parse_unsigned(fields[2], &when)) {
                fail("invalid forget event fields");
                continue;
            }
            static_cast<void>(when);
            const auto it = std::find_if(promotions_.begin(), promotions_.end(),
                [&](const MemoryPromotion& promotion) {
                    return promotion.promotion_id == *promotion_id_value;
                });
            if (it == promotions_.end() || it->forgotten) {
                fail("forget references missing or already forgotten promotion");
                continue;
            }
            it->forgotten = true;
            continue;
        }

        fail("unknown ledger event type");
    }

    if (!input.eof()) {
        if (errors) errors->emplace_back("ledger journal read failed");
        return false;
    }
    return clean;
}

std::size_t SymbiosisLedger::grant_count() const noexcept { return grants_.size(); }
std::size_t SymbiosisLedger::stamp_count() const noexcept { return stamps_.size(); }
std::size_t SymbiosisLedger::promotion_count() const noexcept { return promotions_.size(); }
const std::filesystem::path& SymbiosisLedger::journal_path() const noexcept { return journal_path_; }

std::string_view to_string(GrantState state) noexcept {
    switch (state) {
    case GrantState::Active: return "ACTIVE";
    case GrantState::Pending: return "PENDING";
    case GrantState::Revoked: return "REVOKED";
    case GrantState::Expired: return "EXPIRED";
    case GrantState::Missing: return "MISSING";
    }
    return "MISSING";
}

std::string_view to_string(LedgerStatus status) noexcept {
    switch (status) {
    case LedgerStatus::Ok: return "OK";
    case LedgerStatus::Duplicate: return "DUPLICATE";
    case LedgerStatus::Invalid: return "INVALID";
    case LedgerStatus::NotFound: return "NOT_FOUND";
    case LedgerStatus::Inactive: return "INACTIVE";
    case LedgerStatus::Denied: return "DENIED";
    case LedgerStatus::StorageError: return "STORAGE_ERROR";
    }
    return "INVALID";
}

} // namespace guff
