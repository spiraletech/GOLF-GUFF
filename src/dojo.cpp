#include "guff/dojo.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <system_error>
#include <utility>

namespace guff {
namespace {

constexpr std::size_t kMaxSummaryBytes = 2048U;
constexpr std::size_t kMaxTags = 32U;
constexpr std::size_t kMaxTagBytes = 128U;
constexpr std::size_t kMaxReplay = 4096U;

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
    for (std::size_t i = 0; i < input.size(); i += 2U) {
        const auto high = nibble(input[i]);
        const auto low = nibble(input[i + 1U]);
        if (high < 0 || low < 0) return std::nullopt;
        out.push_back(static_cast<char>((high << 4) | low));
    }
    return out;
}

std::vector<std::string_view> split_tabs(std::string_view line) {
    std::vector<std::string_view> fields;
    std::size_t start = 0U;
    while (start <= line.size()) {
        const auto next = line.find('\t', start);
        if (next == std::string_view::npos) {
            fields.push_back(line.substr(start));
            break;
        }
        fields.push_back(line.substr(start, next - start));
        start = next + 1U;
    }
    return fields;
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

bool valid_prefixed_hash(std::string_view value, std::string_view prefix) {
    if (!value.starts_with(prefix)) return false;
    return is_sha256(value.substr(prefix.size()));
}

std::string canonical_tags(std::vector<std::string> tags) {
    std::sort(tags.begin(), tags.end());
    std::ostringstream out;
    for (const auto& tag : tags) out << tag.size() << ':' << tag << ';';
    return out.str();
}

std::string canonical_payload(const DojoEpisode& e) {
    std::ostringstream out;
    out << e.schema_version << '\n'
        << static_cast<unsigned>(e.task) << '\n'
        << e.profile_name << '\n'
        << e.hardware_id << '\n'
        << e.model_id << '\n'
        << e.route_status << '\n'
        << static_cast<unsigned>(e.outcome) << '\n'
        << static_cast<unsigned>(e.zenkai_stop_reason) << '\n'
        << (e.verified ? 1 : 0) << '\n'
        << e.attempts << '\n'
        << e.evidence_items << '\n'
        << e.tool_events << '\n'
        << e.final_state_sha256 << '\n'
        << e.route_trace_sha256 << '\n'
        << e.outcome_sha256 << '\n'
        << e.summary << '\n'
        << e.recorded_at_utc << '\n'
        << canonical_tags(e.tags);
    return out.str();
}

std::string encode_tags(const std::vector<std::string>& tags) {
    std::ostringstream out;
    for (std::size_t i = 0; i < tags.size(); ++i) {
        if (i) out << ',';
        out << hex_encode(tags[i]);
    }
    return out.str();
}

std::optional<std::vector<std::string>> decode_tags(std::string_view field) {
    std::vector<std::string> tags;
    if (field.empty()) return tags;
    std::size_t start = 0U;
    while (start <= field.size()) {
        const auto next = field.find(',', start);
        const auto part = next == std::string_view::npos
            ? field.substr(start)
            : field.substr(start, next - start);
        auto decoded = hex_decode(part);
        if (!decoded) return std::nullopt;
        tags.push_back(std::move(*decoded));
        if (next == std::string_view::npos) break;
        start = next + 1U;
    }
    return tags;
}

std::string serialize(const DojoEpisode& e) {
    std::ostringstream out;
    out << "D\t"
        << e.schema_version << '\t'
        << hex_encode(e.episode_id) << '\t'
        << static_cast<unsigned>(e.task) << '\t'
        << hex_encode(e.profile_name) << '\t'
        << hex_encode(e.hardware_id) << '\t'
        << hex_encode(e.model_id) << '\t'
        << hex_encode(e.route_status) << '\t'
        << static_cast<unsigned>(e.outcome) << '\t'
        << static_cast<unsigned>(e.zenkai_stop_reason) << '\t'
        << (e.verified ? 1 : 0) << '\t'
        << e.attempts << '\t'
        << e.evidence_items << '\t'
        << e.tool_events << '\t'
        << e.final_state_sha256 << '\t'
        << e.route_trace_sha256 << '\t'
        << e.outcome_sha256 << '\t'
        << hex_encode(e.summary) << '\t'
        << hex_encode(e.recorded_at_utc) << '\t'
        << encode_tags(e.tags);
    return out.str();
}

std::optional<DojoEpisode> deserialize(std::string_view line, std::string* error) {
    const auto fields = split_tabs(line);
    if (fields.size() != 20U || fields[0] != "D") {
        if (error) *error = "invalid DOJO record field count or type";
        return std::nullopt;
    }

    DojoEpisode e;
    unsigned task = 0U, outcome = 0U, stop = 0U, verified = 0U;
    if (!parse_unsigned(fields[1], &e.schema_version) ||
        !parse_unsigned(fields[3], &task) ||
        !parse_unsigned(fields[8], &outcome) ||
        !parse_unsigned(fields[9], &stop) ||
        !parse_unsigned(fields[10], &verified) ||
        !parse_unsigned(fields[11], &e.attempts) ||
        !parse_unsigned(fields[12], &e.evidence_items) ||
        !parse_unsigned(fields[13], &e.tool_events)) {
        if (error) *error = "invalid numeric DOJO field";
        return std::nullopt;
    }
    if (task > static_cast<unsigned>(TaskClass::WorldSimulation) ||
        outcome > static_cast<unsigned>(DojoOutcome::Aborted) ||
        stop > static_cast<unsigned>(ZenkaiStopReason::EvidenceBudget) ||
        verified > 1U) {
        if (error) *error = "DOJO enum field out of range";
        return std::nullopt;
    }

    auto episode_id = hex_decode(fields[2]);
    auto profile = hex_decode(fields[4]);
    auto hardware = hex_decode(fields[5]);
    auto model = hex_decode(fields[6]);
    auto route = hex_decode(fields[7]);
    auto summary = hex_decode(fields[17]);
    auto recorded = hex_decode(fields[18]);
    auto tags = decode_tags(fields[19]);
    if (!episode_id || !profile || !hardware || !model || !route || !summary || !recorded || !tags) {
        if (error) *error = "invalid hex-encoded DOJO field";
        return std::nullopt;
    }

    e.episode_id = std::move(*episode_id);
    e.task = static_cast<TaskClass>(task);
    e.profile_name = std::move(*profile);
    e.hardware_id = std::move(*hardware);
    e.model_id = std::move(*model);
    e.route_status = std::move(*route);
    e.outcome = static_cast<DojoOutcome>(outcome);
    e.zenkai_stop_reason = static_cast<ZenkaiStopReason>(stop);
    e.verified = verified != 0U;
    e.final_state_sha256 = std::string(fields[14]);
    e.route_trace_sha256 = std::string(fields[15]);
    e.outcome_sha256 = std::string(fields[16]);
    e.summary = std::move(*summary);
    e.recorded_at_utc = std::move(*recorded);
    e.tags = std::move(*tags);

    const auto errors = e.validate();
    if (!errors.empty()) {
        if (error) *error = "DOJO record failed validation: " + errors.front();
        return std::nullopt;
    }
    if (e.episode_id != e.immutable_id()) {
        if (error) *error = "DOJO episode identity mismatch";
        return std::nullopt;
    }
    return e;
}

bool matches(const DojoEpisode& e, const DojoQuery& q) {
    if (q.task && e.task != *q.task) return false;
    if (q.outcome && e.outcome != *q.outcome) return false;
    if (!q.profile_name.empty() && e.profile_name != q.profile_name) return false;
    if (!q.model_id.empty() && e.model_id != q.model_id) return false;
    if (q.verified_only && !e.verified) return false;
    return true;
}

std::string json_escape(std::string_view value) {
    std::ostringstream out;
    for (const auto ch : value) {
        switch (ch) {
        case '\\': out << "\\\\"; break;
        case '"': out << "\\\""; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20U) {
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<unsigned>(static_cast<unsigned char>(ch))
                    << std::dec << std::setfill(' ');
            } else {
                out << ch;
            }
        }
    }
    return out.str();
}

std::string to_json(const DojoEpisode& e) {
    std::ostringstream out;
    out << "{\"episode_id\":\"" << json_escape(e.episode_id)
        << "\",\"task\":" << static_cast<unsigned>(e.task)
        << ",\"profile\":\"" << json_escape(e.profile_name)
        << "\",\"hardware_id\":\"" << json_escape(e.hardware_id)
        << "\",\"model_id\":\"" << json_escape(e.model_id)
        << "\",\"route_status\":\"" << json_escape(e.route_status)
        << "\",\"outcome\":\"" << to_string(e.outcome)
        << "\",\"zenkai_stop\":" << static_cast<unsigned>(e.zenkai_stop_reason)
        << ",\"verified\":" << (e.verified ? "true" : "false")
        << ",\"attempts\":" << e.attempts
        << ",\"evidence_items\":" << e.evidence_items
        << ",\"tool_events\":" << e.tool_events
        << ",\"final_state_sha256\":\"" << e.final_state_sha256
        << "\",\"route_trace_sha256\":\"" << e.route_trace_sha256
        << "\",\"outcome_sha256\":\"" << e.outcome_sha256
        << "\",\"summary\":\"" << json_escape(e.summary)
        << "\",\"recorded_at_utc\":\"" << json_escape(e.recorded_at_utc)
        << "\",\"tags\":[";
    for (std::size_t i = 0; i < e.tags.size(); ++i) {
        if (i) out << ',';
        out << '"' << json_escape(e.tags[i]) << '"';
    }
    out << "]}";
    return out.str();
}

DojoOutcome outcome_from(const ZenkaiResult& zenkai) noexcept {
    if (zenkai.verified && zenkai.stop_reason == ZenkaiStopReason::Verified) return DojoOutcome::Success;
    switch (zenkai.stop_reason) {
    case ZenkaiStopReason::RetryNotAuthorized:
    case ZenkaiStopReason::AttemptBudget:
    case ZenkaiStopReason::ToolBudget:
    case ZenkaiStopReason::EvidenceBudget:
        return DojoOutcome::Aborted;
    default:
        return DojoOutcome::Failure;
    }
}

} // namespace

std::vector<std::string> DojoEpisode::validate() const {
    std::vector<std::string> errors;
    if (schema_version != 1U) errors.emplace_back("unsupported schema_version");
    if (profile_name.empty()) errors.emplace_back("profile_name is required");
    if (profile_name.size() > 256U) errors.emplace_back("profile_name exceeds 256 bytes");
    if (!valid_prefixed_hash(hardware_id, "guff:hardware:sha256:"))
        errors.emplace_back("hardware_id must be a canonical GOLF hardware identity");
    if (!model_id.empty() && !valid_prefixed_hash(model_id, "guff:model:sha256:"))
        errors.emplace_back("model_id must be empty or a canonical GOLF model identity");
    if (route_status.empty()) errors.emplace_back("route_status is required");
    if (route_status.size() > 128U) errors.emplace_back("route_status exceeds 128 bytes");
    if (!is_sha256(final_state_sha256)) errors.emplace_back("final_state_sha256 must be SHA-256");
    if (!is_sha256(route_trace_sha256)) errors.emplace_back("route_trace_sha256 must be SHA-256");
    if (!is_sha256(outcome_sha256)) errors.emplace_back("outcome_sha256 must be SHA-256");
    if (summary.empty()) errors.emplace_back("summary is required");
    if (summary.size() > kMaxSummaryBytes) errors.emplace_back("summary exceeds 2048 bytes");
    if (recorded_at_utc.empty()) errors.emplace_back("recorded_at_utc is required");
    if (tags.size() > kMaxTags) errors.emplace_back("too many tags");
    for (const auto& tag : tags) {
        if (tag.empty()) errors.emplace_back("tags must not be empty");
        if (tag.size() > kMaxTagBytes) errors.emplace_back("tag exceeds 128 bytes");
    }
    if (!episode_id.empty() && episode_id != immutable_id()) errors.emplace_back("episode_id does not match canonical identity");
    return errors;
}

std::string DojoEpisode::immutable_id() const {
    return "guff:dojo:sha256:" + sha256(canonical_payload(*this));
}

bool DojoStoreResult::ok() const noexcept {
    return status == DojoStoreStatus::Ok;
}

DojoStore::DojoStore(std::filesystem::path path) : path_(std::move(path)) {}

DojoStoreResult DojoStore::append(DojoEpisode episode) {
    DojoStoreResult result;
    result.errors = episode.validate();
    if (!result.errors.empty()) {
        result.status = DojoStoreStatus::Invalid;
        return result;
    }

    const auto expected = episode.immutable_id();
    if (episode.episode_id.empty()) episode.episode_id = expected;
    if (episode.episode_id != expected) {
        result.status = DojoStoreStatus::Invalid;
        result.errors.emplace_back("episode_id does not match canonical identity");
        return result;
    }
    result.episode_id = episode.episode_id;

    if (std::filesystem::exists(path_)) {
        std::ifstream input(path_, std::ios::binary);
        if (!input) {
            result.status = DojoStoreStatus::StorageError;
            result.errors.emplace_back("unable to open DOJO store for duplicate scan");
            return result;
        }
        std::string line;
        const auto encoded_id = hex_encode(episode.episode_id);
        while (std::getline(input, line)) {
            if (line.find(encoded_id) != std::string::npos) {
                std::string parse_error;
                auto existing = deserialize(line, &parse_error);
                if (existing && existing->episode_id == episode.episode_id) {
                    result.status = DojoStoreStatus::Duplicate;
                    return result;
                }
            }
        }
    }

    std::ofstream output(path_, std::ios::binary | std::ios::app);
    if (!output) {
        result.status = DojoStoreStatus::StorageError;
        result.errors.emplace_back("unable to open DOJO store for append");
        return result;
    }
    output << serialize(episode) << '\n';
    if (!output) {
        result.status = DojoStoreStatus::StorageError;
        result.errors.emplace_back("unable to append DOJO episode");
        return result;
    }

    result.status = DojoStoreStatus::Ok;
    return result;
}

std::vector<DojoEpisode> DojoStore::replay(const DojoQuery& query,
                                           std::vector<std::string>* errors) const {
    std::vector<DojoEpisode> retained;
    if (query.limit == 0U || !std::filesystem::exists(path_)) return retained;
    const auto limit = std::min(query.limit, kMaxReplay);
    retained.reserve(std::min<std::size_t>(limit, 256U));

    std::ifstream input(path_, std::ios::binary);
    if (!input) {
        if (errors) errors->emplace_back("unable to open DOJO store");
        return retained;
    }

    std::string line;
    std::size_t line_number = 0U;
    while (std::getline(input, line)) {
        ++line_number;
        std::string parse_error;
        auto episode = deserialize(line, &parse_error);
        if (!episode) {
            if (errors) errors->push_back("line " + std::to_string(line_number) + ": " + parse_error);
            continue;
        }
        if (!matches(*episode, query)) continue;
        if (retained.size() == limit) retained.erase(retained.begin());
        retained.push_back(std::move(*episode));
    }
    return retained;
}

bool DojoStore::export_jsonl(const std::filesystem::path& destination,
                             const DojoQuery& query,
                             std::vector<std::string>* errors) const {
    const auto episodes = replay(query, errors);
    std::ofstream output(destination, std::ios::binary | std::ios::trunc);
    if (!output) {
        if (errors) errors->emplace_back("unable to open DOJO export destination");
        return false;
    }
    for (const auto& episode : episodes) output << to_json(episode) << '\n';
    return static_cast<bool>(output);
}

const std::filesystem::path& DojoStore::path() const noexcept {
    return path_;
}

DojoEpisode make_dojo_episode(TaskClass task,
                              std::string profile_name,
                              std::string hardware_id,
                              std::string model_id,
                              std::string route_status,
                              const ZenkaiResult& zenkai,
                              std::string_view route_trace_description,
                              std::string summary,
                              std::string recorded_at_utc,
                              std::vector<std::string> tags) {
    if (summary.size() > kMaxSummaryBytes) summary.resize(kMaxSummaryBytes);
    if (tags.size() > kMaxTags) tags.resize(kMaxTags);
    for (auto& tag : tags) if (tag.size() > kMaxTagBytes) tag.resize(kMaxTagBytes);

    std::ostringstream outcome_material;
    outcome_material << zenkai.final_state << '\n'
                     << static_cast<unsigned>(zenkai.stop_reason) << '\n'
                     << (zenkai.verified ? 1 : 0) << '\n'
                     << zenkai.attempts << '\n'
                     << zenkai.evidence_items << '\n'
                     << zenkai.tool_events;

    DojoEpisode episode;
    episode.task = task;
    episode.profile_name = std::move(profile_name);
    episode.hardware_id = std::move(hardware_id);
    episode.model_id = std::move(model_id);
    episode.route_status = std::move(route_status);
    episode.outcome = outcome_from(zenkai);
    episode.zenkai_stop_reason = zenkai.stop_reason;
    episode.verified = zenkai.verified;
    episode.attempts = zenkai.attempts;
    episode.evidence_items = zenkai.evidence_items;
    episode.tool_events = zenkai.tool_events;
    episode.final_state_sha256 = sha256(zenkai.final_state);
    episode.route_trace_sha256 = sha256(route_trace_description);
    episode.outcome_sha256 = sha256(outcome_material.str());
    episode.summary = std::move(summary);
    episode.recorded_at_utc = std::move(recorded_at_utc);
    episode.tags = std::move(tags);
    episode.episode_id = episode.immutable_id();
    return episode;
}

std::string_view to_string(DojoOutcome outcome) noexcept {
    switch (outcome) {
    case DojoOutcome::Success: return "SUCCESS";
    case DojoOutcome::Failure: return "FAILURE";
    case DojoOutcome::Aborted: return "ABORTED";
    }
    return "FAILURE";
}

std::string_view to_string(DojoStoreStatus status) noexcept {
    switch (status) {
    case DojoStoreStatus::Ok: return "OK";
    case DojoStoreStatus::Duplicate: return "DUPLICATE";
    case DojoStoreStatus::Invalid: return "INVALID";
    case DojoStoreStatus::StorageError: return "STORAGE_ERROR";
    }
    return "INVALID";
}

} // namespace guff
