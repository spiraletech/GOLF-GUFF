#include "guff/session_journal.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <system_error>
#include <unordered_set>
#include <utility>

namespace guff {
namespace {

constexpr std::string_view kSessionPrefix = "guff:session:sha256:";
constexpr std::string_view kDojoPrefix = "guff:dojo:sha256:";
constexpr std::string_view kRecoveryDismissStatus = "RECOVERY_DISMISSED";
constexpr std::string_view kRecoveryRetryPrefix = "RECOVERY_RETRY_AS_NEW_SESSION:";
constexpr std::size_t kMaxLineBytes = 16U * 1024U;

std::string genesis_hash() {
    return std::string(64U, '0');
}

bool canonical_id(std::string_view value, std::string_view prefix) noexcept {
    return value.starts_with(prefix) && is_sha256(value.substr(prefix.size()));
}

bool valid_correlation(std::string_view value) noexcept {
    if (value.empty() || value.size() > 96U) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' ||
               ch == '.' || ch == ':';
    });
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

std::optional<std::string> recovery_child_from_status(std::string_view status) {
    if (!status.starts_with(kRecoveryRetryPrefix)) return std::nullopt;
    auto child = std::string(status.substr(kRecoveryRetryPrefix.size()));
    if (!valid_correlation(child)) return std::nullopt;
    return child;
}

std::vector<std::string> validate_begin(const JournalBegin& begin) {
    std::vector<std::string> errors;
    if (!canonical_id(begin.session_id, kSessionPrefix))
        errors.emplace_back("session_id must be a canonical GOLF session identity");
    if (!valid_correlation(begin.correlation_id))
        errors.emplace_back("correlation_id must be a 1-96 byte token");
    if (!is_sha256(begin.request_sha256))
        errors.emplace_back("request_sha256 must be SHA-256");
    if (begin.recorded_at_utc.empty() || begin.recorded_at_utc.size() > 128U)
        errors.emplace_back("recorded_at_utc must be 1-128 bytes");
    return errors;
}

std::vector<std::string> validate_terminal(const JournalTerminal& terminal) {
    std::vector<std::string> errors;
    if (terminal.kind != JournalRecordKind::Commit && terminal.kind != JournalRecordKind::Abort)
        errors.emplace_back("terminal record kind must be COMMIT or ABORT");
    if (!canonical_id(terminal.session_id, kSessionPrefix))
        errors.emplace_back("session_id must be a canonical GOLF session identity");
    if (!valid_correlation(terminal.correlation_id))
        errors.emplace_back("correlation_id must be a 1-96 byte token");
    if (!is_sha256(terminal.request_sha256))
        errors.emplace_back("request_sha256 must be SHA-256");
    if (!is_sha256(terminal.audit_sha256))
        errors.emplace_back("audit_sha256 must be SHA-256");
    if (!terminal.dojo_episode_id.empty() && !canonical_id(terminal.dojo_episode_id, kDojoPrefix))
        errors.emplace_back("dojo_episode_id must be empty or canonical DOJO identity");
    if (terminal.terminal_status.empty() || terminal.terminal_status.size() > 128U)
        errors.emplace_back("terminal_status must be 1-128 bytes");
    if (terminal.recorded_at_utc.empty() || terminal.recorded_at_utc.size() > 128U)
        errors.emplace_back("recorded_at_utc must be 1-128 bytes");
    return errors;
}

std::vector<std::string> validate_recovery(const JournalRecovery& recovery) {
    std::vector<std::string> errors;
    if (recovery.kind != JournalRecordKind::RecoveryDismiss &&
        recovery.kind != JournalRecordKind::RecoveryRetry)
        errors.emplace_back("recovery kind must be RECOVERY_DISMISS or RECOVERY_RETRY");
    if (!canonical_id(recovery.session_id, kSessionPrefix))
        errors.emplace_back("recovery session_id must be canonical");
    if (!valid_correlation(recovery.correlation_id))
        errors.emplace_back("recovery correlation_id must be a 1-96 byte token");
    if (!is_sha256(recovery.request_sha256))
        errors.emplace_back("recovery request_sha256 must be SHA-256");
    if (!is_sha256(recovery.begin_record_sha256))
        errors.emplace_back("begin_record_sha256 must be SHA-256");
    if (!is_sha256(recovery.authorization_sha256))
        errors.emplace_back("authorization_sha256 must be SHA-256");
    if (recovery.recorded_at_utc.empty() || recovery.recorded_at_utc.size() > 128U)
        errors.emplace_back("recorded_at_utc must be 1-128 bytes");
    if (recovery.kind == JournalRecordKind::RecoveryDismiss) {
        if (!recovery.child_correlation_id.empty())
            errors.emplace_back("DISMISS cannot reserve a child correlation id");
    } else {
        if (!valid_correlation(recovery.child_correlation_id))
            errors.emplace_back("RETRY_AS_NEW_SESSION requires a valid child correlation id");
        if (recovery.child_correlation_id == recovery.correlation_id)
            errors.emplace_back("recovery child correlation must be fresh");
    }
    return errors;
}

std::string canonical_record(const JournalRecord& record) {
    std::ostringstream out;
    out << record.schema_version << '\n'
        << record.sequence << '\n'
        << static_cast<unsigned>(record.kind) << '\n'
        << record.session_id << '\n'
        << record.correlation_id << '\n'
        << record.request_sha256 << '\n'
        << record.audit_sha256 << '\n'
        << record.dojo_episode_id << '\n'
        << record.terminal_status << '\n'
        << record.recorded_at_utc << '\n'
        << record.previous_record_sha256;
    return out.str();
}

std::string serialize(const JournalRecord& record) {
    std::ostringstream out;
    out << "J\t"
        << record.schema_version << '\t'
        << record.sequence << '\t'
        << static_cast<unsigned>(record.kind) << '\t'
        << hex_encode(record.session_id) << '\t'
        << hex_encode(record.correlation_id) << '\t'
        << record.request_sha256 << '\t'
        << (record.audit_sha256.empty() ? "-" : record.audit_sha256) << '\t'
        << hex_encode(record.dojo_episode_id) << '\t'
        << hex_encode(record.terminal_status) << '\t'
        << hex_encode(record.recorded_at_utc) << '\t'
        << record.previous_record_sha256 << '\t'
        << record.record_sha256;
    return out.str();
}

std::optional<JournalRecord> deserialize(std::string_view line, std::string* error) {
    if (line.empty() || line.size() > kMaxLineBytes) {
        if (error) *error = "journal record is empty or exceeds line budget";
        return std::nullopt;
    }
    const auto fields = split_tabs(line);
    if (fields.size() != 13U || fields[0] != "J") {
        if (error) *error = "invalid journal field count or record marker";
        return std::nullopt;
    }

    JournalRecord record;
    unsigned kind = 0U;
    if (!parse_unsigned(fields[1], &record.schema_version) ||
        !parse_unsigned(fields[2], &record.sequence) ||
        !parse_unsigned(fields[3], &kind)) {
        if (error) *error = "invalid numeric journal field";
        return std::nullopt;
    }
    const bool schema_one = record.schema_version == 1U;
    const bool schema_two = record.schema_version == 2U;
    if ((!schema_one && !schema_two) ||
        (schema_one && kind > static_cast<unsigned>(JournalRecordKind::Abort)) ||
        (schema_two && kind > static_cast<unsigned>(JournalRecordKind::RecoveryRetry))) {
        if (error) *error = "unsupported journal schema or record kind";
        return std::nullopt;
    }

    auto session = hex_decode(fields[4]);
    auto correlation = hex_decode(fields[5]);
    auto dojo = hex_decode(fields[8]);
    auto status = hex_decode(fields[9]);
    auto recorded = hex_decode(fields[10]);
    if (!session || !correlation || !dojo || !status || !recorded) {
        if (error) *error = "invalid hex-encoded journal field";
        return std::nullopt;
    }

    record.kind = static_cast<JournalRecordKind>(kind);
    record.session_id = std::move(*session);
    record.correlation_id = std::move(*correlation);
    record.request_sha256 = std::string(fields[6]);
    record.audit_sha256 = fields[7] == "-" ? std::string{} : std::string(fields[7]);
    record.dojo_episode_id = std::move(*dojo);
    record.terminal_status = std::move(*status);
    record.recorded_at_utc = std::move(*recorded);
    record.previous_record_sha256 = std::string(fields[11]);
    record.record_sha256 = std::string(fields[12]);

    if (!canonical_id(record.session_id, kSessionPrefix) ||
        !valid_correlation(record.correlation_id) ||
        !is_sha256(record.request_sha256) ||
        !is_sha256(record.previous_record_sha256) ||
        !is_sha256(record.record_sha256) ||
        record.recorded_at_utc.empty() || record.recorded_at_utc.size() > 128U) {
        if (error) *error = "journal record failed common validation";
        return std::nullopt;
    }

    if (record.kind == JournalRecordKind::Begin) {
        if (!record.audit_sha256.empty() || !record.dojo_episode_id.empty() ||
            !record.terminal_status.empty()) {
            if (error) *error = "BEGIN record contains terminal-only fields";
            return std::nullopt;
        }
    } else if (record.kind == JournalRecordKind::Commit ||
               record.kind == JournalRecordKind::Abort) {
        if (!is_sha256(record.audit_sha256) || record.terminal_status.empty() ||
            record.terminal_status.size() > 128U ||
            (!record.dojo_episode_id.empty() && !canonical_id(record.dojo_episode_id, kDojoPrefix))) {
            if (error) *error = "terminal journal record failed validation";
            return std::nullopt;
        }
    } else if (record.kind == JournalRecordKind::RecoveryDismiss) {
        if (!is_sha256(record.audit_sha256) || !record.dojo_episode_id.empty() ||
            record.terminal_status != kRecoveryDismissStatus) {
            if (error) *error = "recovery DISMISS record failed validation";
            return std::nullopt;
        }
    } else {
        const auto child = recovery_child_from_status(record.terminal_status);
        if (!is_sha256(record.audit_sha256) || !record.dojo_episode_id.empty() ||
            !child || *child == record.correlation_id) {
            if (error) *error = "recovery RETRY record failed validation";
            return std::nullopt;
        }
    }

    if (record.record_sha256 != sha256(canonical_record(record))) {
        if (error) *error = "journal record identity mismatch";
        return std::nullopt;
    }
    return record;
}

struct OpenState {
    JournalRecord begin;
};

struct ScanState {
    bool healthy{true};
    std::size_t next_sequence{0U};
    std::string head_sha256{genesis_hash()};
    std::map<std::string, OpenState> open;
    std::unordered_set<std::string> seen;
    std::unordered_set<std::string> used_correlations;
    std::vector<RecoveryLineage> lineages;
    std::vector<std::string> errors;
};

ScanState scan_journal(const std::filesystem::path& path) {
    ScanState state;
    std::error_code ec;
    const bool exists = std::filesystem::exists(path, ec);
    if (ec) {
        state.healthy = false;
        state.errors.emplace_back("failed to inspect journal path");
        return state;
    }
    if (!exists) return state;

    std::ifstream input(path);
    if (!input) {
        state.healthy = false;
        state.errors.emplace_back("failed to open journal for recovery inspection");
        return state;
    }

    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::string error;
        auto record = deserialize(line, &error);
        if (!record) {
            state.healthy = false;
            state.errors.push_back("record " + std::to_string(state.next_sequence) + ": " + error);
            break;
        }
        if (record->sequence != state.next_sequence) {
            state.healthy = false;
            state.errors.emplace_back("journal sequence discontinuity");
            break;
        }
        if (record->previous_record_sha256 != state.head_sha256) {
            state.healthy = false;
            state.errors.emplace_back("journal hash-chain discontinuity");
            break;
        }

        if (record->kind == JournalRecordKind::Begin) {
            if (!state.seen.emplace(record->session_id).second) {
                state.healthy = false;
                state.errors.emplace_back("duplicate BEGIN for immutable session id");
                break;
            }
            state.used_correlations.emplace(record->correlation_id);
            state.open.emplace(record->session_id, OpenState{*record});
            for (auto& lineage : state.lineages) {
                if (!lineage.child_started &&
                    lineage.child_correlation_id == record->correlation_id) {
                    lineage.child_started = true;
                    lineage.child_session_id = record->session_id;
                    break;
                }
            }
        } else if (record->kind == JournalRecordKind::Commit ||
                   record->kind == JournalRecordKind::Abort) {
            const auto it = state.open.find(record->session_id);
            if (it == state.open.end()) {
                state.healthy = false;
                state.errors.emplace_back("terminal record has no matching open BEGIN");
                break;
            }
            if (it->second.begin.correlation_id != record->correlation_id ||
                it->second.begin.request_sha256 != record->request_sha256) {
                state.healthy = false;
                state.errors.emplace_back("terminal record does not match BEGIN contract");
                break;
            }
            state.open.erase(it);
        } else {
            const auto it = state.open.find(record->session_id);
            if (it == state.open.end()) {
                state.healthy = false;
                state.errors.emplace_back("recovery record has no matching interrupted BEGIN");
                break;
            }
            if (it->second.begin.correlation_id != record->correlation_id ||
                it->second.begin.request_sha256 != record->request_sha256) {
                state.healthy = false;
                state.errors.emplace_back("recovery record does not match BEGIN contract");
                break;
            }
            if (record->kind == JournalRecordKind::RecoveryRetry) {
                const auto child = recovery_child_from_status(record->terminal_status);
                if (!child || state.used_correlations.contains(*child)) {
                    state.healthy = false;
                    state.errors.emplace_back("recovery child correlation is invalid or already used");
                    break;
                }
                const auto duplicate = std::find_if(
                    state.lineages.begin(), state.lineages.end(),
                    [&](const RecoveryLineage& lineage) {
                        return lineage.child_correlation_id == *child;
                    });
                if (duplicate != state.lineages.end()) {
                    state.healthy = false;
                    state.errors.emplace_back("recovery child correlation reserved more than once");
                    break;
                }
                state.lineages.push_back({
                    .parent_session_id = record->session_id,
                    .parent_correlation_id = record->correlation_id,
                    .authorization_sha256 = record->audit_sha256,
                    .child_correlation_id = *child,
                    .child_session_id = {},
                    .child_started = false,
                });
            }
            state.open.erase(it);
        }

        state.head_sha256 = record->record_sha256;
        ++state.next_sequence;
    }
    if (!input.eof() && input.fail()) {
        state.healthy = false;
        state.errors.emplace_back("journal read failed before EOF");
    }
    return state;
}

JournalWriteResult append_record(const std::filesystem::path& path,
                                 JournalRecord record) {
    JournalWriteResult result;
    const auto parent = path.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            result.status = JournalStatus::StorageError;
            result.errors.emplace_back("failed to create journal parent directory");
            return result;
        }
    }

    record.record_sha256 = sha256(canonical_record(record));
    const auto line = serialize(record);
    if (line.size() > kMaxLineBytes) {
        result.status = JournalStatus::Invalid;
        result.errors.emplace_back("serialized journal record exceeds line budget");
        return result;
    }

    std::ofstream output(path, std::ios::app);
    if (!output) {
        result.status = JournalStatus::StorageError;
        result.errors.emplace_back("failed to open journal for append");
        return result;
    }
    output << line << '\n';
    output.flush();
    if (!output) {
        result.status = JournalStatus::StorageError;
        result.errors.emplace_back("journal append/flush failed");
        return result;
    }
    result.status = JournalStatus::Ok;
    result.record_sha256 = record.record_sha256;
    return result;
}

} // namespace

bool JournalWriteResult::ok() const noexcept {
    return status == JournalStatus::Ok;
}

SessionJournal::SessionJournal(std::filesystem::path path)
    : path_(std::move(path)) {}

JournalWriteResult SessionJournal::begin(const JournalBegin& begin_record) {
    JournalWriteResult result;
    result.errors = validate_begin(begin_record);
    if (!result.errors.empty()) {
        result.status = JournalStatus::Invalid;
        return result;
    }

    const auto scan = scan_journal(path_);
    if (!scan.healthy) {
        result.status = JournalStatus::IntegrityError;
        result.errors = scan.errors;
        return result;
    }
    if (scan.seen.contains(begin_record.session_id)) {
        result.status = JournalStatus::DuplicateSession;
        result.errors.emplace_back("immutable session id already exists in journal");
        return result;
    }
    const auto reserved = std::find_if(
        scan.lineages.begin(), scan.lineages.end(),
        [&](const RecoveryLineage& lineage) {
            return !lineage.child_started &&
                   lineage.child_correlation_id == begin_record.correlation_id;
        });
    if (reserved != scan.lineages.end()) {
        result.status = JournalStatus::RecoveryNotAuthorized;
        result.errors.emplace_back("reserved recovery child correlation requires begin_recovery_child");
        return result;
    }

    JournalRecord record;
    record.sequence = scan.next_sequence;
    record.kind = JournalRecordKind::Begin;
    record.session_id = begin_record.session_id;
    record.correlation_id = begin_record.correlation_id;
    record.request_sha256 = begin_record.request_sha256;
    record.recorded_at_utc = begin_record.recorded_at_utc;
    record.previous_record_sha256 = scan.head_sha256;
    return append_record(path_, std::move(record));
}

JournalWriteResult SessionJournal::begin_recovery_child(
    const JournalBegin& begin_record,
    std::string_view parent_session_id,
    std::string_view authorization_sha256) {
    JournalWriteResult result;
    result.errors = validate_begin(begin_record);
    if (!canonical_id(parent_session_id, kSessionPrefix))
        result.errors.emplace_back("parent_session_id must be canonical");
    if (!is_sha256(authorization_sha256))
        result.errors.emplace_back("authorization_sha256 must be SHA-256");
    if (!result.errors.empty()) {
        result.status = JournalStatus::Invalid;
        return result;
    }

    const auto scan = scan_journal(path_);
    if (!scan.healthy) {
        result.status = JournalStatus::IntegrityError;
        result.errors = scan.errors;
        return result;
    }
    if (scan.seen.contains(begin_record.session_id)) {
        result.status = JournalStatus::DuplicateSession;
        result.errors.emplace_back("immutable session id already exists in journal");
        return result;
    }

    const auto lineage = std::find_if(
        scan.lineages.begin(), scan.lineages.end(),
        [&](const RecoveryLineage& item) {
            return !item.child_started &&
                   item.parent_session_id == parent_session_id &&
                   item.authorization_sha256 == authorization_sha256 &&
                   item.child_correlation_id == begin_record.correlation_id;
        });
    if (lineage == scan.lineages.end()) {
        result.status = JournalStatus::RecoveryNotAuthorized;
        result.errors.emplace_back("no matching fresh recovery authorization for child BEGIN");
        return result;
    }

    JournalRecord record;
    record.sequence = scan.next_sequence;
    record.kind = JournalRecordKind::Begin;
    record.session_id = begin_record.session_id;
    record.correlation_id = begin_record.correlation_id;
    record.request_sha256 = begin_record.request_sha256;
    record.recorded_at_utc = begin_record.recorded_at_utc;
    record.previous_record_sha256 = scan.head_sha256;
    return append_record(path_, std::move(record));
}

JournalWriteResult SessionJournal::finish(const JournalTerminal& terminal) {
    JournalWriteResult result;
    result.errors = validate_terminal(terminal);
    if (!result.errors.empty()) {
        result.status = JournalStatus::Invalid;
        return result;
    }

    const auto scan = scan_journal(path_);
    if (!scan.healthy) {
        result.status = JournalStatus::IntegrityError;
        result.errors = scan.errors;
        return result;
    }
    const auto open = scan.open.find(terminal.session_id);
    if (open == scan.open.end()) {
        result.status = JournalStatus::SessionNotOpen;
        result.errors.emplace_back("session is not open in journal");
        return result;
    }
    if (open->second.begin.correlation_id != terminal.correlation_id ||
        open->second.begin.request_sha256 != terminal.request_sha256) {
        result.status = JournalStatus::Invalid;
        result.errors.emplace_back("terminal does not match the open BEGIN contract");
        return result;
    }

    JournalRecord record;
    record.sequence = scan.next_sequence;
    record.kind = terminal.kind;
    record.session_id = terminal.session_id;
    record.correlation_id = terminal.correlation_id;
    record.request_sha256 = terminal.request_sha256;
    record.audit_sha256 = terminal.audit_sha256;
    record.dojo_episode_id = terminal.dojo_episode_id;
    record.terminal_status = terminal.terminal_status;
    record.recorded_at_utc = terminal.recorded_at_utc;
    record.previous_record_sha256 = scan.head_sha256;
    return append_record(path_, std::move(record));
}

JournalWriteResult SessionJournal::recover(const JournalRecovery& recovery) {
    JournalWriteResult result;
    result.errors = validate_recovery(recovery);
    if (!result.errors.empty()) {
        result.status = JournalStatus::Invalid;
        return result;
    }

    const auto scan = scan_journal(path_);
    if (!scan.healthy) {
        result.status = JournalStatus::IntegrityError;
        result.errors = scan.errors;
        return result;
    }
    const auto open = scan.open.find(recovery.session_id);
    if (open == scan.open.end()) {
        result.status = JournalStatus::SessionNotOpen;
        result.errors.emplace_back("recovery parent is not interrupted/open");
        return result;
    }
    if (open->second.begin.correlation_id != recovery.correlation_id ||
        open->second.begin.request_sha256 != recovery.request_sha256 ||
        open->second.begin.record_sha256 != recovery.begin_record_sha256) {
        result.status = JournalStatus::Invalid;
        result.errors.emplace_back("recovery authorization does not match interrupted BEGIN identity");
        return result;
    }
    if (recovery.kind == JournalRecordKind::RecoveryRetry) {
        if (scan.used_correlations.contains(recovery.child_correlation_id)) {
            result.status = JournalStatus::Invalid;
            result.errors.emplace_back("recovery child correlation has already been used");
            return result;
        }
        const auto reserved = std::find_if(
            scan.lineages.begin(), scan.lineages.end(),
            [&](const RecoveryLineage& lineage) {
                return lineage.child_correlation_id == recovery.child_correlation_id;
            });
        if (reserved != scan.lineages.end()) {
            result.status = JournalStatus::Invalid;
            result.errors.emplace_back("recovery child correlation is already reserved");
            return result;
        }
    }

    JournalRecord record;
    record.sequence = scan.next_sequence;
    record.kind = recovery.kind;
    record.session_id = recovery.session_id;
    record.correlation_id = recovery.correlation_id;
    record.request_sha256 = recovery.request_sha256;
    record.audit_sha256 = recovery.authorization_sha256;
    record.terminal_status = recovery.kind == JournalRecordKind::RecoveryDismiss
        ? std::string(kRecoveryDismissStatus)
        : std::string(kRecoveryRetryPrefix) + recovery.child_correlation_id;
    record.recorded_at_utc = recovery.recorded_at_utc;
    record.previous_record_sha256 = scan.head_sha256;
    return append_record(path_, std::move(record));
}

RecoveryInspection SessionJournal::inspect() const {
    const auto scan = scan_journal(path_);
    RecoveryInspection result;
    result.healthy = scan.healthy;
    result.records = scan.next_sequence;
    result.head_sha256 = scan.head_sha256;
    result.errors = scan.errors;
    result.recovery_lineage = scan.lineages;
    for (const auto& [session_id, state] : scan.open) {
        result.interrupted.push_back({
            .session_id = session_id,
            .correlation_id = state.begin.correlation_id,
            .request_sha256 = state.begin.request_sha256,
            .begin_record_sha256 = state.begin.record_sha256,
            .recorded_at_utc = state.begin.recorded_at_utc,
            .replay_authorized = false,
            .requires_human_decision = true,
        });
    }
    return result;
}

const std::filesystem::path& SessionJournal::path() const noexcept {
    return path_;
}

std::string_view to_string(JournalRecordKind kind) noexcept {
    switch (kind) {
    case JournalRecordKind::Begin: return "BEGIN";
    case JournalRecordKind::Commit: return "COMMIT";
    case JournalRecordKind::Abort: return "ABORT";
    case JournalRecordKind::RecoveryDismiss: return "RECOVERY_DISMISS";
    case JournalRecordKind::RecoveryRetry: return "RECOVERY_RETRY_AS_NEW_SESSION";
    }
    return "BEGIN";
}

std::string_view to_string(JournalStatus status) noexcept {
    switch (status) {
    case JournalStatus::Ok: return "OK";
    case JournalStatus::DuplicateSession: return "DUPLICATE_SESSION";
    case JournalStatus::SessionNotOpen: return "SESSION_NOT_OPEN";
    case JournalStatus::RecoveryNotAuthorized: return "RECOVERY_NOT_AUTHORIZED";
    case JournalStatus::Invalid: return "INVALID";
    case JournalStatus::IntegrityError: return "INTEGRITY_ERROR";
    case JournalStatus::StorageError: return "STORAGE_ERROR";
    }
    return "INVALID";
}

} // namespace guff
