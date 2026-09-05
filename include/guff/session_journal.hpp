#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class JournalRecordKind : std::uint8_t {
    Begin,
    Commit,
    Abort
};

enum class JournalStatus : std::uint8_t {
    Ok,
    DuplicateSession,
    SessionNotOpen,
    Invalid,
    IntegrityError,
    StorageError
};

struct JournalBegin {
    std::string session_id;
    std::string correlation_id;
    std::string request_sha256;
    std::string recorded_at_utc;
};

struct JournalTerminal {
    JournalRecordKind kind{JournalRecordKind::Abort};
    std::string session_id;
    std::string correlation_id;
    std::string request_sha256;
    std::string audit_sha256;
    std::string dojo_episode_id;
    std::string terminal_status;
    std::string recorded_at_utc;
};

struct JournalRecord {
    std::uint32_t schema_version{1U};
    std::size_t sequence{0U};
    JournalRecordKind kind{JournalRecordKind::Begin};
    std::string session_id;
    std::string correlation_id;
    std::string request_sha256;
    std::string audit_sha256;
    std::string dojo_episode_id;
    std::string terminal_status;
    std::string recorded_at_utc;
    std::string previous_record_sha256;
    std::string record_sha256;
};

struct JournalWriteResult {
    JournalStatus status{JournalStatus::Invalid};
    std::string record_sha256;
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

struct InterruptedSession {
    std::string session_id;
    std::string correlation_id;
    std::string request_sha256;
    std::string begin_record_sha256;
    std::string recorded_at_utc;
    bool replay_authorized{false};
    bool requires_human_decision{true};
};

struct RecoveryInspection {
    bool healthy{true};
    std::size_t records{0U};
    std::string head_sha256;
    std::vector<InterruptedSession> interrupted;
    std::vector<std::string> errors;
};

class SessionJournal {
public:
    explicit SessionJournal(std::filesystem::path path);

    [[nodiscard]] JournalWriteResult begin(const JournalBegin& begin);
    [[nodiscard]] JournalWriteResult finish(const JournalTerminal& terminal);
    [[nodiscard]] RecoveryInspection inspect() const;

    [[nodiscard]] const std::filesystem::path& path() const noexcept;

private:
    std::filesystem::path path_;
};

[[nodiscard]] std::string_view to_string(JournalRecordKind kind) noexcept;
[[nodiscard]] std::string_view to_string(JournalStatus status) noexcept;

} // namespace guff
