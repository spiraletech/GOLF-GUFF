#include "guff/session_journal.hpp"
#include "guff/sha256.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#define CHECK(expression)                                                                     \
    do {                                                                                      \
        if (!(expression)) {                                                                  \
            std::cerr << "CHECK failed: " #expression << " @ " << __FILE__ << ':'          \
                      << __LINE__ << '\n';                                                    \
            return 1;                                                                         \
        }                                                                                     \
    } while (false)

namespace {

std::string session_id(std::string_view seed) {
    return "guff:session:sha256:" + guff::sha256(seed);
}

std::string dojo_id(std::string_view seed) {
    return "guff:dojo:sha256:" + guff::sha256(seed);
}

guff::JournalBegin begin_for(std::string seed, std::string correlation) {
    return {
        .session_id = session_id(seed),
        .correlation_id = std::move(correlation),
        .request_sha256 = guff::sha256("request:" + seed),
        .recorded_at_utc = "2026-09-04T17:07:00-07:00",
    };
}

guff::JournalTerminal terminal_for(const guff::JournalBegin& begin,
                                   guff::JournalRecordKind kind,
                                   std::string status,
                                   bool with_dojo) {
    return {
        .kind = kind,
        .session_id = begin.session_id,
        .correlation_id = begin.correlation_id,
        .request_sha256 = begin.request_sha256,
        .audit_sha256 = guff::sha256("audit:" + begin.session_id),
        .dojo_episode_id = with_dojo ? dojo_id("dojo:" + begin.session_id) : std::string{},
        .terminal_status = std::move(status),
        .recorded_at_utc = "2026-09-04T17:08:00-07:00",
    };
}

} // namespace

int main() {
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-session-journal-regression");
    const auto path = root / "transactions.journal";
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root);

    guff::SessionJournal journal(path);
    const auto empty = journal.inspect();
    CHECK(empty.healthy);
    CHECK(empty.records == 0U);
    CHECK(empty.interrupted.empty());
    CHECK(empty.head_sha256 == std::string(64U, '0'));

    const auto first = begin_for("first", "corr-journal-001");
    const auto first_begin = journal.begin(first);
    CHECK(first_begin.ok());
    CHECK(guff::is_sha256(first_begin.record_sha256));

    const auto interrupted = journal.inspect();
    CHECK(interrupted.healthy);
    CHECK(interrupted.records == 1U);
    CHECK(interrupted.interrupted.size() == 1U);
    CHECK(interrupted.interrupted.front().session_id == first.session_id);
    CHECK(interrupted.interrupted.front().begin_record_sha256 == first_begin.record_sha256);
    CHECK(!interrupted.interrupted.front().replay_authorized);
    CHECK(interrupted.interrupted.front().requires_human_decision);

    const auto duplicate = journal.begin(first);
    CHECK(duplicate.status == guff::JournalStatus::DuplicateSession);

    const auto first_commit = journal.finish(
        terminal_for(first, guff::JournalRecordKind::Commit, "COMPLETED", true));
    CHECK(first_commit.ok());
    CHECK(guff::is_sha256(first_commit.record_sha256));

    const auto closed = journal.inspect();
    CHECK(closed.healthy);
    CHECK(closed.records == 2U);
    CHECK(closed.interrupted.empty());
    CHECK(closed.head_sha256 == first_commit.record_sha256);

    const auto second_finish = journal.finish(
        terminal_for(first, guff::JournalRecordKind::Abort, "ABORTED", false));
    CHECK(second_finish.status == guff::JournalStatus::SessionNotOpen);

    const auto second = begin_for("second", "corr-journal-002");
    CHECK(journal.begin(second).ok());

    guff::SessionJournal reopened(path);
    const auto after_reopen = reopened.inspect();
    CHECK(after_reopen.healthy);
    CHECK(after_reopen.records == 3U);
    CHECK(after_reopen.interrupted.size() == 1U);
    CHECK(after_reopen.interrupted.front().session_id == second.session_id);
    CHECK(!after_reopen.interrupted.front().replay_authorized);

    CHECK(reopened.finish(
        terminal_for(second, guff::JournalRecordKind::Abort, "VERIFICATION_FAILED", true)).ok());

    const auto crash = begin_for("crash", "corr-journal-crash");
    CHECK(reopened.begin(crash).ok());
    const auto crash_inspection = reopened.inspect();
    CHECK(crash_inspection.healthy);
    CHECK(crash_inspection.records == 5U);
    CHECK(crash_inspection.interrupted.size() == 1U);
    CHECK(crash_inspection.interrupted.front().session_id == crash.session_id);
    CHECK(crash_inspection.interrupted.front().requires_human_decision);
    CHECK(!crash_inspection.interrupted.front().replay_authorized);

    {
        std::ofstream corrupt(path, std::ios::app);
        CHECK(corrupt.good());
        corrupt << "CORRUPTED-TAIL\n";
        corrupt.flush();
        CHECK(corrupt.good());
    }

    const auto damaged = reopened.inspect();
    CHECK(!damaged.healthy);
    CHECK(!damaged.errors.empty());

    const auto blocked = reopened.begin(begin_for("blocked", "corr-journal-blocked"));
    CHECK(blocked.status == guff::JournalStatus::IntegrityError);

    std::filesystem::remove_all(root, ec);
    return 0;
}
