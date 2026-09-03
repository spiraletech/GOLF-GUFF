#pragma once

#include "guff/scorecard.hpp"
#include "guff/zenkai.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class DojoOutcome : std::uint8_t {
    Success,
    Failure,
    Aborted
};

enum class DojoStoreStatus : std::uint8_t {
    Ok,
    Duplicate,
    Invalid,
    StorageError
};

struct DojoEpisode {
    std::uint32_t schema_version{1U};
    std::string episode_id;
    TaskClass task{TaskClass::General};
    std::string profile_name;
    std::string hardware_id;
    std::string model_id;
    std::string route_status;
    DojoOutcome outcome{DojoOutcome::Failure};
    ZenkaiStopReason zenkai_stop_reason{ZenkaiStopReason::AttemptBudget};
    bool verified{false};
    std::size_t attempts{0U};
    std::size_t evidence_items{0U};
    std::size_t tool_events{0U};
    std::string final_state_sha256;
    std::string route_trace_sha256;
    std::string outcome_sha256;
    std::string summary;
    std::string recorded_at_utc;
    std::vector<std::string> tags;

    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] std::string immutable_id() const;
};

struct DojoQuery {
    std::optional<TaskClass> task;
    std::optional<DojoOutcome> outcome;
    std::string profile_name;
    std::string model_id;
    bool verified_only{false};
    std::size_t limit{128U};
};

struct DojoStoreResult {
    DojoStoreStatus status{DojoStoreStatus::Invalid};
    std::string episode_id;
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

class DojoStore {
public:
    explicit DojoStore(std::filesystem::path path);

    [[nodiscard]] DojoStoreResult append(DojoEpisode episode);
    [[nodiscard]] std::vector<DojoEpisode> replay(
        const DojoQuery& query = {},
        std::vector<std::string>* errors = nullptr) const;
    [[nodiscard]] bool export_jsonl(
        const std::filesystem::path& destination,
        const DojoQuery& query = {},
        std::vector<std::string>* errors = nullptr) const;

    [[nodiscard]] const std::filesystem::path& path() const noexcept;

private:
    std::filesystem::path path_;
};

[[nodiscard]] DojoEpisode make_dojo_episode(
    TaskClass task,
    std::string profile_name,
    std::string hardware_id,
    std::string model_id,
    std::string route_status,
    const ZenkaiResult& zenkai,
    std::string_view route_trace_description,
    std::string summary,
    std::string recorded_at_utc,
    std::vector<std::string> tags = {});

[[nodiscard]] std::string_view to_string(DojoOutcome outcome) noexcept;
[[nodiscard]] std::string_view to_string(DojoStoreStatus status) noexcept;

} // namespace guff
