#pragma once

#include "guff/scorecard.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class ScorecardAppendStatus : std::uint8_t {
    Appended,
    Duplicate,
    Invalid,
    IoError
};

struct ScorecardAppendResult {
    ScorecardAppendStatus status{ScorecardAppendStatus::IoError};
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

struct ScorecardHydrationQuery {
    HardwareProfile hardware;
    TaskClass task{TaskClass::General};
    std::string profile_name;
    ScoreWeights weights{};
    std::size_t max_records{256};
};

struct ScorecardHydrationReport {
    bool ok{false};
    std::size_t lines_scanned{0};
    std::size_t records_matched{0};
    std::size_t records_loaded{0};
    std::size_t records_rejected{0};
    bool truncated{false};
    std::vector<std::string> errors;
};

class ScorecardStore {
public:
    explicit ScorecardStore(std::filesystem::path path);

    [[nodiscard]] ScorecardAppendResult append(const BenchmarkRecord& record) const;
    [[nodiscard]] ScorecardHydrationReport hydrate(const ScorecardHydrationQuery& query,
                                                   Scorecard& destination) const;

    [[nodiscard]] const std::filesystem::path& path() const noexcept;

private:
    std::filesystem::path path_;
};

[[nodiscard]] std::string_view to_string(ScorecardAppendStatus status) noexcept;

} // namespace guff
