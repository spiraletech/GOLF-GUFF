#include "guff/scorecard_store.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <iomanip>
#include <limits>
#include <locale>
#include <optional>
#include <sstream>
#include <string_view>
#include <system_error>
#include <utility>

namespace guff {
namespace {

constexpr std::string_view kHeader = "GUFF_SCORECARD_STORE_V1";
constexpr std::size_t kMaxReportedErrors = 8U;

std::string hex_encode(std::string_view input) {
    constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(input.size() * 2U);
    for (const unsigned char ch : input) {
        output.push_back(digits[(ch >> 4U) & 0x0fU]);
        output.push_back(digits[ch & 0x0fU]);
    }
    return output;
}

int hex_value(char ch) noexcept {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
    if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
    return -1;
}

std::optional<std::string> hex_decode(std::string_view input) {
    if ((input.size() % 2U) != 0U) return std::nullopt;
    std::string output;
    output.reserve(input.size() / 2U);
    for (std::size_t i = 0; i < input.size(); i += 2U) {
        const int high = hex_value(input[i]);
        const int low = hex_value(input[i + 1U]);
        if (high < 0 || low < 0) return std::nullopt;
        output.push_back(static_cast<char>((high << 4U) | low));
    }
    return output;
}

std::vector<std::string_view> split_tabs(std::string_view line) {
    std::vector<std::string_view> fields;
    std::size_t start = 0U;
    while (start <= line.size()) {
        const auto end = line.find('\t', start);
        if (end == std::string_view::npos) {
            fields.push_back(line.substr(start));
            break;
        }
        fields.push_back(line.substr(start, end - start));
        start = end + 1U;
    }
    return fields;
}

template <typename T>
bool parse_integer(std::string_view value, T& output) {
    const char* begin = value.data();
    const char* end = value.data() + value.size();
    const auto [ptr, ec] = std::from_chars(begin, end, output);
    return ec == std::errc{} && ptr == end;
}

bool parse_double(std::string_view value, double& output) {
    std::string owned(value);
    std::istringstream stream(owned);
    stream.imbue(std::locale::classic());
    stream >> output;
    return stream && stream.peek() == std::char_traits<char>::eof();
}

std::string serialize_record(const BenchmarkRecord& record) {
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << std::setprecision(std::numeric_limits<double>::max_digits10);
    out << "R1"
        << '\t' << hex_encode(record.run_id)
        << '\t' << hex_encode(record.model_id)
        << '\t' << hex_encode(record.hardware_id)
        << '\t' << static_cast<unsigned int>(record.task)
        << '\t' << hex_encode(record.profile_name)
        << '\t' << record.context_tokens
        << '\t' << record.output_tokens
        << '\t' << hex_encode(record.recorded_at_utc)
        << '\t' << record.metrics.prompt_tokens_per_second
        << '\t' << record.metrics.generation_tokens_per_second
        << '\t' << record.metrics.time_to_first_token_ms
        << '\t' << record.metrics.wall_time_ms
        << '\t' << record.metrics.peak_ram_mb
        << '\t' << record.metrics.peak_vram_mb
        << '\t' << record.metrics.accuracy
        << '\t' << record.metrics.tool_success_rate
        << '\t' << record.metrics.verification_pass_rate
        << '\t' << record.metrics.energy_wh
        << '\t' << record.metrics.retries
        << '\t' << (record.metrics.completed ? 1 : 0)
        << '\t' << record.tags.size();
    for (const auto& tag : record.tags) {
        out << '\t' << hex_encode(tag);
    }
    return out.str();
}

std::optional<BenchmarkRecord> parse_record(std::string_view line, std::string& error) {
    const auto fields = split_tabs(line);
    constexpr std::size_t base_fields = 22U;
    if (fields.size() < base_fields || fields[0] != "R1") {
        error = "invalid SCORECARD store record prefix or field count";
        return std::nullopt;
    }

    BenchmarkRecord record;
    const auto run_id = hex_decode(fields[1]);
    const auto model_id = hex_decode(fields[2]);
    const auto hardware_id = hex_decode(fields[3]);
    const auto profile_name = hex_decode(fields[5]);
    const auto recorded_at = hex_decode(fields[8]);
    if (!run_id || !model_id || !hardware_id || !profile_name || !recorded_at) {
        error = "invalid hex-escaped string field";
        return std::nullopt;
    }

    unsigned int task_value = 0U;
    if (!parse_integer(fields[4], task_value) || task_value > static_cast<unsigned int>(TaskClass::WorldSimulation)) {
        error = "invalid task class";
        return std::nullopt;
    }

    record.run_id = *run_id;
    record.model_id = *model_id;
    record.hardware_id = *hardware_id;
    record.task = static_cast<TaskClass>(task_value);
    record.profile_name = *profile_name;
    record.recorded_at_utc = *recorded_at;

    if (!parse_integer(fields[6], record.context_tokens) ||
        !parse_integer(fields[7], record.output_tokens) ||
        !parse_double(fields[9], record.metrics.prompt_tokens_per_second) ||
        !parse_double(fields[10], record.metrics.generation_tokens_per_second) ||
        !parse_double(fields[11], record.metrics.time_to_first_token_ms) ||
        !parse_double(fields[12], record.metrics.wall_time_ms) ||
        !parse_double(fields[13], record.metrics.peak_ram_mb) ||
        !parse_double(fields[14], record.metrics.peak_vram_mb) ||
        !parse_double(fields[15], record.metrics.accuracy) ||
        !parse_double(fields[16], record.metrics.tool_success_rate) ||
        !parse_double(fields[17], record.metrics.verification_pass_rate) ||
        !parse_double(fields[18], record.metrics.energy_wh) ||
        !parse_integer(fields[19], record.metrics.retries)) {
        error = "invalid numeric SCORECARD field";
        return std::nullopt;
    }

    unsigned int completed = 0U;
    std::size_t tag_count = 0U;
    if (!parse_integer(fields[20], completed) || completed > 1U ||
        !parse_integer(fields[21], tag_count) ||
        fields.size() != base_fields + tag_count) {
        error = "invalid completion or tag count";
        return std::nullopt;
    }
    record.metrics.completed = completed == 1U;

    record.tags.reserve(tag_count);
    for (std::size_t index = 0; index < tag_count; ++index) {
        const auto tag = hex_decode(fields[base_fields + index]);
        if (!tag) {
            error = "invalid tag encoding";
            return std::nullopt;
        }
        record.tags.push_back(*tag);
    }

    const auto validation = record.validate();
    if (!validation.empty()) {
        error = validation.front();
        return std::nullopt;
    }
    return record;
}

void report_error(std::vector<std::string>& errors, std::string message) {
    if (errors.size() < kMaxReportedErrors) errors.push_back(std::move(message));
}

bool better_rank(const RankedBenchmark& lhs, const RankedBenchmark& rhs) {
    if (lhs.score.total != rhs.score.total) return lhs.score.total > rhs.score.total;
    if (lhs.record.metrics.generation_tokens_per_second != rhs.record.metrics.generation_tokens_per_second) {
        return lhs.record.metrics.generation_tokens_per_second > rhs.record.metrics.generation_tokens_per_second;
    }
    return lhs.record.run_id < rhs.record.run_id;
}

} // namespace

bool ScorecardAppendResult::ok() const noexcept {
    return status == ScorecardAppendStatus::Appended;
}

ScorecardStore::ScorecardStore(std::filesystem::path path)
    : path_(std::move(path)) {}

ScorecardAppendResult ScorecardStore::append(const BenchmarkRecord& record) const {
    ScorecardAppendResult result;
    result.errors = record.validate();
    if (!result.errors.empty()) {
        result.status = ScorecardAppendStatus::Invalid;
        return result;
    }

    std::error_code ec;
    const bool exists = std::filesystem::exists(path_, ec);
    if (ec) {
        result.status = ScorecardAppendStatus::IoError;
        result.errors.emplace_back("unable to inspect SCORECARD store path");
        return result;
    }

    std::uintmax_t existing_size = 0U;
    if (exists) {
        existing_size = std::filesystem::file_size(path_, ec);
        if (ec) {
            result.status = ScorecardAppendStatus::IoError;
            result.errors.emplace_back("unable to read SCORECARD store size");
            return result;
        }
    }

    if (exists && existing_size > 0U) {
        std::ifstream input(path_);
        if (!input) {
            result.status = ScorecardAppendStatus::IoError;
            result.errors.emplace_back("unable to open SCORECARD store for duplicate scan");
            return result;
        }
        std::string line;
        if (!std::getline(input, line) || line != kHeader) {
            result.status = ScorecardAppendStatus::IoError;
            result.errors.emplace_back("unsupported or corrupt SCORECARD store header");
            return result;
        }
        std::size_t line_number = 1U;
        while (std::getline(input, line)) {
            ++line_number;
            if (line.empty()) continue;
            std::string parse_error;
            const auto existing = parse_record(line, parse_error);
            if (!existing) {
                result.status = ScorecardAppendStatus::IoError;
                result.errors.push_back("corrupt SCORECARD store record at line " + std::to_string(line_number) + ": " + parse_error);
                return result;
            }
            if (existing->run_id == record.run_id) {
                result.status = ScorecardAppendStatus::Duplicate;
                result.errors.emplace_back("run_id already exists in SCORECARD store");
                return result;
            }
        }
        if (!input.eof()) {
            result.status = ScorecardAppendStatus::IoError;
            result.errors.emplace_back("error while scanning SCORECARD store");
            return result;
        }
    }

    if (!path_.parent_path().empty()) {
        std::filesystem::create_directories(path_.parent_path(), ec);
        if (ec) {
            result.status = ScorecardAppendStatus::IoError;
            result.errors.emplace_back("unable to create SCORECARD store directory");
            return result;
        }
    }

    const bool write_header = !exists || existing_size == 0U;
    std::ofstream output(path_, std::ios::app);
    if (!output) {
        result.status = ScorecardAppendStatus::IoError;
        result.errors.emplace_back("unable to open SCORECARD store for append");
        return result;
    }
    if (write_header) output << kHeader << '\n';
    output << serialize_record(record) << '\n';
    output.flush();
    if (!output.good()) {
        result.status = ScorecardAppendStatus::IoError;
        result.errors.emplace_back("failed while appending SCORECARD record");
        return result;
    }

    result.status = ScorecardAppendStatus::Appended;
    return result;
}

ScorecardHydrationReport ScorecardStore::hydrate(const ScorecardHydrationQuery& query,
                                                 Scorecard& destination) const {
    ScorecardHydrationReport report;
    const std::size_t limit = std::max<std::size_t>(1U, query.max_records);

    std::error_code ec;
    if (!std::filesystem::exists(path_, ec)) {
        report.ok = !ec;
        if (ec) report.errors.emplace_back("unable to inspect SCORECARD store path");
        return report;
    }

    std::ifstream input(path_);
    if (!input) {
        report.errors.emplace_back("unable to open SCORECARD store for hydration");
        return report;
    }

    std::string line;
    if (!std::getline(input, line) || line != kHeader) {
        report.errors.emplace_back("unsupported or corrupt SCORECARD store header");
        return report;
    }

    const auto hardware_id = query.hardware.immutable_id();
    ScorecardEvaluator evaluator;
    std::vector<RankedBenchmark> retained;
    retained.reserve(limit);

    std::size_t line_number = 1U;
    while (std::getline(input, line)) {
        ++line_number;
        if (line.empty()) continue;
        ++report.lines_scanned;

        std::string parse_error;
        auto record = parse_record(line, parse_error);
        if (!record) {
            ++report.records_rejected;
            report_error(report.errors, "rejected line " + std::to_string(line_number) + ": " + parse_error);
            continue;
        }
        if (record->hardware_id != hardware_id || record->task != query.task) continue;
        if (!query.profile_name.empty() && record->profile_name != query.profile_name) continue;

        ++report.records_matched;
        RankedBenchmark ranked{*record, evaluator.evaluate(*record, query.hardware, query.weights)};
        if (retained.size() < limit) {
            retained.push_back(std::move(ranked));
            std::sort(retained.begin(), retained.end(), better_rank);
        } else if (better_rank(ranked, retained.back())) {
            retained.back() = std::move(ranked);
            std::sort(retained.begin(), retained.end(), better_rank);
        }
    }

    if (!input.eof()) {
        report.errors.emplace_back("error while reading SCORECARD store");
        return report;
    }

    report.truncated = report.records_matched > retained.size();
    for (auto& ranked : retained) {
        std::vector<std::string> add_errors;
        if (destination.add(std::move(ranked.record), &add_errors)) {
            ++report.records_loaded;
        } else {
            ++report.records_rejected;
            if (!add_errors.empty()) report_error(report.errors, add_errors.front());
        }
    }

    report.ok = true;
    return report;
}

const std::filesystem::path& ScorecardStore::path() const noexcept {
    return path_;
}

std::string_view to_string(ScorecardAppendStatus status) noexcept {
    switch (status) {
    case ScorecardAppendStatus::Appended: return "APPENDED";
    case ScorecardAppendStatus::Duplicate: return "DUPLICATE";
    case ScorecardAppendStatus::Invalid: return "INVALID";
    case ScorecardAppendStatus::IoError: return "IO_ERROR";
    }
    return "IO_ERROR";
}

} // namespace guff
