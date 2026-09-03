#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class RouteTraceOutcome : std::uint8_t {
    Info,
    Pass,
    Reject,
    Select,
    Stop
};

struct RouteTraceEntry {
    std::string stage;
    RouteTraceOutcome outcome{RouteTraceOutcome::Info};
    std::string detail;
    std::string model_id;
};

class RouteTrace {
public:
    static constexpr std::size_t kMaxEntries = 64U;

    void add(std::string stage,
             RouteTraceOutcome outcome,
             std::string detail,
             std::string model_id = {});

    [[nodiscard]] const std::vector<RouteTraceEntry>& entries() const noexcept;
    [[nodiscard]] bool truncated() const noexcept;
    [[nodiscard]] std::string describe() const;

private:
    std::vector<RouteTraceEntry> entries_;
    bool truncated_{false};
};

[[nodiscard]] std::string_view to_string(RouteTraceOutcome outcome) noexcept;

} // namespace guff
