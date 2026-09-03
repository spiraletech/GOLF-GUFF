#include "guff/route_trace.hpp"

#include <sstream>
#include <utility>

namespace guff {

void RouteTrace::add(std::string stage,
                     RouteTraceOutcome outcome,
                     std::string detail,
                     std::string model_id) {
    if (entries_.size() >= kMaxEntries) {
        truncated_ = true;
        return;
    }
    entries_.push_back({
        .stage = std::move(stage),
        .outcome = outcome,
        .detail = std::move(detail),
        .model_id = std::move(model_id),
    });
}

const std::vector<RouteTraceEntry>& RouteTrace::entries() const noexcept {
    return entries_;
}

bool RouteTrace::truncated() const noexcept {
    return truncated_;
}

std::string RouteTrace::describe() const {
    std::ostringstream out;
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        const auto& entry = entries_[i];
        if (i != 0U) out << " -> ";
        out << entry.stage << ':' << to_string(entry.outcome);
        if (!entry.model_id.empty()) out << '[' << entry.model_id << ']';
    }
    if (truncated_) out << " -> TRACE_TRUNCATED";
    return out.str();
}

std::string_view to_string(RouteTraceOutcome outcome) noexcept {
    switch (outcome) {
    case RouteTraceOutcome::Info: return "INFO";
    case RouteTraceOutcome::Pass: return "PASS";
    case RouteTraceOutcome::Reject: return "REJECT";
    case RouteTraceOutcome::Select: return "SELECT";
    case RouteTraceOutcome::Stop: return "STOP";
    }
    return "INFO";
}

} // namespace guff
