#include "guff/route_trace.hpp"

#include <cassert>
#include <string>

int main() {
    guff::RouteTrace trace;
    trace.add("risk-gate", guff::RouteTraceOutcome::Pass, "model route allowed");
    trace.add("verification-gate", guff::RouteTraceOutcome::Reject,
              "unverified club rejected", "guff:model:test");
    trace.add("selection", guff::RouteTraceOutcome::Select,
              "winner", "guff:model:winner");

    assert(trace.entries().size() == 3U);
    assert(!trace.truncated());
    assert(trace.entries()[1].outcome == guff::RouteTraceOutcome::Reject);
    assert(trace.describe().find("selection:SELECT") != std::string::npos);

    for (std::size_t i = 0; i < guff::RouteTrace::kMaxEntries + 10U; ++i) {
        trace.add("overflow", guff::RouteTraceOutcome::Info, std::to_string(i));
    }
    assert(trace.entries().size() == guff::RouteTrace::kMaxEntries);
    assert(trace.truncated());
    assert(trace.describe().find("TRACE_TRUNCATED") != std::string::npos);
    return 0;
}
