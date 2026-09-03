#include "guff/recursor.hpp"

#include <algorithm>
#include <utility>

namespace guff {

Recursor::Recursor(RecursionBudget budget)
    : budget_(budget) {
    budget_.max_depth = std::max<std::size_t>(1, budget_.max_depth);
    budget_.max_steps = std::max<std::size_t>(1, budget_.max_steps);
    budget_.max_working_items = std::max<std::size_t>(1, budget_.max_working_items);
    budget_.confidence_stop = std::clamp(budget_.confidence_stop, 0.0, 1.0);
}

RecursionResult Recursor::run(std::string initial_state,
                              const StepFunction& step) const {
    RecursionFrame frame;
    frame.state = std::move(initial_state);

    RecursionResult result;
    result.state = frame.state;

    for (std::size_t step_index = 0; step_index < budget_.max_steps; ++step_index) {
        frame.step = step_index;
        if (frame.depth >= budget_.max_depth) {
            result.stopped_by_budget = true;
            break;
        }

        auto next = step(frame);
        next.step = step_index + 1;
        next.depth = std::min(next.depth, budget_.max_depth);
        next.confidence = std::clamp(next.confidence, 0.0, 1.0);

        result.trace.push_back(next.state);
        result.state = next.state;
        result.steps = step_index + 1;
        result.confidence = next.confidence;

        if (next.confidence >= budget_.confidence_stop || !next.produced_new_information) {
            break;
        }

        frame = std::move(next);
    }

    if (result.steps == budget_.max_steps &&
        result.confidence < budget_.confidence_stop) {
        result.stopped_by_budget = true;
    }

    return result;
}

} // namespace guff
