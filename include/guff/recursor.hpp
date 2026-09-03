#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

namespace guff {

struct RecursionBudget {
    std::size_t max_depth{4};
    std::size_t max_steps{12};
    std::size_t max_working_items{32};
    double confidence_stop{0.92};
};

struct RecursionFrame {
    std::size_t depth{0};
    std::size_t step{0};
    double confidence{0.0};
    bool produced_new_information{true};
    std::string state;
};

struct RecursionResult {
    std::string state;
    std::size_t steps{0};
    double confidence{0.0};
    bool stopped_by_budget{false};
    std::vector<std::string> trace;
};

class Recursor {
public:
    using StepFunction = std::function<RecursionFrame(const RecursionFrame&)>;

    explicit Recursor(RecursionBudget budget = {});

    [[nodiscard]] RecursionResult run(std::string initial_state,
                                      const StepFunction& step) const;

private:
    RecursionBudget budget_;
};

} // namespace guff
