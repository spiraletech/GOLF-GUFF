#include "guff/reality.hpp"

#include <algorithm>
#include <sstream>
#include <utility>

namespace guff {

void RealityStack::observe(RealityCoordinate coordinate) {
    coordinate.confidence = std::clamp(coordinate.confidence, 0.0, 1.0);

    const auto same_identity = [&](const RealityCoordinate& existing) {
        return existing.layer == coordinate.layer &&
               existing.scope == coordinate.scope &&
               existing.entity == coordinate.entity;
    };

    if (auto it = std::find_if(coordinates_.begin(), coordinates_.end(), same_identity);
        it != coordinates_.end()) {
        *it = std::move(coordinate);
        return;
    }

    coordinates_.push_back(std::move(coordinate));
}

void RealityStack::clear_transient() {
    std::erase_if(coordinates_, [](const RealityCoordinate& coordinate) {
        return coordinate.layer == RealityLayer::Meta ||
               coordinate.layer == RealityLayer::Representation;
    });
}

std::optional<RealityCoordinate> RealityStack::best(RealityLayer layer) const {
    std::optional<RealityCoordinate> result;
    for (const auto& coordinate : coordinates_) {
        if (coordinate.layer != layer) {
            continue;
        }
        if (!result || coordinate.confidence > result->confidence) {
            result = coordinate;
        }
    }
    return result;
}

std::vector<RealityCoordinate> RealityStack::snapshot() const {
    return coordinates_;
}

std::string RealityStack::describe() const {
    std::ostringstream out;
    for (std::size_t i = 0; i < coordinates_.size(); ++i) {
        const auto& coordinate = coordinates_[i];
        if (i != 0) {
            out << " -> ";
        }
        out << to_string(coordinate.layer) << ':' << coordinate.scope;
        if (!coordinate.entity.empty()) {
            out << '/' << coordinate.entity;
        }
        out << '@' << coordinate.confidence;
    }
    return out.str();
}

std::string_view to_string(RealityLayer layer) noexcept {
    switch (layer) {
    case RealityLayer::Physical: return "PHYSICAL";
    case RealityLayer::OperatingSystem: return "OS";
    case RealityLayer::Runtime: return "RUNTIME";
    case RealityLayer::Project: return "PROJECT";
    case RealityLayer::Application: return "APPLICATION";
    case RealityLayer::Simulation: return "SIMULATION";
    case RealityLayer::Semantic: return "SEMANTIC";
    case RealityLayer::Memory: return "MEMORY";
    case RealityLayer::Meta: return "META";
    case RealityLayer::Representation: return "REPRESENTATION";
    }
    return "UNKNOWN";
}

} // namespace guff
