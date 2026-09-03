#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class RealityLayer : std::uint8_t {
    Physical,
    OperatingSystem,
    Runtime,
    Project,
    Application,
    Simulation,
    Semantic,
    Memory,
    Meta,
    Representation
};

struct RealityCoordinate {
    RealityLayer layer{RealityLayer::Semantic};
    std::string scope;
    std::string entity;
    double confidence{1.0};
};

class RealityStack {
public:
    void observe(RealityCoordinate coordinate);
    void clear_transient();

    [[nodiscard]] std::optional<RealityCoordinate> best(RealityLayer layer) const;
    [[nodiscard]] std::vector<RealityCoordinate> snapshot() const;
    [[nodiscard]] std::string describe() const;

private:
    std::vector<RealityCoordinate> coordinates_;
};

[[nodiscard]] std::string_view to_string(RealityLayer layer) noexcept;

} // namespace guff
