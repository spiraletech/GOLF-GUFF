#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace guff {

enum class Platform : std::uint8_t { Unknown, Windows, Linux, MacOS };
enum class CpuArchitecture : std::uint8_t { Unknown, X86, X86_64, Arm64 };

struct HardwareProfile {
    std::uint32_t schema_version{1};
    Platform platform{Platform::Unknown};
    CpuArchitecture architecture{CpuArchitecture::Unknown};
    std::uint32_t logical_threads{1};
    std::uint64_t ram_mb{0};
    std::uint64_t vram_mb{0};
    bool gpu_present{false};
    std::string cpu_name;
    std::string gpu_name;

    [[nodiscard]] std::string canonical_payload() const;
    [[nodiscard]] std::string immutable_id() const;
};

[[nodiscard]] HardwareProfile detect_hardware_profile();
[[nodiscard]] std::string_view to_string(Platform platform) noexcept;
[[nodiscard]] std::string_view to_string(CpuArchitecture architecture) noexcept;

} // namespace guff
