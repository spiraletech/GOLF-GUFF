#include "guff/hardware_profile.hpp"
#include "guff/sha256.hpp"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <thread>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#elif defined(__linux__)
#include <unistd.h>
#elif defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

namespace guff {
namespace {

std::string detect_cpu_name() {
#if defined(_WIN32)
    if (const char* value = std::getenv("PROCESSOR_IDENTIFIER")) return value;
#elif defined(__linux__)
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    while (std::getline(cpuinfo, line)) {
        const auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        const auto key = line.substr(0, pos);
        if (key.find("model name") == std::string::npos && key.find("Hardware") == std::string::npos) continue;
        auto value = line.substr(pos + 1);
        const auto first = value.find_first_not_of(" \t");
        return first == std::string::npos ? std::string{} : value.substr(first);
    }
#elif defined(__APPLE__)
    std::size_t size = 0;
    if (sysctlbyname("machdep.cpu.brand_string", nullptr, &size, nullptr, 0) == 0 && size > 1) {
        std::string value(size, '\0');
        if (sysctlbyname("machdep.cpu.brand_string", value.data(), &size, nullptr, 0) == 0) {
            if (!value.empty() && value.back() == '\0') value.pop_back();
            return value;
        }
    }
#endif
    return {};
}

std::uint64_t detect_ram_mb() {
#if defined(_WIN32)
    MEMORYSTATUSEX status{};
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) return status.ullTotalPhys / (1024ULL * 1024ULL);
#elif defined(__linux__)
    const long pages = sysconf(_SC_PHYS_PAGES);
    const long page_size = sysconf(_SC_PAGE_SIZE);
    if (pages > 0 && page_size > 0) {
        return (static_cast<std::uint64_t>(pages) * static_cast<std::uint64_t>(page_size)) / (1024ULL * 1024ULL);
    }
#elif defined(__APPLE__)
    std::uint64_t bytes = 0;
    std::size_t size = sizeof(bytes);
    if (sysctlbyname("hw.memsize", &bytes, &size, nullptr, 0) == 0) return bytes / (1024ULL * 1024ULL);
#endif
    return 0;
}

Platform detect_platform() noexcept {
#if defined(_WIN32)
    return Platform::Windows;
#elif defined(__linux__)
    return Platform::Linux;
#elif defined(__APPLE__)
    return Platform::MacOS;
#else
    return Platform::Unknown;
#endif
}

CpuArchitecture detect_architecture() noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    return CpuArchitecture::X86_64;
#elif defined(_M_IX86) || defined(__i386__)
    return CpuArchitecture::X86;
#elif defined(_M_ARM64) || defined(__aarch64__)
    return CpuArchitecture::Arm64;
#else
    return CpuArchitecture::Unknown;
#endif
}

} // namespace

std::string HardwareProfile::canonical_payload() const {
    std::ostringstream out;
    out << "schema=" << schema_version << '\n'
        << "platform=" << to_string(platform) << '\n'
        << "architecture=" << to_string(architecture) << '\n'
        << "logical_threads=" << std::max<std::uint32_t>(1U, logical_threads) << '\n'
        << "ram_mb=" << ram_mb << '\n'
        << "vram_mb=" << vram_mb << '\n'
        << "gpu_present=" << (gpu_present ? 1 : 0) << '\n'
        << "cpu_name=" << cpu_name << '\n'
        << "gpu_name=" << gpu_name << '\n';
    return out.str();
}

std::string HardwareProfile::immutable_id() const {
    return "guff:hardware:sha256:" + sha256(canonical_payload());
}

HardwareProfile detect_hardware_profile() {
    HardwareProfile profile;
    profile.platform = detect_platform();
    profile.architecture = detect_architecture();
    profile.logical_threads = std::max(1U, std::thread::hardware_concurrency());
    profile.ram_mb = detect_ram_mb();
    profile.cpu_name = detect_cpu_name();
    return profile;
}

std::string_view to_string(Platform platform) noexcept {
    switch (platform) {
    case Platform::Windows: return "windows";
    case Platform::Linux: return "linux";
    case Platform::MacOS: return "macos";
    case Platform::Unknown: return "unknown";
    }
    return "unknown";
}

std::string_view to_string(CpuArchitecture architecture) noexcept {
    switch (architecture) {
    case CpuArchitecture::X86: return "x86";
    case CpuArchitecture::X86_64: return "x86_64";
    case CpuArchitecture::Arm64: return "arm64";
    case CpuArchitecture::Unknown: return "unknown";
    }
    return "unknown";
}

} // namespace guff
