#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace guff {

enum class ModelFormat : std::uint8_t {
    Unknown,
    GGUF,
    SafeTensors,
    Other
};

enum class Quantization : std::uint8_t {
    Unknown,
    F32,
    F16,
    BF16,
    Q8_0,
    Q6_K,
    Q5_K_M,
    Q4_K_M,
    Q4_0
};

struct UpstreamProvenance {
    std::string provider;
    std::string repository;
    std::string revision;
    std::string source_filename;
    std::string source_sha256;
};

struct LicenseMetadata {
    std::string spdx_id;
    std::string name;
    bool commercial_use_allowed{false};
    bool redistribution_allowed{false};
};

struct HardwareRequirements {
    std::uint64_t min_ram_mb{0};
    std::uint64_t min_vram_mb{0};
    std::uint32_t recommended_threads{1};
    bool cpu_only_supported{true};
};

struct VerificationReport {
    bool manifest_valid{false};
    bool file_exists{false};
    bool size_matches{false};
    bool hash_matches{false};
    std::uint64_t actual_size_bytes{0};
    std::string expected_sha256;
    std::string actual_sha256;
    std::vector<std::string> errors;

    [[nodiscard]] bool ok() const noexcept;
};

struct ModelManifest {
    std::uint32_t schema_version{1};

    std::string display_name;
    std::string family;
    std::string architecture;
    std::string variant;

    std::uint64_t parameter_count{0};
    ModelFormat format{ModelFormat::Unknown};
    Quantization quantization{Quantization::Unknown};

    std::string file_name;
    std::uint64_t file_size_bytes{0};
    std::string sha256;

    UpstreamProvenance provenance;
    LicenseMetadata license;
    HardwareRequirements hardware;

    std::vector<std::string> capabilities;
    std::vector<std::string> tags;

    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] std::string canonical_identity_payload() const;
    [[nodiscard]] std::string immutable_id() const;
    [[nodiscard]] VerificationReport verify_file(const std::filesystem::path& path) const;
};

[[nodiscard]] std::string_view to_string(ModelFormat format) noexcept;
[[nodiscard]] std::string_view to_string(Quantization quantization) noexcept;

} // namespace guff
