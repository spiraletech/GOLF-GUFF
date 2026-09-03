#include "guff/model_manifest.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <sstream>
#include <system_error>

namespace guff {
namespace {

std::string lower_hex(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

void append_field(std::ostringstream& out,
                  std::string_view key,
                  std::string_view value) {
    out << key.size() << ':' << key
        << '=' << value.size() << ':' << value
        << ';';
}

template <typename T>
void append_number(std::ostringstream& out,
                   std::string_view key,
                   T value) {
    append_field(out, key, std::to_string(value));
}

void append_bool(std::ostringstream& out,
                 std::string_view key,
                 bool value) {
    append_field(out, key, value ? "1" : "0");
}

std::vector<std::string> normalized_list(const std::vector<std::string>& input) {
    auto values = input;
    std::erase_if(values, [](const std::string& value) {
        return value.empty();
    });
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    return values;
}

bool safe_relative_model_path(std::string_view file_name) {
    if (file_name.empty()) {
        return false;
    }

    const std::filesystem::path path(file_name);
    if (path.is_absolute()) {
        return false;
    }

    for (const auto& part : path) {
        if (part == "..") {
            return false;
        }
    }
    return true;
}

} // namespace

bool VerificationReport::ok() const noexcept {
    return manifest_valid && file_exists && size_matches && hash_matches && errors.empty();
}

std::vector<std::string> ModelManifest::validate() const {
    std::vector<std::string> errors;

    if (schema_version != 1U) {
        errors.emplace_back("unsupported manifest schema version");
    }
    if (display_name.empty()) {
        errors.emplace_back("display_name is required");
    }
    if (family.empty()) {
        errors.emplace_back("family is required");
    }
    if (architecture.empty()) {
        errors.emplace_back("architecture is required");
    }
    if (parameter_count == 0U) {
        errors.emplace_back("parameter_count must be non-zero");
    }
    if (format == ModelFormat::Unknown) {
        errors.emplace_back("model format is required");
    }
    if (quantization == Quantization::Unknown) {
        errors.emplace_back("quantization is required");
    }
    if (!safe_relative_model_path(file_name)) {
        errors.emplace_back("file_name must be a safe relative path");
    }
    if (file_size_bytes == 0U) {
        errors.emplace_back("file_size_bytes must be non-zero");
    }
    if (!is_sha256(sha256)) {
        errors.emplace_back("sha256 must be exactly 64 hexadecimal characters");
    }

    if (provenance.provider.empty()) {
        errors.emplace_back("provenance.provider is required");
    }
    if (provenance.repository.empty()) {
        errors.emplace_back("provenance.repository is required");
    }
    if (provenance.revision.empty()) {
        errors.emplace_back("provenance.revision is required");
    }
    if (provenance.source_filename.empty()) {
        errors.emplace_back("provenance.source_filename is required");
    }
    if (!is_sha256(provenance.source_sha256)) {
        errors.emplace_back("provenance.source_sha256 must be a SHA-256 digest");
    }

    if (license.spdx_id.empty()) {
        errors.emplace_back("license.spdx_id is required");
    }
    if (license.name.empty()) {
        errors.emplace_back("license.name is required");
    }

    if (hardware.min_ram_mb == 0U) {
        errors.emplace_back("hardware.min_ram_mb must be non-zero");
    }
    if (hardware.recommended_threads == 0U) {
        errors.emplace_back("hardware.recommended_threads must be non-zero");
    }

    return errors;
}

std::string ModelManifest::canonical_identity_payload() const {
    std::ostringstream out;

    append_number(out, "schema_version", schema_version);
    append_field(out, "display_name", display_name);
    append_field(out, "family", family);
    append_field(out, "architecture", architecture);
    append_field(out, "variant", variant);
    append_number(out, "parameter_count", parameter_count);
    append_field(out, "format", to_string(format));
    append_field(out, "quantization", to_string(quantization));
    append_field(out, "file_name", file_name);
    append_number(out, "file_size_bytes", file_size_bytes);
    append_field(out, "sha256", lower_hex(sha256));

    append_field(out, "provenance.provider", provenance.provider);
    append_field(out, "provenance.repository", provenance.repository);
    append_field(out, "provenance.revision", provenance.revision);
    append_field(out, "provenance.source_filename", provenance.source_filename);
    append_field(out, "provenance.source_sha256", lower_hex(provenance.source_sha256));

    append_field(out, "license.spdx_id", license.spdx_id);
    append_field(out, "license.name", license.name);
    append_bool(out, "license.commercial_use_allowed", license.commercial_use_allowed);
    append_bool(out, "license.redistribution_allowed", license.redistribution_allowed);

    append_number(out, "hardware.min_ram_mb", hardware.min_ram_mb);
    append_number(out, "hardware.min_vram_mb", hardware.min_vram_mb);
    append_number(out, "hardware.recommended_threads", hardware.recommended_threads);
    append_bool(out, "hardware.cpu_only_supported", hardware.cpu_only_supported);

    const auto canonical_capabilities = normalized_list(capabilities);
    append_number(out, "capabilities.count", canonical_capabilities.size());
    for (const auto& capability : canonical_capabilities) {
        append_field(out, "capability", capability);
    }

    const auto canonical_tags = normalized_list(tags);
    append_number(out, "tags.count", canonical_tags.size());
    for (const auto& tag : canonical_tags) {
        append_field(out, "tag", tag);
    }

    return out.str();
}

std::string ModelManifest::immutable_id() const {
    return "guff:model:sha256:" + guff::sha256(canonical_identity_payload());
}

VerificationReport ModelManifest::verify_file(const std::filesystem::path& path) const {
    VerificationReport report;
    report.errors = validate();
    report.manifest_valid = report.errors.empty();
    report.expected_sha256 = lower_hex(sha256);

    if (!report.manifest_valid) {
        return report;
    }

    std::error_code ec;
    report.file_exists = std::filesystem::is_regular_file(path, ec);
    if (ec || !report.file_exists) {
        report.errors.emplace_back("model file does not exist or is not a regular file");
        return report;
    }

    report.actual_size_bytes = std::filesystem::file_size(path, ec);
    if (ec) {
        report.errors.emplace_back("unable to read model file size");
        return report;
    }

    report.size_matches = report.actual_size_bytes == file_size_bytes;
    if (!report.size_matches) {
        report.errors.emplace_back("model file size does not match manifest");
    }

    const auto digest = sha256_file(path);
    if (!digest) {
        report.errors.emplace_back("unable to hash model file");
        return report;
    }

    report.actual_sha256 = lower_hex(*digest);
    report.hash_matches = report.actual_sha256 == report.expected_sha256;
    if (!report.hash_matches) {
        report.errors.emplace_back("model SHA-256 does not match manifest");
    }

    return report;
}

std::string_view to_string(ModelFormat format) noexcept {
    switch (format) {
    case ModelFormat::Unknown: return "UNKNOWN";
    case ModelFormat::GGUF: return "GGUF";
    case ModelFormat::SafeTensors: return "SAFETENSORS";
    case ModelFormat::Other: return "OTHER";
    }
    return "UNKNOWN";
}

std::string_view to_string(Quantization quantization) noexcept {
    switch (quantization) {
    case Quantization::Unknown: return "UNKNOWN";
    case Quantization::F32: return "F32";
    case Quantization::F16: return "F16";
    case Quantization::BF16: return "BF16";
    case Quantization::Q8_0: return "Q8_0";
    case Quantization::Q6_K: return "Q6_K";
    case Quantization::Q5_K_M: return "Q5_K_M";
    case Quantization::Q4_K_M: return "Q4_K_M";
    case Quantization::Q4_0: return "Q4_0";
    }
    return "UNKNOWN";
}

} // namespace guff
