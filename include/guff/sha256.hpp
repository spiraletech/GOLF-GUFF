#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace guff {

[[nodiscard]] std::string sha256(std::string_view data);
[[nodiscard]] std::optional<std::string> sha256_file(const std::filesystem::path& path);
[[nodiscard]] bool is_sha256(std::string_view value) noexcept;

} // namespace guff
