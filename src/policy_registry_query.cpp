#include "guff/policy_registry.hpp"

#include <charconv>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace guff {
namespace {

std::optional<std::string> hex_decode(std::string_view input) {
    if ((input.size() % 2U) != 0U) return std::nullopt;
    auto nibble = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(input.size() / 2U);
    for (std::size_t i = 0U; i < input.size(); i += 2U) {
        const int high = nibble(input[i]);
        const int low = nibble(input[i + 1U]);
        if (high < 0 || low < 0) return std::nullopt;
        out.push_back(static_cast<char>((high << 4) | low));
    }
    return out;
}

std::vector<std::string_view> split_tabs(std::string_view line) {
    std::vector<std::string_view> out;
    std::size_t start = 0U;
    while (start <= line.size()) {
        const auto next = line.find('\t', start);
        if (next == std::string_view::npos) {
            out.push_back(line.substr(start));
            break;
        }
        out.push_back(line.substr(start, next - start));
        start = next + 1U;
    }
    return out;
}

template <typename T>
bool parse_unsigned(std::string_view value, T* out) {
    if (!out || value.empty()) return false;
    T parsed{};
    const auto* begin = value.data();
    const auto* end = begin + value.size();
    const auto [ptr, ec] = std::from_chars(begin, end, parsed);
    if (ec != std::errc{} || ptr != end) return false;
    *out = parsed;
    return true;
}

std::optional<SignedPolicyPackage> find_package_in_healthy_registry(
    const std::filesystem::path& path,
    std::string_view policy_id) {
    std::ifstream input(path);
    if (!input) return std::nullopt;

    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto fields = split_tabs(line);
        if (fields.size() != 18U || fields[0] != "PREG") return std::nullopt;

        unsigned kind = 0U;
        std::uint32_t schema = 0U;
        if (!parse_unsigned(fields[1], &schema) || !parse_unsigned(fields[3], &kind)) {
            return std::nullopt;
        }
        if (schema != 1U || kind != 0U || fields[4] != policy_id) continue;

        std::uint64_t signed_at = 0U;
        if (!parse_unsigned(fields[8], &signed_at)) return std::nullopt;
        auto signer = hex_decode(fields[6]);
        auto algorithm = hex_decode(fields[7]);
        auto signature = hex_decode(fields[9]);
        if (!signer || !algorithm || !signature) return std::nullopt;

        SignedPolicyPackage package;
        package.policy_id = std::string(fields[4]);
        package.package_id = std::string(fields[5]);
        package.signer_id = std::move(*signer);
        package.algorithm = std::move(*algorithm);
        package.signed_at_unix_ms = signed_at;
        package.signature = std::move(*signature);
        return package;
    }
    return std::nullopt;
}

} // namespace

std::optional<SignedPolicyPackage> SignedPolicyRegistry::package(
    std::string_view policy_id) const {
    const auto snapshot = inspect();
    if (!snapshot.healthy || policy_id.empty()) return std::nullopt;
    return find_package_in_healthy_registry(journal_path_, policy_id);
}

std::optional<SignedPolicyPackage> SignedPolicyRegistry::active_package() const {
    const auto snapshot = inspect();
    if (!snapshot.healthy || snapshot.active_policy_id.empty()) return std::nullopt;
    auto package = find_package_in_healthy_registry(journal_path_, snapshot.active_policy_id);
    if (!package || package->package_id != snapshot.active_package_id) return std::nullopt;
    return package;
}

} // namespace guff
