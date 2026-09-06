#include "guff/alpha_release.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <sstream>
#include <utility>

namespace guff {
namespace {

constexpr std::string_view kAlphaPrefix = "guff:alpha-release:sha256:";
constexpr std::string_view kRingPrefix = "guff:ring-release:sha256:";
constexpr std::string_view kVersionPrefix = "0.31.0-alpha.";

bool valid_text(std::string_view value, std::size_t max_bytes) {
    if (value.empty() || value.size() > max_bytes) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch >= 0x20U && ch != 0x7fU;
    });
}

bool valid_commit_sha(std::string_view value) {
    if (value.size() != 40U && value.size() != 64U) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isxdigit(ch) != 0;
    });
}

bool valid_alpha_version(std::string_view value) {
    if (!value.starts_with(kVersionPrefix) || value.size() == kVersionPrefix.size()) {
        return false;
    }
    return std::all_of(value.begin() + static_cast<std::ptrdiff_t>(kVersionPrefix.size()),
                       value.end(),
                       [](unsigned char ch) { return std::isdigit(ch) != 0; });
}

bool valid_prefixed_sha256(std::string_view value, std::string_view prefix) {
    return value.starts_with(prefix) &&
           value.size() == prefix.size() + 64U &&
           is_sha256(value.substr(prefix.size()));
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

void push_bounded(std::vector<std::string>& out,
                  std::size_t limit,
                  std::string value) {
    if (out.size() < limit) out.push_back(std::move(value));
}

std::vector<AlphaReleaseEvidence> sorted_evidence(
    const std::vector<AlphaReleaseEvidence>& evidence) {
    auto sorted = evidence;
    std::sort(sorted.begin(), sorted.end(),
              [](const AlphaReleaseEvidence& a, const AlphaReleaseEvidence& b) {
                  if (a.name != b.name) return a.name < b.name;
                  if (a.evidence_sha256 != b.evidence_sha256) {
                      return a.evidence_sha256 < b.evidence_sha256;
                  }
                  if (a.passed != b.passed) return a.passed < b.passed;
                  return a.detail < b.detail;
              });
    return sorted;
}

} // namespace

bool AlphaReleaseCertificate::ready() const noexcept {
    return status == AlphaReleaseStatus::Ready;
}

AlphaReleaseGate::AlphaReleaseGate(AlphaReleaseBudget budget)
    : budget_(budget) {}

AlphaReleaseCertificate AlphaReleaseGate::evaluate(
    const AlphaReleaseRequest& request) const {
    AlphaReleaseCertificate certificate;
    certificate.version = request.version;
    certificate.commit_sha = request.commit_sha;
    certificate.source_tree_sha256 = request.source_tree_sha256;
    certificate.ring_release_id = request.ring_release.release_id;

    if (budget_.max_evidence == 0U || budget_.max_blockers == 0U ||
        budget_.max_detail_bytes == 0U) {
        certificate.status = AlphaReleaseStatus::Invalid;
        certificate.blockers.emplace_back("alpha release budget contains a zero ceiling");
        return certificate;
    }
    if (request.evidence.size() > budget_.max_evidence) {
        certificate.status = AlphaReleaseStatus::Invalid;
        certificate.blockers.emplace_back("alpha release evidence count exceeds gate ceiling");
        return certificate;
    }

    std::map<std::string, AlphaReleaseEvidence> evidence_by_name;
    for (const auto& item : request.evidence) {
        if (!valid_text(item.name, 128U) || !is_sha256(item.evidence_sha256) ||
            item.detail.size() > budget_.max_detail_bytes) {
            certificate.status = AlphaReleaseStatus::Invalid;
            certificate.blockers.emplace_back(
                "alpha release evidence contains malformed name/hash/detail");
            return certificate;
        }
        if (!evidence_by_name.emplace(item.name, item).second) {
            certificate.status = AlphaReleaseStatus::Invalid;
            certificate.blockers.emplace_back(
                "duplicate alpha release evidence name: " + item.name);
            return certificate;
        }
    }

    auto check = [&](bool passed, std::string label) {
        ++certificate.checks;
        push_bounded(certificate.trace, budget_.max_blockers,
                     std::string(passed ? "PASS " : "BLOCK ") + label);
        if (!passed) {
            push_bounded(certificate.blockers, budget_.max_blockers, std::move(label));
        }
    };

    check(valid_alpha_version(request.version),
          "version must identify the 0.31.0 alpha line");
    check(valid_commit_sha(request.commit_sha),
          "release commit must be a 40- or 64-hex Git object identity");
    check(is_sha256(request.source_tree_sha256),
          "source tree must have an explicit SHA-256 digest");
    check(request.ring_release.ready(),
          "L26 ring release gate must already be READY");
    check(valid_prefixed_sha256(request.ring_release.release_id, kRingPrefix),
          "ring release identity must be content-addressed");

    bool all_supplied_passed = true;
    for (const auto& item : request.evidence) {
        all_supplied_passed = all_supplied_passed && item.passed;
    }
    check(all_supplied_passed, "all supplied alpha evidence must pass");

    for (const auto& required : required_evidence_names()) {
        const auto it = evidence_by_name.find(required);
        check(it != evidence_by_name.end(),
              "required alpha evidence present: " + required);
        if (it != evidence_by_name.end()) {
            check(it->second.passed,
                  "required alpha evidence passed: " + required);
        }
    }

    certificate.alpha_release_id = std::string(kAlphaPrefix) +
        sha256(canonical_alpha_release_material(request));
    certificate.status = certificate.blockers.empty()
        ? AlphaReleaseStatus::Ready
        : AlphaReleaseStatus::Blocked;
    return certificate;
}

const AlphaReleaseBudget& AlphaReleaseGate::budget() const noexcept {
    return budget_;
}

std::vector<std::string> AlphaReleaseGate::required_evidence_names() {
    return {
        "l27-real-gguf-bridge",
        "l28-offline-kernel-task",
        "l29-benchmark-memory-proof",
        "l30-failure-replay-proof",
        "release-package-build",
    };
}

std::string canonical_alpha_release_material(
    const AlphaReleaseRequest& request) {
    std::ostringstream out;
    append_field(out, "schema", "GOLF-GUFF-ALPHA-V1");
    append_field(out, "version", request.version);
    append_field(out, "commit_sha", request.commit_sha);
    append_field(out, "source_tree_sha256", request.source_tree_sha256);
    append_field(out, "ring_release_status", to_string(request.ring_release.status));
    append_field(out, "ring_release_id", request.ring_release.release_id);

    const auto sorted = sorted_evidence(request.evidence);
    append_number(out, "evidence_count", sorted.size());
    for (const auto& item : sorted) {
        append_field(out, "evidence_name", item.name);
        append_number(out, "evidence_passed", item.passed ? 1 : 0);
        append_field(out, "evidence_sha256", item.evidence_sha256);
        append_field(out, "evidence_detail", item.detail);
    }
    return out.str();
}

std::string_view to_string(AlphaReleaseStatus status) noexcept {
    switch (status) {
    case AlphaReleaseStatus::Ready: return "READY";
    case AlphaReleaseStatus::Blocked: return "BLOCKED";
    case AlphaReleaseStatus::Invalid: return "INVALID";
    }
    return "INVALID";
}

} // namespace guff
