#include "guff/alpha_release.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

bool split_key_value(const std::string& line,
                     std::string* key,
                     std::string* value) {
    const auto pos = line.find('=');
    if (pos == std::string::npos || pos == 0U) return false;
    if (key) *key = line.substr(0U, pos);
    if (value) *value = line.substr(pos + 1U);
    return true;
}

bool parse_evidence_line(const std::string& line,
                         guff::AlphaReleaseEvidence* evidence) {
    if (!evidence) return false;
    std::istringstream parser(line);
    std::string status;
    std::string name;
    std::string digest;
    std::string detail;
    if (!std::getline(parser, status, '\t') ||
        !std::getline(parser, name, '\t') ||
        !std::getline(parser, digest, '\t')) {
        return false;
    }
    std::getline(parser, detail);
    if (status != "PASS" && status != "FAIL") return false;
    evidence->name = std::move(name);
    evidence->passed = status == "PASS";
    evidence->evidence_sha256 = std::move(digest);
    evidence->detail = std::move(detail);
    return true;
}

bool load_manifest(const std::filesystem::path& path,
                   guff::AlphaReleaseRequest* request,
                   std::vector<std::string>* errors) {
    if (!request) return false;
    std::ifstream input(path);
    if (!input) {
        if (errors) errors->emplace_back("failed to open alpha evidence manifest");
        return false;
    }

    std::string line;
    if (!std::getline(input, line)) {
        if (errors) errors->emplace_back("alpha evidence manifest is empty");
        return false;
    }
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line != "GOLF-GUFF-ALPHA-EVIDENCE-V1") {
        if (errors) errors->emplace_back("alpha evidence manifest has wrong schema header");
        return false;
    }

    bool saw_version = false;
    bool saw_commit = false;
    bool saw_tree = false;
    bool saw_ring_status = false;
    bool saw_ring_id = false;
    std::size_t line_number = 1U;

    while (std::getline(input, line)) {
        ++line_number;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line.front() == '#') continue;

        if (line.starts_with("PASS\t") || line.starts_with("FAIL\t")) {
            guff::AlphaReleaseEvidence evidence;
            if (!parse_evidence_line(line, &evidence)) {
                if (errors) errors->push_back(
                    "malformed alpha evidence line " + std::to_string(line_number));
                continue;
            }
            request->evidence.push_back(std::move(evidence));
            continue;
        }

        std::string key;
        std::string value;
        if (!split_key_value(line, &key, &value)) {
            if (errors) errors->push_back(
                "malformed alpha manifest field on line " +
                std::to_string(line_number));
            continue;
        }

        if (key == "version") {
            if (saw_version) {
                if (errors) errors->emplace_back("duplicate version field");
                continue;
            }
            saw_version = true;
            request->version = std::move(value);
        } else if (key == "commit_sha") {
            if (saw_commit) {
                if (errors) errors->emplace_back("duplicate commit_sha field");
                continue;
            }
            saw_commit = true;
            request->commit_sha = std::move(value);
        } else if (key == "source_tree_sha256") {
            if (saw_tree) {
                if (errors) errors->emplace_back("duplicate source_tree_sha256 field");
                continue;
            }
            saw_tree = true;
            request->source_tree_sha256 = std::move(value);
        } else if (key == "ring_release_status") {
            if (saw_ring_status) {
                if (errors) errors->emplace_back("duplicate ring_release_status field");
                continue;
            }
            saw_ring_status = true;
            if (value == "READY") {
                request->ring_release.status = guff::RingReleaseStatus::Ready;
            } else if (value == "BLOCKED") {
                request->ring_release.status = guff::RingReleaseStatus::Blocked;
            } else if (value == "INVALID") {
                request->ring_release.status = guff::RingReleaseStatus::Invalid;
            } else if (errors) {
                errors->emplace_back("invalid ring_release_status value");
            }
        } else if (key == "ring_release_id") {
            if (saw_ring_id) {
                if (errors) errors->emplace_back("duplicate ring_release_id field");
                continue;
            }
            saw_ring_id = true;
            request->ring_release.release_id = std::move(value);
        } else if (errors) {
            errors->push_back("unknown alpha manifest field: " + key);
        }
    }

    if (!saw_version && errors) errors->emplace_back("missing version field");
    if (!saw_commit && errors) errors->emplace_back("missing commit_sha field");
    if (!saw_tree && errors) errors->emplace_back("missing source_tree_sha256 field");
    if (!saw_ring_status && errors) errors->emplace_back("missing ring_release_status field");
    if (!saw_ring_id && errors) errors->emplace_back("missing ring_release_id field");
    return errors ? errors->empty() : true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: GOLF-GUFF-ALPHA-CHECK <alpha-evidence-manifest>\n";
        return 2;
    }

    guff::AlphaReleaseRequest request;
    std::vector<std::string> errors;
    const auto manifest_path = std::filesystem::path(argv[1]);
    const bool loaded = load_manifest(manifest_path, &request, &errors);

    guff::AlphaReleaseCertificate certificate;
    if (loaded) {
        guff::AlphaReleaseGate gate;
        certificate = gate.evaluate(request);
    } else {
        certificate.status = guff::AlphaReleaseStatus::Invalid;
        certificate.version = request.version;
        certificate.commit_sha = request.commit_sha;
        certificate.source_tree_sha256 = request.source_tree_sha256;
        certificate.ring_release_id = request.ring_release.release_id;
        certificate.blockers = errors;
    }

    std::cout << "GOLF GUFF / ALPHA RELEASE CHECK L31\n";
    std::cout << "MANIFEST: " << manifest_path.string() << '\n';
    std::cout << "STATUS: " << guff::to_string(certificate.status) << '\n';
    std::cout << "ALPHA-RELEASE-ID: "
              << (certificate.alpha_release_id.empty()
                      ? "NONE"
                      : certificate.alpha_release_id)
              << '\n';
    std::cout << "VERSION: " << certificate.version << '\n';
    std::cout << "COMMIT: " << certificate.commit_sha << '\n';
    std::cout << "SOURCE-TREE-SHA256: " << certificate.source_tree_sha256 << '\n';
    std::cout << "RING-RELEASE-ID: " << certificate.ring_release_id << '\n';
    std::cout << "CHECKS: " << certificate.checks << '\n';
    for (const auto& blocker : certificate.blockers) {
        std::cout << "BLOCKER: " << blocker << '\n';
    }
    for (const auto& trace : certificate.trace) {
        std::cout << "TRACE: " << trace << '\n';
    }

    return certificate.ready() ? 0 : 2;
}
