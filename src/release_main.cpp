#include "guff/release_gate.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

class RejectAllVerifier final : public guff::AuthorityVerifier {
public:
    bool knows(std::string_view, std::string_view) const override { return false; }
    bool verify(std::string_view,
                std::string_view,
                std::string_view,
                std::string_view) const override {
        return false;
    }
};

std::vector<guff::RingReleaseEvidence> load_evidence(const std::filesystem::path& path,
                                                     std::vector<std::string>* errors) {
    std::vector<guff::RingReleaseEvidence> out;
    if (path.empty()) return out;
    std::ifstream input(path);
    if (!input) {
        if (errors) errors->emplace_back("failed to open release evidence manifest");
        return out;
    }
    std::string line;
    std::size_t line_number = 0U;
    while (std::getline(input, line)) {
        ++line_number;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line.front() == '#') continue;
        std::istringstream parser(line);
        std::string status, name, digest, detail;
        if (!std::getline(parser, status, '\t') ||
            !std::getline(parser, name, '\t') ||
            !std::getline(parser, digest, '\t')) {
            if (errors) errors->push_back("malformed evidence line " + std::to_string(line_number));
            continue;
        }
        std::getline(parser, detail);
        if (status != "PASS" && status != "FAIL") {
            if (errors) errors->push_back("invalid evidence status on line " + std::to_string(line_number));
            continue;
        }
        out.push_back({name, status == "PASS", digest, detail});
    }
    return out;
}

} // namespace

int main(int argc, char** argv) {
    const std::filesystem::path root = argc > 1
        ? std::filesystem::path(argv[1])
        : std::filesystem::current_path();
    const std::filesystem::path evidence_path = argc > 2
        ? std::filesystem::path(argv[2])
        : std::filesystem::path{};

    RejectAllVerifier verifier;
    guff::SignedPolicyRegistry policies(root / "guff-policies.journal", verifier, verifier);
    guff::SessionJournal sessions(root / "guff-transactions.journal");
    guff::AuthorityLedger authority(root / "guff-authority.journal", verifier);
    guff::RuntimeIdentityStore identities(root / "guff-runtime-identities.journal");
    guff::OperatorReviewQueue reviews(root / "guff-operator-reviews.journal");
    guff::OperatorConsole console(policies, sessions, authority, identities, reviews);

    std::vector<std::string> manifest_errors;
    const auto evidence = load_evidence(evidence_path, &manifest_errors);
    const auto snapshot = console.snapshot();
    guff::RingReleaseGate gate;
    auto result = gate.evaluate(snapshot, evidence);
    if (!manifest_errors.empty()) {
        result.status = guff::RingReleaseStatus::Invalid;
        result.blockers.insert(result.blockers.end(), manifest_errors.begin(), manifest_errors.end());
    }

    std::cout << "GOLF GUFF / RING V1 RELEASE GATE L26\n";
    std::cout << "ROOT: " << root.string() << '\n';
    std::cout << "STATUS: " << guff::to_string(result.status) << '\n';
    std::cout << "RELEASE-ID: " << (result.release_id.empty() ? "NONE" : result.release_id) << '\n';
    std::cout << "CHECKS: " << result.checks << '\n';
    for (const auto& blocker : result.blockers) {
        std::cout << "BLOCKER: " << blocker << '\n';
    }
    for (const auto& trace : result.trace) {
        std::cout << "TRACE: " << trace << '\n';
    }
    return result.ready() ? 0 : 2;
}
