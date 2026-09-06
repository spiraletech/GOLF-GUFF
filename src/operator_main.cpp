#include "guff/operator_console.hpp"

#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>

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

} // namespace

int main(int argc, char** argv) {
    const std::filesystem::path root = argc > 1
        ? std::filesystem::path(argv[1])
        : std::filesystem::current_path();

    RejectAllVerifier verifier;
    guff::SignedPolicyRegistry policies(root / "guff-policies.journal", verifier, verifier);
    guff::SessionJournal sessions(root / "guff-transactions.journal");
    guff::AuthorityLedger authority(root / "guff-authority.journal", verifier);
    guff::RuntimeIdentityStore identities(root / "guff-runtime-identities.journal");
    guff::OperatorReviewQueue reviews(root / "guff-operator-reviews.journal");
    guff::OperatorConsole console(policies, sessions, authority, identities, reviews);

    const auto state = console.snapshot();
    std::cout << "GOLF GUFF / OPERATOR L25\n";
    std::cout << "ROOT: " << root.string() << '\n';
    std::cout << "HEALTH: " << (state.healthy ? "GREEN" : "REFUSE") << '\n';
    std::cout << "POLICY: records=" << state.policy.records
              << " registered=" << state.policy.registered_policies
              << " revoked=" << state.policy.revoked_policies
              << " generation=" << state.policy.activation_generation
              << " active=" << (state.policy.active_policy_id.empty() ? "NONE" : state.policy.active_policy_id)
              << '\n';
    if (state.active_policy) {
        std::cout << "POLICY-PROVENANCE: package=" << state.active_policy->package_id
                  << " signer=" << state.active_policy->signer_id
                  << " algorithm=" << state.active_policy->algorithm
                  << " signed_at_ms=" << state.active_policy->signed_at_unix_ms << '\n';
    }
    std::cout << "RECOVERY: records=" << state.recovery.records
              << " interrupted=" << state.recovery.interrupted.size()
              << " lineage=" << state.recovery.recovery_lineage.size() << '\n';
    std::cout << "AUTHORITY: records=" << state.authority.records
              << " trusted_keys=" << state.authority.trusted_keys
              << " consumed_receipts=" << state.authority.consumed_receipts
              << " revoked_receipts=" << state.authority.revoked_receipts
              << " delegated_receipts=" << state.authority.delegated_receipts << '\n';
    std::cout << "IDENTITY: records=" << state.identities.records
              << " devices=" << state.identities.devices
              << " images=" << state.identities.executables
              << " processes=" << state.identities.processes
              << " attestations=" << state.identities.attestations
              << " revoked=" << (state.identities.revoked_devices +
                                    state.identities.revoked_executables +
                                    state.identities.revoked_processes) << '\n';
    std::cout << "REVIEWS: records=" << state.reviews.records
              << " tickets=" << state.reviews.tickets
              << " pending=" << state.reviews.pending
              << " deferred=" << state.reviews.deferred
              << " refused=" << state.reviews.refused
              << " superseded=" << state.reviews.superseded << '\n';

    for (const auto& ticket : state.reviews.pending_tickets) {
        std::cout << "REVIEW " << ticket.ticket_id
                  << " risk=" << guff::to_string(ticket.risk)
                  << " capability=" << guff::to_string(ticket.capability)
                  << " subject=" << ticket.subject_id
                  << " reason=" << ticket.reason << '\n';
    }
    for (const auto& error : state.errors) {
        std::cout << "ERROR: " << error << '\n';
    }

    return state.healthy ? 0 : 2;
}
