#include "guff/authority_receipt.hpp"
#include "guff/sha256.hpp"

#include <iostream>
#include <optional>
#include <string>
#include <string_view>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "CHECK failed: " #expression << " @ " << __FILE__ << ':' << __LINE__ << '\n'; return 1; } } while (false)

namespace {

class TestSigner final : public guff::AuthoritySigner, public guff::AuthorityVerifier {
public:
    std::string signer_id() const override { return "local:test-signer"; }
    std::string algorithm() const override { return "TEST-SHA256"; }
    std::optional<std::string> sign(std::string_view canonical) const override {
        return guff::sha256(std::string("test-secret\n") + std::string(canonical));
    }
    bool knows(std::string_view signer, std::string_view algorithm_name) const override {
        return signer == signer_id() && algorithm_name == algorithm();
    }
    bool verify(std::string_view signer,
                std::string_view algorithm_name,
                std::string_view canonical,
                std::string_view signature) const override {
        if (!knows(signer, algorithm_name)) return false;
        const auto expected = sign(canonical);
        return expected && *expected == signature;
    }
};

} // namespace

int main() {
    TestSigner signer;
    guff::AuthorityEnvelope envelope;
    envelope.purpose = guff::AuthorityPurpose::Recovery;
    envelope.subject_id = "guff:session:sha256:" + guff::sha256("parent-session");
    envelope.actor_reference = "local-user-confirmation";
    envelope.signer_id = signer.signer_id();
    envelope.issued_at_utc = "2026-09-05T01:00:00Z";
    envelope.nonce = "receipt-001";
    envelope.scope_sha256 = guff::sha256("retry-as-new-session");

    std::vector<std::string> errors;
    const auto receipt = guff::issue_authority_receipt(envelope, signer, &errors);
    CHECK(receipt.has_value());
    CHECK(errors.empty());
    CHECK(receipt->receipt_id.starts_with("guff:authority:sha256:"));
    CHECK(receipt->envelope_sha256 == guff::authority_envelope_sha256(envelope));

    const auto verified = guff::verify_authority_receipt(
        *receipt, signer, guff::AuthorityPurpose::Recovery, envelope.subject_id);
    CHECK(verified.ok());

    auto tampered = *receipt;
    tampered.envelope.scope_sha256 = guff::sha256("different-scope");
    CHECK(guff::verify_authority_receipt(
        tampered, signer, guff::AuthorityPurpose::Recovery, envelope.subject_id).status ==
        guff::AuthorityReceiptStatus::Invalid);

    CHECK(guff::verify_authority_receipt(
        *receipt, signer, guff::AuthorityPurpose::PersistentSymbiosis, envelope.subject_id).status ==
        guff::AuthorityReceiptStatus::PurposeMismatch);

    CHECK(guff::verify_authority_receipt(
        *receipt, signer, guff::AuthorityPurpose::Recovery, "other-subject").status ==
        guff::AuthorityReceiptStatus::SubjectMismatch);

    auto forged = *receipt;
    forged.signature = guff::sha256("forged-signature");
    forged.receipt_id = guff::authority_receipt_id(forged.envelope, forged.algorithm, forged.signature);
    CHECK(guff::verify_authority_receipt(
        forged, signer, guff::AuthorityPurpose::Recovery, envelope.subject_id).status ==
        guff::AuthorityReceiptStatus::SignatureRejected);

    return 0;
}
