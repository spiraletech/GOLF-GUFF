#include "guff/operator_console.hpp"
#include "guff/sha256.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#define CHECK(expression) do { if (!(expression)) { std::cerr << "CHECK failed: " #expression << " @ " << __FILE__ << ':' << __LINE__ << '\n'; return 1; } } while (false)

namespace {

std::string read_bytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

bool write_bytes(const std::filesystem::path& path, const std::string& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(output);
}

guff::PolicyEvaluationRequest review_request() {
    guff::PolicyEvaluationRequest request;
    request.operation.subject_id = "project:spiraletech/GOLF-GUFF";
    request.operation.slot_id = "forge.generic";
    request.operation.capability = guff::SlotCapability::GenericTool;
    request.operation.layer = guff::RealityLayer::Project;
    request.operation.requires_identity = false;
    request.operation.requires_authority = false;
    return request;
}

guff::PolicyEvaluationResult review_result(const guff::PolicyEvaluationRequest& request) {
    guff::PolicyEvaluationResult result;
    result.status = guff::PolicyEvaluationStatus::Decided;
    result.decision = guff::PolicyDecision::HumanReview;
    result.risk = guff::classify_policy_risk(request.operation);
    result.policy_id = "guff:policy:sha256:" + guff::sha256("l26-adversarial-policy");
    result.reason = "high-risk generic tool requires operator review";
    result.matched_rule_ids = {
        "guff:policy-rule:sha256:" + guff::sha256("l26-review-rule")
    };
    return result;
}

template <typename Inspector>
bool run_byte_mutation_corpus(const std::filesystem::path& original,
                              const std::filesystem::path& scratch,
                              Inspector unhealthy,
                              std::size_t max_mutations) {
    const auto bytes = read_bytes(original);
    if (bytes.empty()) return false;
    std::size_t mutations = 0U;
    for (std::size_t i = 0U; i < bytes.size() && mutations < max_mutations; ++i) {
        if (bytes[i] == '\n' || bytes[i] == '\r') continue;
        auto changed = bytes;
        changed[i] = changed[i] == 'X' ? 'Y' : 'X';
        if (!write_bytes(scratch, changed) || !unhealthy(scratch)) return false;
        ++mutations;
    }
    return mutations > 0U;
}

} // namespace

int main() {
    const auto root = std::filesystem::absolute(
        std::filesystem::temp_directory_path() / "guff-l26-adversarial");
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);
    CHECK(!ec);

    // Build a valid operator-review journal, then mutate its serialized cold state.
    const auto review_path = root / "reviews.journal";
    guff::OperatorReviewQueue reviews(review_path);
    const auto request = review_request();
    const auto decision = review_result(request);
    CHECK(reviews.enqueue(decision, request, 1'725'700'000'000ULL).ok());
    CHECK(reviews.inspect().healthy);

    const auto review_scratch = root / "reviews-mutated.journal";
    CHECK(run_byte_mutation_corpus(
        review_path,
        review_scratch,
        [](const std::filesystem::path& path) {
            guff::OperatorReviewQueue mutated(path);
            return !mutated.inspect().healthy;
        },
        96U));

    auto review_bytes = read_bytes(review_path);
    CHECK(review_bytes.size() > 8U);
    CHECK(write_bytes(review_scratch, review_bytes.substr(0U, review_bytes.size() - 7U)));
    CHECK(!guff::OperatorReviewQueue(review_scratch).inspect().healthy);
    CHECK(write_bytes(review_scratch, review_bytes + review_bytes));
    CHECK(!guff::OperatorReviewQueue(review_scratch).inspect().healthy);
    CHECK(write_bytes(review_scratch, review_bytes + "GARBAGE-L26-TAIL\n"));
    CHECK(!guff::OperatorReviewQueue(review_scratch).inspect().healthy);

    // Repeat the mutation campaign against the transaction journal grammar.
    const auto tx_path = root / "transactions.journal";
    guff::SessionJournal transactions(tx_path);
    guff::JournalBegin begin;
    begin.session_id = "guff:session:sha256:" + guff::sha256("l26-session");
    begin.correlation_id = "l26-correlation";
    begin.request_sha256 = guff::sha256("l26-request");
    begin.recorded_at_utc = "2026-09-06T05:40:00Z";
    CHECK(transactions.begin(begin).ok());
    CHECK(transactions.inspect().healthy);

    const auto tx_scratch = root / "transactions-mutated.journal";
    CHECK(run_byte_mutation_corpus(
        tx_path,
        tx_scratch,
        [](const std::filesystem::path& path) {
            guff::SessionJournal mutated(path);
            return !mutated.inspect().healthy;
        },
        96U));

    auto tx_bytes = read_bytes(tx_path);
    CHECK(tx_bytes.size() > 8U);
    CHECK(write_bytes(tx_scratch, tx_bytes.substr(0U, tx_bytes.size() - 5U)));
    CHECK(!guff::SessionJournal(tx_scratch).inspect().healthy);
    CHECK(write_bytes(tx_scratch, tx_bytes + tx_bytes));
    CHECK(!guff::SessionJournal(tx_scratch).inspect().healthy);
    CHECK(write_bytes(tx_scratch, tx_bytes + "CORRUPTED-L26-TAIL\n"));
    CHECK(!guff::SessionJournal(tx_scratch).inspect().healthy);

    // Storage failure injection: make the would-be journal parent a regular file.
    const auto blocked_parent = root / "blocked-parent";
    CHECK(write_bytes(blocked_parent, "not-a-directory"));

    guff::OperatorReviewQueue blocked_reviews(blocked_parent / "reviews.journal");
    const auto blocked_review = blocked_reviews.enqueue(
        decision, request, 1'725'700'000'100ULL);
    CHECK(blocked_review.status == guff::OperatorConsoleStatus::StorageFailure);

    guff::SessionJournal blocked_transactions(blocked_parent / "transactions.journal");
    auto blocked_begin = begin;
    blocked_begin.session_id = "guff:session:sha256:" + guff::sha256("blocked-session");
    blocked_begin.correlation_id = "blocked-correlation";
    const auto blocked_tx = blocked_transactions.begin(blocked_begin);
    CHECK(blocked_tx.status == guff::JournalStatus::StorageError);

    // Failure injection must not create child journal files or mutate the valid originals.
    CHECK(!std::filesystem::exists(blocked_parent / "reviews.journal", ec));
    ec.clear();
    CHECK(!std::filesystem::exists(blocked_parent / "transactions.journal", ec));
    CHECK(guff::OperatorReviewQueue(review_path).inspect().healthy);
    CHECK(guff::SessionJournal(tx_path).inspect().healthy);

    std::filesystem::remove_all(root, ec);
    return 0;
}
