#include "guff/operator_console.hpp"

#include "guff/sha256.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <map>
#include <sstream>
#include <system_error>
#include <utility>

namespace guff {
namespace {

constexpr std::string_view kReviewPrefix = "guff:operator-review:sha256:";
constexpr std::string_view kPolicyPrefix = "guff:policy:sha256:";
constexpr std::string_view kRulePrefix = "guff:policy-rule:sha256:";
constexpr std::size_t kMaxLineBytes = 64U * 1024U;

enum class ReviewRecordKind : std::uint8_t { Enqueue, Close };

struct ReviewRecord {
    std::uint32_t schema_version{1U};
    std::size_t sequence{0U};
    ReviewRecordKind kind{ReviewRecordKind::Enqueue};
    OperatorReviewTicket ticket;
    std::string previous_record_sha256;
    std::string record_sha256;
};

struct ReviewScan {
    bool healthy{true};
    std::size_t next_sequence{0U};
    std::string head_sha256{std::string(64U, '0')};
    std::map<std::string, OperatorReviewTicket> tickets;
    std::vector<std::string> errors;
};

bool canonical_id(std::string_view value, std::string_view prefix) noexcept {
    return value.starts_with(prefix) && is_sha256(value.substr(prefix.size()));
}

bool valid_text(std::string_view value, std::size_t max_bytes) {
    if (value.empty() || value.size() > max_bytes) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch >= 0x20U && ch != 0x7fU;
    });
}

std::string hex_encode(std::string_view input) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(input.size() * 2U);
    for (const auto ch : input) {
        const auto value = static_cast<unsigned char>(ch);
        out.push_back(digits[(value >> 4U) & 0x0fU]);
        out.push_back(digits[value & 0x0fU]);
    }
    return out;
}

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

std::string join_rule_ids(const std::vector<std::string>& ids) {
    std::ostringstream out;
    for (std::size_t i = 0U; i < ids.size(); ++i) {
        if (i != 0U) out << ',';
        out << ids[i];
    }
    return out.str();
}

std::optional<std::vector<std::string>> parse_rule_ids(std::string_view joined) {
    std::vector<std::string> out;
    if (joined.empty()) return out;
    std::size_t start = 0U;
    while (start <= joined.size()) {
        const auto next = joined.find(',', start);
        const auto item = next == std::string_view::npos
            ? joined.substr(start)
            : joined.substr(start, next - start);
        if (!canonical_id(item, kRulePrefix)) return std::nullopt;
        out.emplace_back(item);
        if (next == std::string_view::npos) break;
        start = next + 1U;
    }
    return out;
}

std::string canonical_ticket(const OperatorReviewTicket& ticket) {
    std::ostringstream out;
    out << ticket.schema_version << '\n'
        << ticket.policy_id << '\n'
        << ticket.subject_id << '\n'
        << ticket.slot_id << '\n'
        << static_cast<unsigned>(ticket.capability) << '\n'
        << static_cast<unsigned>(ticket.layer) << '\n'
        << static_cast<unsigned>(ticket.risk) << '\n'
        << ticket.reason << '\n'
        << join_rule_ids(ticket.matched_rule_ids) << '\n'
        << ticket.created_at_unix_ms;
    return out.str();
}

std::string ticket_id_for(const OperatorReviewTicket& ticket) {
    return std::string(kReviewPrefix) + sha256(canonical_ticket(ticket));
}

std::string canonical_record(const ReviewRecord& record) {
    const auto& t = record.ticket;
    std::ostringstream out;
    out << record.schema_version << '\n'
        << record.sequence << '\n'
        << static_cast<unsigned>(record.kind) << '\n'
        << t.ticket_id << '\n'
        << t.policy_id << '\n'
        << t.subject_id << '\n'
        << t.slot_id << '\n'
        << static_cast<unsigned>(t.capability) << '\n'
        << static_cast<unsigned>(t.layer) << '\n'
        << static_cast<unsigned>(t.risk) << '\n'
        << t.reason << '\n'
        << join_rule_ids(t.matched_rule_ids) << '\n'
        << t.created_at_unix_ms << '\n'
        << static_cast<unsigned>(t.state) << '\n'
        << t.resolved_at_unix_ms << '\n'
        << t.resolution_note_sha256 << '\n'
        << record.previous_record_sha256;
    return out.str();
}

std::string serialize(const ReviewRecord& record) {
    const auto& t = record.ticket;
    std::ostringstream out;
    out << "OREV\t"
        << record.schema_version << '\t'
        << record.sequence << '\t'
        << static_cast<unsigned>(record.kind) << '\t'
        << t.ticket_id << '\t'
        << (t.policy_id.empty() ? "-" : t.policy_id) << '\t'
        << hex_encode(t.subject_id) << '\t'
        << hex_encode(t.slot_id) << '\t'
        << static_cast<unsigned>(t.capability) << '\t'
        << static_cast<unsigned>(t.layer) << '\t'
        << static_cast<unsigned>(t.risk) << '\t'
        << hex_encode(t.reason) << '\t'
        << hex_encode(join_rule_ids(t.matched_rule_ids)) << '\t'
        << t.created_at_unix_ms << '\t'
        << static_cast<unsigned>(t.state) << '\t'
        << t.resolved_at_unix_ms << '\t'
        << (t.resolution_note_sha256.empty() ? "-" : t.resolution_note_sha256) << '\t'
        << record.previous_record_sha256 << '\t'
        << record.record_sha256;
    return out.str();
}

std::optional<ReviewRecord> deserialize(std::string_view line,
                                        const OperatorReviewQueueBudget& budget,
                                        std::string* error) {
    if (line.empty() || line.size() > kMaxLineBytes) {
        if (error) *error = "operator review record is empty or exceeds line ceiling";
        return std::nullopt;
    }
    const auto fields = split_tabs(line);
    if (fields.size() != 19U || fields[0] != "OREV") {
        if (error) *error = "operator review marker/field count is invalid";
        return std::nullopt;
    }

    ReviewRecord record;
    unsigned kind = 0U, capability = 0U, layer = 0U, risk = 0U, state = 0U;
    if (!parse_unsigned(fields[1], &record.schema_version) ||
        !parse_unsigned(fields[2], &record.sequence) ||
        !parse_unsigned(fields[3], &kind) ||
        !parse_unsigned(fields[8], &capability) ||
        !parse_unsigned(fields[9], &layer) ||
        !parse_unsigned(fields[10], &risk) ||
        !parse_unsigned(fields[13], &record.ticket.created_at_unix_ms) ||
        !parse_unsigned(fields[14], &state) ||
        !parse_unsigned(fields[15], &record.ticket.resolved_at_unix_ms) ||
        record.schema_version != 1U || kind > 1U ||
        state > static_cast<unsigned>(OperatorReviewState::Superseded)) {
        if (error) *error = "operator review numeric/schema field is invalid";
        return std::nullopt;
    }

    auto subject = hex_decode(fields[6]);
    auto slot = hex_decode(fields[7]);
    auto reason = hex_decode(fields[11]);
    auto joined_rules = hex_decode(fields[12]);
    if (!subject || !slot || !reason || !joined_rules) {
        if (error) *error = "operator review hex field is invalid";
        return std::nullopt;
    }
    auto rules = parse_rule_ids(*joined_rules);
    if (!rules) {
        if (error) *error = "operator review matched-rule identity is invalid";
        return std::nullopt;
    }

    record.kind = static_cast<ReviewRecordKind>(kind);
    auto& t = record.ticket;
    t.ticket_id = std::string(fields[4]);
    t.policy_id = fields[5] == "-" ? std::string{} : std::string(fields[5]);
    t.subject_id = std::move(*subject);
    t.slot_id = std::move(*slot);
    t.capability = static_cast<SlotCapability>(capability);
    t.layer = static_cast<RealityLayer>(layer);
    t.risk = static_cast<PolicyRisk>(risk);
    t.reason = std::move(*reason);
    t.matched_rule_ids = std::move(*rules);
    t.state = static_cast<OperatorReviewState>(state);
    t.resolution_note_sha256 = fields[16] == "-" ? std::string{} : std::string(fields[16]);
    record.previous_record_sha256 = std::string(fields[17]);
    record.record_sha256 = std::string(fields[18]);

    if (!canonical_id(t.ticket_id, kReviewPrefix) ||
        !is_sha256(record.previous_record_sha256) || !is_sha256(record.record_sha256)) {
        if (error) *error = "operator review identity/hash field is invalid";
        return std::nullopt;
    }

    if (record.kind == ReviewRecordKind::Enqueue) {
        if (!canonical_id(t.policy_id, kPolicyPrefix) ||
            !valid_text(t.subject_id, 256U) || !valid_text(t.slot_id, 192U) ||
            t.reason.empty() || t.reason.size() > budget.max_reason_bytes ||
            t.matched_rule_ids.size() > budget.max_matched_rules ||
            t.created_at_unix_ms == 0U || t.state != OperatorReviewState::Pending ||
            t.resolved_at_unix_ms != 0U || !t.resolution_note_sha256.empty() ||
            t.ticket_id != ticket_id_for(t)) {
            if (error) *error = "operator review ENQUEUE validation failed";
            return std::nullopt;
        }
    } else {
        if (!t.policy_id.empty() || !t.subject_id.empty() || !t.slot_id.empty() ||
            !t.reason.empty() || !t.matched_rule_ids.empty() || t.created_at_unix_ms != 0U ||
            t.state == OperatorReviewState::Pending || t.resolved_at_unix_ms == 0U ||
            !is_sha256(t.resolution_note_sha256)) {
            if (error) *error = "operator review CLOSE validation failed";
            return std::nullopt;
        }
    }

    if (record.record_sha256 != sha256(canonical_record(record))) {
        if (error) *error = "operator review record hash mismatch";
        return std::nullopt;
    }
    return record;
}

ReviewScan scan_queue(const std::filesystem::path& path,
                      const OperatorReviewQueueBudget& budget) {
    ReviewScan scan;
    std::error_code ec;
    const bool exists = std::filesystem::exists(path, ec);
    if (ec) {
        scan.healthy = false;
        scan.errors.emplace_back("failed to inspect operator review journal path");
        return scan;
    }
    if (!exists) return scan;

    std::ifstream input(path);
    if (!input) {
        scan.healthy = false;
        scan.errors.emplace_back("failed to open operator review journal");
        return scan;
    }

    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (scan.next_sequence >= budget.max_records) {
            scan.healthy = false;
            scan.errors.emplace_back("operator review record ceiling exceeded");
            break;
        }
        std::string error;
        auto record = deserialize(line, budget, &error);
        if (!record) {
            scan.healthy = false;
            scan.errors.push_back("record " + std::to_string(scan.next_sequence) + ": " + error);
            break;
        }
        if (record->sequence != scan.next_sequence ||
            record->previous_record_sha256 != scan.head_sha256) {
            scan.healthy = false;
            scan.errors.emplace_back("operator review sequence/hash-chain discontinuity");
            break;
        }

        if (record->kind == ReviewRecordKind::Enqueue) {
            if (scan.tickets.size() >= budget.max_tickets ||
                scan.tickets.contains(record->ticket.ticket_id)) {
                scan.healthy = false;
                scan.errors.emplace_back("operator review ticket capacity/duplicate violation");
                break;
            }
            scan.tickets.emplace(record->ticket.ticket_id, record->ticket);
        } else {
            const auto it = scan.tickets.find(record->ticket.ticket_id);
            if (it == scan.tickets.end()) {
                scan.healthy = false;
                scan.errors.emplace_back("operator review CLOSE references unknown ticket");
                break;
            }
            if (it->second.state != OperatorReviewState::Pending) {
                scan.healthy = false;
                scan.errors.emplace_back("operator review ticket closed more than once");
                break;
            }
            it->second.state = record->ticket.state;
            it->second.resolved_at_unix_ms = record->ticket.resolved_at_unix_ms;
            it->second.resolution_note_sha256 = record->ticket.resolution_note_sha256;
        }

        scan.head_sha256 = record->record_sha256;
        ++scan.next_sequence;
    }
    if (!input.eof() && input.fail()) {
        scan.healthy = false;
        scan.errors.emplace_back("operator review journal read failed before EOF");
    }
    return scan;
}

OperatorReviewQueueResult append_record(const std::filesystem::path& path,
                                        ReviewRecord record) {
    OperatorReviewQueueResult result;
    const auto parent = path.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            result.status = OperatorConsoleStatus::StorageFailure;
            result.reason = "failed to create operator review journal parent directory";
            return result;
        }
    }
    record.record_sha256 = sha256(canonical_record(record));
    const auto line = serialize(record);
    if (line.size() > kMaxLineBytes) {
        result.status = OperatorConsoleStatus::Invalid;
        result.reason = "serialized operator review record exceeds line ceiling";
        return result;
    }
    std::ofstream output(path, std::ios::app);
    if (!output) {
        result.status = OperatorConsoleStatus::StorageFailure;
        result.reason = "failed to open operator review journal for append";
        return result;
    }
    output << line << '\n';
    output.flush();
    if (!output) {
        result.status = OperatorConsoleStatus::StorageFailure;
        result.reason = "operator review append/flush failed";
        return result;
    }
    result.status = OperatorConsoleStatus::Ready;
    result.ticket_id = record.ticket.ticket_id;
    result.state = record.ticket.state;
    result.record_sha256 = record.record_sha256;
    return result;
}

void append_errors(std::vector<std::string>& target,
                   std::string_view prefix,
                   const std::vector<std::string>& source) {
    for (const auto& error : source) {
        target.emplace_back(std::string(prefix) + error);
    }
}

} // namespace

bool OperatorReviewQueueResult::ok() const noexcept {
    return status == OperatorConsoleStatus::Ready;
}

OperatorReviewQueue::OperatorReviewQueue(std::filesystem::path journal_path,
                                         OperatorReviewQueueBudget budget)
    : journal_path_(std::move(journal_path)), budget_(budget) {}

OperatorReviewQueueResult OperatorReviewQueue::enqueue(
    const PolicyEvaluationResult& result,
    const PolicyEvaluationRequest& request,
    std::uint64_t created_at_unix_ms) {
    OperatorReviewQueueResult out;
    if (result.status != PolicyEvaluationStatus::Decided ||
        result.decision != PolicyDecision::HumanReview) {
        out.status = OperatorConsoleStatus::NotHumanReview;
        out.reason = "only HUMAN_REVIEW policy decisions can enter the operator queue";
        return out;
    }
    if (!canonical_id(result.policy_id, kPolicyPrefix) ||
        classify_policy_risk(request.operation) != result.risk ||
        !valid_text(request.operation.subject_id, 256U) ||
        !valid_text(request.operation.slot_id, 192U) || created_at_unix_ms == 0U ||
        result.reason.empty() || result.reason.size() > budget_.max_reason_bytes ||
        result.matched_rule_ids.size() > budget_.max_matched_rules) {
        out.status = OperatorConsoleStatus::Invalid;
        out.reason = "human-review ticket facts are malformed or exceed queue budget";
        return out;
    }
    for (const auto& id : result.matched_rule_ids) {
        if (!canonical_id(id, kRulePrefix)) {
            out.status = OperatorConsoleStatus::Invalid;
            out.reason = "human-review ticket contains invalid matched-rule identity";
            return out;
        }
    }

    const auto scan = scan_queue(journal_path_, budget_);
    if (!scan.healthy) {
        out.status = OperatorConsoleStatus::Corrupt;
        out.reason = scan.errors.empty() ? "operator review queue is unhealthy" : scan.errors.front();
        return out;
    }
    if (scan.next_sequence >= budget_.max_records || scan.tickets.size() >= budget_.max_tickets) {
        out.status = OperatorConsoleStatus::QueueFull;
        out.reason = "operator review queue capacity reached";
        return out;
    }

    OperatorReviewTicket ticket;
    ticket.policy_id = result.policy_id;
    ticket.subject_id = request.operation.subject_id;
    ticket.slot_id = request.operation.slot_id;
    ticket.capability = request.operation.capability;
    ticket.layer = request.operation.layer;
    ticket.risk = result.risk;
    ticket.reason = result.reason;
    ticket.matched_rule_ids = result.matched_rule_ids;
    ticket.created_at_unix_ms = created_at_unix_ms;
    ticket.ticket_id = ticket_id_for(ticket);
    if (scan.tickets.contains(ticket.ticket_id)) {
        out.status = OperatorConsoleStatus::AlreadyClosed;
        out.ticket_id = ticket.ticket_id;
        out.reason = "identical human-review ticket already exists";
        return out;
    }

    ReviewRecord record;
    record.sequence = scan.next_sequence;
    record.kind = ReviewRecordKind::Enqueue;
    record.ticket = std::move(ticket);
    record.previous_record_sha256 = scan.head_sha256;
    return append_record(journal_path_, std::move(record));
}

OperatorReviewQueueResult OperatorReviewQueue::close(
    std::string_view ticket_id,
    OperatorReviewState state,
    std::uint64_t resolved_at_unix_ms,
    std::string_view resolution_note_sha256) {
    OperatorReviewQueueResult out;
    if (!canonical_id(ticket_id, kReviewPrefix) || state == OperatorReviewState::Pending ||
        resolved_at_unix_ms == 0U || !is_sha256(resolution_note_sha256)) {
        out.status = OperatorConsoleStatus::Invalid;
        out.reason = "review close request is malformed; closure cannot grant ALLOW";
        return out;
    }
    const auto scan = scan_queue(journal_path_, budget_);
    if (!scan.healthy) {
        out.status = OperatorConsoleStatus::Corrupt;
        out.reason = scan.errors.empty() ? "operator review queue is unhealthy" : scan.errors.front();
        return out;
    }
    if (scan.next_sequence >= budget_.max_records) {
        out.status = OperatorConsoleStatus::QueueFull;
        out.reason = "operator review record ceiling reached";
        return out;
    }
    const auto it = scan.tickets.find(std::string(ticket_id));
    if (it == scan.tickets.end()) {
        out.status = OperatorConsoleStatus::NotFound;
        out.reason = "review ticket not found";
        return out;
    }
    if (it->second.state != OperatorReviewState::Pending) {
        out.status = OperatorConsoleStatus::AlreadyClosed;
        out.ticket_id = std::string(ticket_id);
        out.state = it->second.state;
        out.reason = "review ticket is already closed";
        return out;
    }

    ReviewRecord record;
    record.sequence = scan.next_sequence;
    record.kind = ReviewRecordKind::Close;
    record.ticket.ticket_id = std::string(ticket_id);
    record.ticket.state = state;
    record.ticket.resolved_at_unix_ms = resolved_at_unix_ms;
    record.ticket.resolution_note_sha256 = std::string(resolution_note_sha256);
    record.previous_record_sha256 = scan.head_sha256;
    return append_record(journal_path_, std::move(record));
}

OperatorReviewQueueInspection OperatorReviewQueue::inspect() const {
    const auto scan = scan_queue(journal_path_, budget_);
    OperatorReviewQueueInspection out;
    out.healthy = scan.healthy;
    out.records = scan.next_sequence;
    out.tickets = scan.tickets.size();
    out.errors = scan.errors;
    for (const auto& [_, ticket] : scan.tickets) {
        switch (ticket.state) {
        case OperatorReviewState::Pending:
            ++out.pending;
            out.pending_tickets.push_back(ticket);
            break;
        case OperatorReviewState::Deferred: ++out.deferred; break;
        case OperatorReviewState::Refused: ++out.refused; break;
        case OperatorReviewState::Superseded: ++out.superseded; break;
        }
    }
    std::sort(out.pending_tickets.begin(), out.pending_tickets.end(),
              [](const OperatorReviewTicket& a, const OperatorReviewTicket& b) {
                  if (a.created_at_unix_ms != b.created_at_unix_ms)
                      return a.created_at_unix_ms < b.created_at_unix_ms;
                  return a.ticket_id < b.ticket_id;
              });
    return out;
}

std::optional<OperatorReviewTicket> OperatorReviewQueue::ticket(
    std::string_view ticket_id) const {
    const auto scan = scan_queue(journal_path_, budget_);
    if (!scan.healthy) return std::nullopt;
    const auto it = scan.tickets.find(std::string(ticket_id));
    if (it == scan.tickets.end()) return std::nullopt;
    return it->second;
}

const std::filesystem::path& OperatorReviewQueue::journal_path() const noexcept {
    return journal_path_;
}

OperatorConsole::OperatorConsole(SignedPolicyRegistry& policy_registry,
                                 SessionJournal& session_journal,
                                 AuthorityLedger& authority_ledger,
                                 RuntimeIdentityStore& identity_store,
                                 OperatorReviewQueue& review_queue) noexcept
    : policy_registry_(policy_registry),
      session_journal_(session_journal),
      authority_ledger_(authority_ledger),
      identity_store_(identity_store),
      review_queue_(review_queue) {}

OperatorConsoleSnapshot OperatorConsole::snapshot() const {
    OperatorConsoleSnapshot out;
    out.policy = policy_registry_.inspect();
    out.recovery = session_journal_.inspect();
    out.authority = authority_ledger_.inspect();
    out.identities = identity_store_.inspect();
    out.reviews = review_queue_.inspect();

    out.healthy = out.policy.healthy && out.recovery.healthy && out.authority.healthy &&
                  out.identities.healthy && out.reviews.healthy;
    append_errors(out.errors, "policy: ", out.policy.errors);
    append_errors(out.errors, "recovery: ", out.recovery.errors);
    append_errors(out.errors, "authority: ", out.authority.errors);
    append_errors(out.errors, "identity: ", out.identities.errors);
    append_errors(out.errors, "review: ", out.reviews.errors);

    if (out.policy.healthy && !out.policy.active_policy_id.empty()) {
        auto package = policy_registry_.package(out.policy.active_policy_id);
        if (!package) {
            out.healthy = false;
            out.errors.emplace_back("policy: active package provenance could not be reconstructed");
        } else {
            out.active_policy = ActivePolicyProvenance{
                .policy_id = package->policy_id,
                .package_id = package->package_id,
                .signer_id = package->signer_id,
                .algorithm = package->algorithm,
                .signed_at_unix_ms = package->signed_at_unix_ms,
            };
        }
    }
    return out;
}

OperatorReviewQueueResult OperatorConsole::enqueue_review(
    const PolicyEvaluationResult& result,
    const PolicyEvaluationRequest& request,
    std::uint64_t created_at_unix_ms) {
    const auto policy = policy_registry_.inspect();
    if (!policy.healthy) {
        return {OperatorConsoleStatus::Corrupt, {}, OperatorReviewState::Pending, {},
                "active policy registry is unhealthy"};
    }
    if (policy.active_policy_id.empty() || policy.active_policy_id != result.policy_id) {
        return {OperatorConsoleStatus::Invalid, {}, OperatorReviewState::Pending, {},
                "review decision does not belong to the currently active policy"};
    }
    return review_queue_.enqueue(result, request, created_at_unix_ms);
}

std::optional<SignedPolicyControl> OperatorConsole::issue_policy_control(
    const OperatorPolicyControlRequest& request,
    const AuthoritySigner& signer,
    std::vector<std::string>* errors) const {
    std::vector<std::string> local;
    const auto snapshot = policy_registry_.inspect();
    if (!snapshot.healthy) local.emplace_back("policy registry is unhealthy");
    if (!canonical_id(request.policy_id, kPolicyPrefix))
        local.emplace_back("operator policy_id is invalid");
    if (!valid_text(request.actor_reference, 256U))
        local.emplace_back("operator actor_reference is invalid");
    if (request.issued_at_unix_ms == 0U)
        local.emplace_back("operator issued_at_unix_ms must be nonzero");
    if (!valid_text(request.nonce, 128U)) local.emplace_back("operator nonce is invalid");
    if (!valid_text(request.reason, 1024U)) local.emplace_back("operator reason is invalid");

    auto package = local.empty() ? policy_registry_.package(request.policy_id) : std::nullopt;
    if (local.empty() && !package) local.emplace_back("operator target policy/package is not registered");
    if (!local.empty()) {
        if (errors) *errors = std::move(local);
        return std::nullopt;
    }

    PolicyControlEnvelope envelope;
    envelope.action = request.action;
    envelope.package_id = package->package_id;
    envelope.policy_id = package->policy_id;
    envelope.expected_active_policy_id = snapshot.active_policy_id;
    envelope.actor_reference = request.actor_reference;
    envelope.issued_at_unix_ms = request.issued_at_unix_ms;
    envelope.nonce = request.nonce;
    envelope.reason_sha256 = sha256(request.reason);

    auto control = issue_signed_policy_control(envelope, signer, &local);
    if (!control && errors) *errors = std::move(local);
    return control;
}

PolicyRegistryResult OperatorConsole::apply_policy_control(
    const SignedPolicyControl& control) {
    return policy_registry_.apply_control(control);
}

std::string_view to_string(OperatorReviewState state) noexcept {
    switch (state) {
    case OperatorReviewState::Pending: return "PENDING";
    case OperatorReviewState::Deferred: return "DEFERRED";
    case OperatorReviewState::Refused: return "REFUSED";
    case OperatorReviewState::Superseded: return "SUPERSEDED";
    }
    return "PENDING";
}

std::string_view to_string(OperatorConsoleStatus status) noexcept {
    switch (status) {
    case OperatorConsoleStatus::Ready: return "READY";
    case OperatorConsoleStatus::Invalid: return "INVALID";
    case OperatorConsoleStatus::NotHumanReview: return "NOT_HUMAN_REVIEW";
    case OperatorConsoleStatus::QueueFull: return "QUEUE_FULL";
    case OperatorConsoleStatus::NotFound: return "NOT_FOUND";
    case OperatorConsoleStatus::AlreadyClosed: return "ALREADY_CLOSED";
    case OperatorConsoleStatus::StorageFailure: return "STORAGE_FAILURE";
    case OperatorConsoleStatus::Corrupt: return "CORRUPT";
    case OperatorConsoleStatus::SigningFailed: return "SIGNING_FAILED";
    }
    return "INVALID";
}

} // namespace guff
