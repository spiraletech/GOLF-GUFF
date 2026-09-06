#include "guff/runtime_attestation.hpp"

#include "guff/hardware_profile.hpp"
#include "guff/sha256.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <fstream>
#include <limits>
#include <sstream>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <winreg.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

namespace guff {
namespace {

constexpr std::string_view kAttestationPrefix = "guff:attestation:sha256:";
constexpr std::string_view kHardwarePrefix = "guff:hardware:sha256:";
constexpr std::string_view kSessionPrefix = "guff:session:sha256:";
constexpr std::uint64_t kProviderMaxAgeMs = 10'000U;

std::uint64_t system_now_ms() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

bool valid_token(std::string_view value, std::size_t max_bytes = 256U) {
    if (value.empty() || value.size() > max_bytes) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' ||
               ch == '.' || ch == ':' || ch == '/';
    });
}

bool prefixed_sha256(std::string_view value, std::string_view prefix) {
    return value.starts_with(prefix) && is_sha256(value.substr(prefix.size()));
}

std::string trim_ascii(std::string value) {
    while (!value.empty() &&
           (value.back() == '\r' || value.back() == '\n' ||
            value.back() == ' ' || value.back() == '\t')) {
        value.pop_back();
    }
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    if (first > 0U) value.erase(0U, first);
    return value;
}

std::optional<std::string> read_first_line(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return std::nullopt;
    std::string line;
    std::getline(input, line);
    line = trim_ascii(std::move(line));
    if (line.empty()) return std::nullopt;
    return line;
}

struct NativeMeasurements {
    RuntimeAttestationTrust trust{RuntimeAttestationTrust::NativeOsLocal};
    std::string device_id;
    std::filesystem::path executable_path;
    std::string executable_sha256;
    std::uint64_t process_id{0U};
    std::uint64_t process_started_unix_ms{0U};
};

#if defined(_WIN32)
std::optional<std::string> wide_to_utf8(std::wstring_view value) {
    if (value.empty()) return std::string{};
    const int bytes = WideCharToMultiByte(CP_UTF8,
                                          WC_ERR_INVALID_CHARS,
                                          value.data(),
                                          static_cast<int>(value.size()),
                                          nullptr,
                                          0,
                                          nullptr,
                                          nullptr);
    if (bytes <= 0) return std::nullopt;
    std::string out(static_cast<std::size_t>(bytes), '\0');
    if (WideCharToMultiByte(CP_UTF8,
                            WC_ERR_INVALID_CHARS,
                            value.data(),
                            static_cast<int>(value.size()),
                            out.data(),
                            bytes,
                            nullptr,
                            nullptr) != bytes) {
        return std::nullopt;
    }
    return out;
}

std::optional<std::filesystem::path> native_executable_path() {
    std::vector<wchar_t> buffer(512U);
    for (unsigned attempt = 0U; attempt < 8U; ++attempt) {
        const DWORD length = GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0U) return std::nullopt;
        if (length < buffer.size() - 1U) {
            return std::filesystem::path(std::wstring(buffer.data(), length));
        }
        buffer.resize(buffer.size() * 2U);
    }
    return std::nullopt;
}

std::optional<std::string> windows_machine_guid() {
    HKEY key = nullptr;
    const LONG opened = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Cryptography",
        0,
        KEY_READ | KEY_WOW64_64KEY,
        &key);
    if (opened != ERROR_SUCCESS || !key) return std::nullopt;

    DWORD type = 0U;
    DWORD bytes = 0U;
    LONG status = RegQueryValueExW(
        key, L"MachineGuid", nullptr, &type, nullptr, &bytes);
    if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) ||
        bytes < sizeof(wchar_t)) {
        RegCloseKey(key);
        return std::nullopt;
    }

    std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 1U, L'\0');
    status = RegQueryValueExW(
        key,
        L"MachineGuid",
        nullptr,
        &type,
        reinterpret_cast<LPBYTE>(buffer.data()),
        &bytes);
    RegCloseKey(key);
    if (status != ERROR_SUCCESS) return std::nullopt;

    const std::wstring value(buffer.data());
    auto utf8 = wide_to_utf8(value);
    if (!utf8) return std::nullopt;
    *utf8 = trim_ascii(std::move(*utf8));
    if (utf8->empty()) return std::nullopt;
    return utf8;
}

std::optional<std::string> windows_host_fallback() {
    std::vector<wchar_t> buffer(MAX_COMPUTERNAME_LENGTH + 1U, L'\0');
    DWORD size = static_cast<DWORD>(buffer.size());
    if (!GetComputerNameW(buffer.data(), &size) || size == 0U) return std::nullopt;
    return wide_to_utf8(std::wstring_view(buffer.data(), size));
}

std::optional<std::uint64_t> native_process_start_ms() {
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) {
        return std::nullopt;
    }
    ULARGE_INTEGER value{};
    value.LowPart = creation.dwLowDateTime;
    value.HighPart = creation.dwHighDateTime;
    constexpr std::uint64_t kUnixEpochFileTime = 116444736000000000ULL;
    if (value.QuadPart < kUnixEpochFileTime) return std::nullopt;
    return (value.QuadPart - kUnixEpochFileTime) / 10'000ULL;
}

std::optional<NativeMeasurements> collect_native_measurements(
    RuntimeAttestationStatus* failure_status,
    std::string* error) {
    NativeMeasurements result;

    auto executable = native_executable_path();
    if (!executable) {
        if (failure_status) *failure_status = RuntimeAttestationStatus::ExecutableMeasurementFailed;
        if (error) *error = "Windows failed to resolve the current executable path";
        return std::nullopt;
    }
    auto executable_digest = sha256_file(*executable);
    if (!executable_digest) {
        if (failure_status) *failure_status = RuntimeAttestationStatus::ExecutableMeasurementFailed;
        if (error) *error = "Windows failed to hash the current executable";
        return std::nullopt;
    }

    std::string machine_material;
    if (auto guid = windows_machine_guid()) {
        machine_material = "machine-guid\n" + *guid;
    } else if (auto host = windows_host_fallback()) {
        result.trust = RuntimeAttestationTrust::NativeOsLocalDegraded;
        machine_material = "host-fallback\n" + *host + "\n" +
                           detect_hardware_profile().canonical_payload();
    } else {
        if (failure_status) *failure_status = RuntimeAttestationStatus::DeviceMeasurementFailed;
        if (error) *error = "Windows failed to derive a local machine identity";
        return std::nullopt;
    }

    auto started = native_process_start_ms();
    if (!started) {
        if (failure_status) *failure_status = RuntimeAttestationStatus::ProcessMeasurementFailed;
        if (error) *error = "Windows failed to read the current process creation time";
        return std::nullopt;
    }

    result.device_id = std::string(kHardwarePrefix) +
                       sha256("native-runtime-device-v1\nwindows\n" + machine_material);
    result.executable_path = std::move(*executable);
    result.executable_sha256 = std::move(*executable_digest);
    result.process_id = static_cast<std::uint64_t>(GetCurrentProcessId());
    result.process_started_unix_ms = *started;
    return result;
}

#elif defined(__linux__)
std::optional<std::filesystem::path> native_executable_path() {
    std::error_code ec;
    auto path = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (ec || path.empty()) return std::nullopt;
    return path;
}

std::optional<std::string> linux_machine_id() {
    if (auto value = read_first_line("/etc/machine-id")) return value;
    return read_first_line("/var/lib/dbus/machine-id");
}

std::optional<std::string> linux_host_fallback() {
    std::vector<char> buffer(256U, '\0');
    if (gethostname(buffer.data(), buffer.size() - 1U) != 0) return std::nullopt;
    buffer.back() = '\0';
    std::string value(buffer.data());
    value = trim_ascii(std::move(value));
    if (value.empty()) return std::nullopt;
    return value;
}

template <typename T>
bool parse_unsigned(std::string_view text, T* out) {
    if (!out || text.empty()) return false;
    T value{};
    const auto* first = text.data();
    const auto* last = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(first, last, value);
    if (ec != std::errc{} || ptr != last) return false;
    *out = value;
    return true;
}

std::optional<std::uint64_t> linux_boot_time_seconds() {
    std::ifstream input("/proc/stat");
    if (!input) return std::nullopt;
    std::string line;
    while (std::getline(input, line)) {
        if (!line.starts_with("btime ")) continue;
        std::uint64_t seconds = 0U;
        if (parse_unsigned(std::string_view(line).substr(6U), &seconds)) return seconds;
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<std::uint64_t> native_process_start_ms() {
    std::ifstream input("/proc/self/stat");
    if (!input) return std::nullopt;
    std::string line;
    std::getline(input, line);
    const auto close = line.rfind(')');
    if (close == std::string::npos || close + 2U >= line.size()) return std::nullopt;

    std::istringstream fields(line.substr(close + 2U));
    std::string token;
    std::vector<std::string> values;
    while (fields >> token) values.push_back(std::move(token));
    // After the executable name, token 0 is /proc stat field 3 (state).
    // Process start ticks are field 22, therefore token index 19.
    if (values.size() <= 19U) return std::nullopt;

    std::uint64_t start_ticks = 0U;
    if (!parse_unsigned(values[19U], &start_ticks)) return std::nullopt;
    const long ticks_per_second = sysconf(_SC_CLK_TCK);
    if (ticks_per_second <= 0) return std::nullopt;
    const auto boot_seconds = linux_boot_time_seconds();
    if (!boot_seconds) return std::nullopt;

    return (*boot_seconds * 1'000ULL) +
           ((start_ticks * 1'000ULL) / static_cast<std::uint64_t>(ticks_per_second));
}

std::optional<NativeMeasurements> collect_native_measurements(
    RuntimeAttestationStatus* failure_status,
    std::string* error) {
    NativeMeasurements result;

    auto executable = native_executable_path();
    if (!executable) {
        if (failure_status) *failure_status = RuntimeAttestationStatus::ExecutableMeasurementFailed;
        if (error) *error = "Linux failed to resolve /proc/self/exe";
        return std::nullopt;
    }
    // Hash the procfs executable link itself so a deleted-but-running binary remains measurable.
    auto executable_digest = sha256_file("/proc/self/exe");
    if (!executable_digest) {
        if (failure_status) *failure_status = RuntimeAttestationStatus::ExecutableMeasurementFailed;
        if (error) *error = "Linux failed to hash /proc/self/exe";
        return std::nullopt;
    }

    std::string machine_material;
    if (auto machine = linux_machine_id()) {
        machine_material = "machine-id\n" + *machine;
    } else if (auto host = linux_host_fallback()) {
        result.trust = RuntimeAttestationTrust::NativeOsLocalDegraded;
        machine_material = "host-fallback\n" + *host + "\n" +
                           detect_hardware_profile().canonical_payload();
    } else {
        if (failure_status) *failure_status = RuntimeAttestationStatus::DeviceMeasurementFailed;
        if (error) *error = "Linux failed to derive a local machine identity";
        return std::nullopt;
    }

    auto started = native_process_start_ms();
    if (!started) {
        if (failure_status) *failure_status = RuntimeAttestationStatus::ProcessMeasurementFailed;
        if (error) *error = "Linux failed to read /proc/self process start identity";
        return std::nullopt;
    }

    result.device_id = std::string(kHardwarePrefix) +
                       sha256("native-runtime-device-v1\nlinux\n" + machine_material);
    result.executable_path = std::move(*executable);
    result.executable_sha256 = std::move(*executable_digest);
    result.process_id = static_cast<std::uint64_t>(getpid());
    result.process_started_unix_ms = *started;
    return result;
}
#endif

bool valid_request(const RuntimeAttestationRequest& request) {
    return valid_token(request.slot_id, 192U) &&
           prefixed_sha256(request.session_id, kSessionPrefix) &&
           valid_token(request.challenge_nonce, 128U) &&
           request.max_age_ms > 0U && request.max_age_ms <= kProviderMaxAgeMs;
}

bool same_context(const RuntimeAttestationEvidence& evidence,
                  const RuntimeAttestationRequest& request) {
    return evidence.binding.slot_id == request.slot_id &&
           evidence.binding.session_id == request.session_id &&
           evidence.binding.layer == request.layer;
}

} // namespace

bool RuntimeAttestationResult::ok() const noexcept {
    return status == RuntimeAttestationStatus::Attested && evidence.has_value();
}

bool AttestedRuntimeLeaseResult::ok() const noexcept {
    return status == AttestedRuntimeLeaseStatus::Allowed && lease.ok();
}

NativeRuntimeAttestationProvider::NativeRuntimeAttestationProvider(Clock clock)
    : clock_(clock ? std::move(clock) : Clock{system_now_ms}) {}

std::string NativeRuntimeAttestationProvider::provider_id() const {
#if defined(_WIN32)
    return "guff.native-runtime-attestor.windows.v1";
#elif defined(__linux__)
    return "guff.native-runtime-attestor.linux.v1";
#else
    return "guff.native-runtime-attestor.unsupported.v1";
#endif
}

RuntimeAttestationTrust NativeRuntimeAttestationProvider::trust() const noexcept {
    return RuntimeAttestationTrust::NativeOsLocal;
}

RuntimeAttestationResult NativeRuntimeAttestationProvider::attest(
    const RuntimeAttestationRequest& request) const {
    RuntimeAttestationResult result;
    if (!valid_request(request)) {
        result.status = RuntimeAttestationStatus::InvalidRequest;
        result.errors.emplace_back("runtime attestation request is malformed or exceeds the provider freshness ceiling");
        return result;
    }

#if !defined(_WIN32) && !defined(__linux__)
    result.status = RuntimeAttestationStatus::UnsupportedPlatform;
    result.errors.emplace_back("native runtime attestation currently supports Windows and Linux");
    return result;
#else
    RuntimeAttestationStatus failure = RuntimeAttestationStatus::ProcessMeasurementFailed;
    std::string measurement_error;
    auto measurements = collect_native_measurements(&failure, &measurement_error);
    if (!measurements) {
        result.status = failure;
        result.errors.push_back(std::move(measurement_error));
        return result;
    }

    RuntimeAttestationEvidence evidence;
    evidence.provider_id = provider_id();
    evidence.trust = measurements->trust;
    evidence.process_id = measurements->process_id;
    evidence.process_started_unix_ms = measurements->process_started_unix_ms;
    evidence.observed_at_unix_ms = clock_ ? clock_() : system_now_ms();
    if (evidence.observed_at_unix_ms >
        std::numeric_limits<std::uint64_t>::max() - request.max_age_ms) {
        result.status = RuntimeAttestationStatus::EvidenceInvalid;
        result.errors.emplace_back("runtime attestation validity window overflows");
        return result;
    }
    evidence.valid_until_unix_ms = evidence.observed_at_unix_ms + request.max_age_ms;
    evidence.challenge_nonce = request.challenge_nonce;
    evidence.executable_locator_sha256 = sha256(measurements->executable_path.generic_string());

    evidence.binding.device_id = measurements->device_id;
    evidence.binding.executable_sha256 = measurements->executable_sha256;
    const std::string process_nonce = sha256(
        evidence.provider_id + "\n" + evidence.binding.device_id + "\n" +
        std::to_string(evidence.process_id) + "\n" +
        std::to_string(evidence.process_started_unix_ms));
    evidence.binding.process_instance_sha256 = runtime_process_instance_sha256(
        evidence.binding.device_id,
        evidence.binding.executable_sha256,
        evidence.process_id,
        evidence.process_started_unix_ms,
        process_nonce);
    evidence.binding.slot_id = request.slot_id;
    evidence.binding.session_id = request.session_id;
    evidence.binding.layer = request.layer;

    const auto canonical = canonical_runtime_attestation(evidence);
    evidence.canonical_sha256 = sha256(canonical);
    evidence.attestation_id = runtime_attestation_id(evidence);
    if (!validate_runtime_attestation_identity(evidence)) {
        result.status = RuntimeAttestationStatus::EvidenceInvalid;
        result.errors.emplace_back("native provider produced invalid attestation identity");
        return result;
    }

    result.status = RuntimeAttestationStatus::Attested;
    result.evidence = std::move(evidence);
    return result;
#endif
}

std::string canonical_runtime_attestation(const RuntimeAttestationEvidence& evidence) {
    std::ostringstream out;
    out << evidence.schema_version << '\n'
        << evidence.provider_id << '\n'
        << static_cast<unsigned>(evidence.trust) << '\n'
        << canonical_runtime_binding(evidence.binding) << '\n'
        << evidence.process_id << '\n'
        << evidence.process_started_unix_ms << '\n'
        << evidence.observed_at_unix_ms << '\n'
        << evidence.valid_until_unix_ms << '\n'
        << evidence.challenge_nonce << '\n'
        << evidence.executable_locator_sha256;
    return out.str();
}

std::string runtime_attestation_id(const RuntimeAttestationEvidence& evidence) {
    return std::string(kAttestationPrefix) + sha256(canonical_runtime_attestation(evidence));
}

bool validate_runtime_attestation_identity(
    const RuntimeAttestationEvidence& evidence) noexcept {
    if (evidence.schema_version != 1U ||
        evidence.provider_id.empty() ||
        !prefixed_sha256(evidence.binding.device_id, kHardwarePrefix) ||
        !is_sha256(evidence.binding.executable_sha256) ||
        !is_sha256(evidence.binding.process_instance_sha256) ||
        !prefixed_sha256(evidence.binding.session_id, kSessionPrefix) ||
        !valid_token(evidence.binding.slot_id, 192U) ||
        evidence.process_id == 0U || evidence.process_started_unix_ms == 0U ||
        evidence.observed_at_unix_ms == 0U ||
        evidence.valid_until_unix_ms <= evidence.observed_at_unix_ms ||
        !valid_token(evidence.challenge_nonce, 128U) ||
        !is_sha256(evidence.executable_locator_sha256)) {
        return false;
    }
    const auto canonical = canonical_runtime_attestation(evidence);
    return evidence.canonical_sha256 == sha256(canonical) &&
           evidence.attestation_id == runtime_attestation_id(evidence);
}

AttestedRuntimeLeaseAuthorityGate::AttestedRuntimeLeaseAuthorityGate(
    const RuntimeAttestationProvider& provider,
    const RuntimeLeaseAuthorityGate& lease_gate,
    RuntimeAttestationPolicy policy,
    Clock clock)
    : provider_(provider),
      lease_gate_(lease_gate),
      policy_(policy),
      clock_(clock ? std::move(clock) : Clock{system_now_ms}) {}

AttestedRuntimeLeaseResult AttestedRuntimeLeaseAuthorityGate::authorize(
    const RuntimeCapabilityLease& lease,
    const SessionKeyBundle& bundle,
    const RuntimeAttestationRequest& request) const {
    AttestedRuntimeLeaseResult result;
    auto attestation = provider_.attest(request);
    result.attestation_status = attestation.status;
    if (!attestation.ok()) {
        result.status = AttestedRuntimeLeaseStatus::AttestationRejected;
        result.errors = std::move(attestation.errors);
        return result;
    }

    const auto& evidence = *attestation.evidence;
    result.attestation_id = evidence.attestation_id;
    if (evidence.provider_id != provider_.provider_id()) {
        result.attestation_status = RuntimeAttestationStatus::ProviderMismatch;
        result.status = AttestedRuntimeLeaseStatus::AttestationRejected;
        result.errors.emplace_back("runtime attestation provider identity changed across the trust boundary");
        return result;
    }
    if (evidence.trust == RuntimeAttestationTrust::NativeOsLocalDegraded &&
        !policy_.allow_degraded_device_identity) {
        result.attestation_status = RuntimeAttestationStatus::DeviceMeasurementFailed;
        result.status = AttestedRuntimeLeaseStatus::AttestationRejected;
        result.errors.emplace_back("degraded OS device identity is not allowed by runtime attestation policy");
        return result;
    }
    if (!validate_runtime_attestation_identity(evidence)) {
        result.attestation_status = RuntimeAttestationStatus::EvidenceInvalid;
        result.status = AttestedRuntimeLeaseStatus::AttestationRejected;
        result.errors.emplace_back("runtime attestation canonical digest is invalid");
        return result;
    }
    if (evidence.challenge_nonce != request.challenge_nonce) {
        result.attestation_status = RuntimeAttestationStatus::ChallengeMismatch;
        result.status = AttestedRuntimeLeaseStatus::AttestationRejected;
        result.errors.emplace_back("runtime attestation challenge does not match the current request");
        return result;
    }
    if (!same_context(evidence, request)) {
        result.attestation_status = RuntimeAttestationStatus::ContextMismatch;
        result.status = AttestedRuntimeLeaseStatus::AttestationRejected;
        result.errors.emplace_back("runtime attestation context does not match slot/session/layer request");
        return result;
    }

    const auto now = clock_ ? clock_() : system_now_ms();
    const auto allowed_age = std::min(policy_.max_age_ms, request.max_age_ms);
    const bool too_far_future = evidence.observed_at_unix_ms > now &&
        (evidence.observed_at_unix_ms - now) > policy_.max_future_skew_ms;
    const bool too_old = now >= evidence.observed_at_unix_ms &&
        (now - evidence.observed_at_unix_ms) > allowed_age;
    const bool validity_too_long =
        evidence.valid_until_unix_ms - evidence.observed_at_unix_ms > request.max_age_ms;
    if (too_far_future || too_old || now > evidence.valid_until_unix_ms || validity_too_long) {
        result.attestation_status = RuntimeAttestationStatus::Stale;
        result.status = AttestedRuntimeLeaseStatus::AttestationRejected;
        result.errors.emplace_back("runtime attestation evidence is outside the accepted freshness window");
        return result;
    }

    result.lease = lease_gate_.authorize(lease, bundle, evidence.binding);
    if (!result.lease.ok()) {
        result.status = AttestedRuntimeLeaseStatus::LeaseRejected;
        result.errors = result.lease.errors;
        return result;
    }
    result.status = AttestedRuntimeLeaseStatus::Allowed;
    return result;
}

std::optional<RuntimeCapabilityLease> AttestedRuntimeLeaseIssuer::issue(
    const SessionKeyBundle& bundle,
    const RuntimeAttestationEvidence& evidence,
    const AttestedRuntimeLeaseIssueRequest& request,
    const SessionKeySigner& signer,
    std::vector<std::string>* errors) {
    std::vector<std::string> local_errors;
    if (!validate_runtime_attestation_identity(evidence)) {
        local_errors.emplace_back("cannot issue a runtime lease from invalid attestation evidence");
    }
    if (request.expires_at_unix_ms <= evidence.observed_at_unix_ms) {
        local_errors.emplace_back("attested runtime lease must expire after the observation time");
    }
    if (!local_errors.empty()) {
        if (errors) *errors = std::move(local_errors);
        return std::nullopt;
    }

    RuntimeLeaseIssueRequest lease_request;
    lease_request.binding = evidence.binding;
    lease_request.capability = request.capability;
    lease_request.issued_at_unix_ms = std::max(
        evidence.observed_at_unix_ms, bundle.receipt.issued_at_unix_ms);
    lease_request.expires_at_unix_ms = request.expires_at_unix_ms;
    lease_request.max_uses = request.max_uses;
    lease_request.nonce = request.nonce;
    return RuntimeLeaseIssuer::issue(bundle, lease_request, signer, errors);
}

std::string_view to_string(RuntimeAttestationTrust trust) noexcept {
    switch (trust) {
    case RuntimeAttestationTrust::NativeOsLocal: return "NATIVE_OS_LOCAL";
    case RuntimeAttestationTrust::NativeOsLocalDegraded: return "NATIVE_OS_LOCAL_DEGRADED";
    }
    return "UNKNOWN";
}

std::string_view to_string(RuntimeAttestationStatus status) noexcept {
    switch (status) {
    case RuntimeAttestationStatus::Attested: return "ATTESTED";
    case RuntimeAttestationStatus::InvalidRequest: return "INVALID_REQUEST";
    case RuntimeAttestationStatus::UnsupportedPlatform: return "UNSUPPORTED_PLATFORM";
    case RuntimeAttestationStatus::DeviceMeasurementFailed: return "DEVICE_MEASUREMENT_FAILED";
    case RuntimeAttestationStatus::ExecutableMeasurementFailed: return "EXECUTABLE_MEASUREMENT_FAILED";
    case RuntimeAttestationStatus::ProcessMeasurementFailed: return "PROCESS_MEASUREMENT_FAILED";
    case RuntimeAttestationStatus::EvidenceInvalid: return "EVIDENCE_INVALID";
    case RuntimeAttestationStatus::ProviderMismatch: return "PROVIDER_MISMATCH";
    case RuntimeAttestationStatus::ChallengeMismatch: return "CHALLENGE_MISMATCH";
    case RuntimeAttestationStatus::ContextMismatch: return "CONTEXT_MISMATCH";
    case RuntimeAttestationStatus::Stale: return "STALE";
    }
    return "UNKNOWN";
}

std::string_view to_string(AttestedRuntimeLeaseStatus status) noexcept {
    switch (status) {
    case AttestedRuntimeLeaseStatus::Allowed: return "ALLOWED";
    case AttestedRuntimeLeaseStatus::AttestationRejected: return "ATTESTATION_REJECTED";
    case AttestedRuntimeLeaseStatus::LeaseRejected: return "LEASE_REJECTED";
    }
    return "UNKNOWN";
}

} // namespace guff
