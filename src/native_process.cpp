#include "guff/native_process.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <limits>
#include <set>
#include <thread>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace guff {
namespace {

std::size_t saturating_add(std::size_t lhs, std::size_t rhs) noexcept {
    if (rhs > std::numeric_limits<std::size_t>::max() - lhs) {
        return std::numeric_limits<std::size_t>::max();
    }
    return lhs + rhs;
}

bool valid_environment_name(std::string_view value) {
    if (value.empty() || value.size() > 128U) return false;
    const auto first = static_cast<unsigned char>(value.front());
    if (!(std::isalpha(first) != 0 || first == '_')) return false;
    return std::all_of(value.begin() + 1, value.end(), [](unsigned char ch) {
        return std::isalnum(ch) != 0 || ch == '_';
    });
}

bool contains_nul(std::string_view value) noexcept {
    return value.find('\0') != std::string_view::npos;
}

std::optional<std::filesystem::path> canonical_existing(const std::filesystem::path& path) {
    std::error_code ec;
    auto canonical = std::filesystem::canonical(path, ec);
    if (ec) return std::nullopt;
    return canonical;
}

bool path_within(const std::filesystem::path& child, const std::filesystem::path& root) {
    auto child_it = child.begin();
    auto root_it = root.begin();
    for (; root_it != root.end(); ++root_it, ++child_it) {
        if (child_it == child.end() || *child_it != *root_it) return false;
    }
    return true;
}

std::size_t total_argument_bytes(const NativeProcessBinding& binding, std::string_view payload) {
    std::size_t total = 0U;
    for (const auto& arg : binding.arguments) total = saturating_add(total, arg.size());
    if (binding.payload_mode == NativePayloadMode::SingleArgument) {
        total = saturating_add(total, payload.size());
    }
    return total;
}

std::size_t total_environment_bytes(const NativeProcessBinding& binding) {
    std::size_t total = 0U;
    for (const auto& [name, value] : binding.environment) {
        total = saturating_add(total, name.size());
        total = saturating_add(total, value.size());
        total = saturating_add(total, 2U);
    }
    return total;
}

std::vector<std::string> effective_arguments(const NativeProcessBinding& binding,
                                             std::string_view payload) {
    auto args = binding.arguments;
    if (binding.payload_mode == NativePayloadMode::SingleArgument) args.emplace_back(payload);
    return args;
}

#ifdef _WIN32
std::optional<std::wstring> utf8_to_wide(std::string_view value) {
    if (value.empty()) return std::wstring{};
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                              value.data(), static_cast<int>(value.size()),
                                              nullptr, 0);
    if (required <= 0) return std::nullopt;
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                            value.data(), static_cast<int>(value.size()),
                            result.data(), required) != required) {
        return std::nullopt;
    }
    return result;
}

std::wstring quote_windows_argument(std::wstring_view value) {
    if (!value.empty() && value.find_first_of(L" \t\"") == std::wstring_view::npos) {
        return std::wstring(value);
    }
    std::wstring out;
    out.push_back(L'"');
    std::size_t backslashes = 0U;
    for (const auto ch : value) {
        if (ch == L'\\') {
            ++backslashes;
            continue;
        }
        if (ch == L'"') {
            out.append(backslashes * 2U + 1U, L'\\');
            out.push_back(L'"');
            backslashes = 0U;
            continue;
        }
        out.append(backslashes, L'\\');
        backslashes = 0U;
        out.push_back(ch);
    }
    out.append(backslashes * 2U, L'\\');
    out.push_back(L'"');
    return out;
}

bool drain_windows_pipe(HANDLE read_pipe, ForgeOutputSink& output) {
    std::array<char, 4096U> buffer{};
    while (true) {
        DWORD available = 0U;
        if (!PeekNamedPipe(read_pipe, nullptr, 0U, nullptr, &available, nullptr)) return true;
        if (available == 0U) return true;
        DWORD read = 0U;
        const auto wanted = static_cast<DWORD>(std::min<std::size_t>(buffer.size(), available));
        if (!ReadFile(read_pipe, buffer.data(), wanted, &read, nullptr) || read == 0U) return true;
        if (!output.write(std::string_view(buffer.data(), read))) return false;
    }
}

ForgeExecutorReport run_windows(const NativeProcessBinding& binding,
                                const ForgeExecutionRequest& request,
                                ForgeOutputSink& output) {
    ForgeExecutorReport report;
    const auto args = effective_arguments(binding, request.payload);
    std::vector<std::wstring> wide_args;
    wide_args.reserve(args.size());
    for (const auto& arg : args) {
        auto converted = utf8_to_wide(arg);
        if (!converted) return report;
        wide_args.push_back(std::move(*converted));
    }

    std::wstring command_line = quote_windows_argument(binding.executable.wstring());
    for (const auto& arg : wide_args) {
        command_line.push_back(L' ');
        command_line += quote_windows_argument(arg);
    }

    auto environment = binding.environment;
    std::sort(environment.begin(), environment.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.first < rhs.first;
    });
    std::wstring environment_block;
    for (const auto& [name, value] : environment) {
        auto wide_name = utf8_to_wide(name);
        auto wide_value = utf8_to_wide(value);
        if (!wide_name || !wide_value) return report;
        environment_block += *wide_name;
        environment_block.push_back(L'=');
        environment_block += *wide_value;
        environment_block.push_back(L'\0');
    }
    environment_block.push_back(L'\0');
    if (binding.environment.empty()) environment_block.push_back(L'\0');

    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    HANDLE read_pipe = nullptr;
    HANDLE write_pipe = nullptr;
    if (!CreatePipe(&read_pipe, &write_pipe, &security, 0U)) return report;
    if (!SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0U)) {
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        return report;
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = write_pipe;
    startup.hStdError = write_pipe;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION process{};

    auto mutable_command = command_line;
    const auto executable = binding.executable.wstring();
    const auto working_directory = binding.working_directory.wstring();
    const BOOL launched = CreateProcessW(
        executable.c_str(), mutable_command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        environment_block.data(), working_directory.c_str(), &startup, &process);
    CloseHandle(write_pipe);
    if (!launched) {
        CloseHandle(read_pipe);
        return report;
    }

    const auto started = std::chrono::steady_clock::now();
    bool timeout = false;
    bool output_overflow = false;
    while (true) {
        if (!drain_windows_pipe(read_pipe, output)) {
            output_overflow = true;
            TerminateProcess(process.hProcess, 125U);
            WaitForSingleObject(process.hProcess, INFINITE);
            break;
        }

        const auto wait = WaitForSingleObject(process.hProcess, 5U);
        if (wait == WAIT_OBJECT_0) break;
        if (wait == WAIT_FAILED) {
            TerminateProcess(process.hProcess, 126U);
            WaitForSingleObject(process.hProcess, INFINITE);
            break;
        }

        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        if (elapsed >= static_cast<long long>(request.budget.max_wall_time_ms)) {
            timeout = true;
            TerminateProcess(process.hProcess, 124U);
            WaitForSingleObject(process.hProcess, INFINITE);
            break;
        }
    }
    static_cast<void>(drain_windows_pipe(read_pipe, output));

    DWORD exit_code = 126U;
    GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    CloseHandle(read_pipe);

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();
    report.completed = true;
    report.exit_code = static_cast<int>(exit_code);
    report.reported_wall_time_ms = elapsed < 0 ? 0U : static_cast<std::uint64_t>(elapsed);
    if (timeout) report.reported_wall_time_ms = request.budget.max_wall_time_ms + 1U;
    if (output_overflow && report.exit_code == 0) report.exit_code = 125;
    return report;
}
#else
bool drain_posix_pipe(int fd, ForgeOutputSink& output) {
    std::array<char, 4096U> buffer{};
    while (true) {
        const auto count = ::read(fd, buffer.data(), buffer.size());
        if (count > 0) {
            if (!output.write(std::string_view(buffer.data(), static_cast<std::size_t>(count)))) return false;
            continue;
        }
        if (count == 0) return true;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
        return true;
    }
}

ForgeExecutorReport run_posix(const NativeProcessBinding& binding,
                              const ForgeExecutionRequest& request,
                              ForgeOutputSink& output) {
    ForgeExecutorReport report;
    int pipe_fds[2]{};
    if (::pipe(pipe_fds) != 0) return report;

    const auto args = effective_arguments(binding, request.payload);
    std::vector<std::string> argv_storage;
    argv_storage.reserve(args.size() + 1U);
    argv_storage.push_back(binding.executable.string());
    argv_storage.insert(argv_storage.end(), args.begin(), args.end());
    std::vector<char*> argv;
    argv.reserve(argv_storage.size() + 1U);
    for (auto& value : argv_storage) argv.push_back(value.data());
    argv.push_back(nullptr);

    std::vector<std::string> env_storage;
    env_storage.reserve(binding.environment.size());
    for (const auto& [name, value] : binding.environment) env_storage.push_back(name + "=" + value);
    std::vector<char*> envp;
    envp.reserve(env_storage.size() + 1U);
    for (auto& value : env_storage) envp.push_back(value.data());
    envp.push_back(nullptr);

    const auto pid = ::fork();
    if (pid < 0) {
        ::close(pipe_fds[0]);
        ::close(pipe_fds[1]);
        return report;
    }
    if (pid == 0) {
        ::close(pipe_fds[0]);
        static_cast<void>(::dup2(pipe_fds[1], STDOUT_FILENO));
        static_cast<void>(::dup2(pipe_fds[1], STDERR_FILENO));
        ::close(pipe_fds[1]);
        if (::chdir(binding.working_directory.c_str()) != 0) ::_exit(126);
        ::execve(binding.executable.c_str(), argv.data(), envp.data());
        ::_exit(127);
    }

    ::close(pipe_fds[1]);
    const auto flags = ::fcntl(pipe_fds[0], F_GETFL, 0);
    if (flags >= 0) static_cast<void>(::fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK));

    const auto started = std::chrono::steady_clock::now();
    bool timeout = false;
    bool output_overflow = false;
    int wait_status = 0;
    bool reaped = false;

    while (!reaped) {
        if (!drain_posix_pipe(pipe_fds[0], output)) {
            output_overflow = true;
            static_cast<void>(::kill(pid, SIGKILL));
        }

        const auto waited = ::waitpid(pid, &wait_status, WNOHANG);
        if (waited == pid) {
            reaped = true;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            static_cast<void>(::kill(pid, SIGKILL));
            static_cast<void>(::waitpid(pid, &wait_status, 0));
            reaped = true;
            break;
        }

        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        if (!output_overflow && elapsed >= static_cast<long long>(request.budget.max_wall_time_ms)) {
            timeout = true;
            static_cast<void>(::kill(pid, SIGKILL));
        }
        if (output_overflow || timeout) {
            static_cast<void>(::waitpid(pid, &wait_status, 0));
            reaped = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    static_cast<void>(drain_posix_pipe(pipe_fds[0], output));
    ::close(pipe_fds[0]);

    int exit_code = 126;
    if (WIFEXITED(wait_status)) exit_code = WEXITSTATUS(wait_status);
    else if (WIFSIGNALED(wait_status)) exit_code = 128 + WTERMSIG(wait_status);

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();
    report.completed = true;
    report.exit_code = exit_code;
    report.reported_wall_time_ms = elapsed < 0 ? 0U : static_cast<std::uint64_t>(elapsed);
    if (timeout) report.reported_wall_time_ms = request.budget.max_wall_time_ms + 1U;
    return report;
}
#endif

} // namespace

std::vector<std::string> NativeProcessBinding::validate() const {
    std::vector<std::string> errors;
    if (executable.empty() || !executable.is_absolute()) errors.emplace_back("executable must be an absolute path");
    std::error_code ec;
    if (!executable.empty() && (!std::filesystem::exists(executable, ec) || ec ||
        !std::filesystem::is_regular_file(executable, ec))) {
        errors.emplace_back("executable must exist and be a regular file");
    }
    if (working_root.empty() || working_directory.empty() ||
        !working_root.is_absolute() || !working_directory.is_absolute()) {
        errors.emplace_back("working_root and working_directory must be absolute");
    } else {
        const auto root = canonical_existing(working_root);
        const auto directory = canonical_existing(working_directory);
        if (!root || !directory) errors.emplace_back("working_root and working_directory must exist");
        else if (!path_within(*directory, *root)) errors.emplace_back("working_directory escapes working_root");
    }
    if (limits.max_arguments == 0U || limits.max_argument_bytes == 0U ||
        limits.max_environment_entries == 0U || limits.max_environment_bytes == 0U) {
        errors.emplace_back("native process limits must be greater than zero");
    }
    if (arguments.size() + (payload_mode == NativePayloadMode::SingleArgument ? 1U : 0U) > limits.max_arguments) {
        errors.emplace_back("argument count exceeds native process limit");
    }
    if (total_argument_bytes(*this, {}) > limits.max_argument_bytes) errors.emplace_back("fixed argument bytes exceed native process limit");
    if (environment.size() > limits.max_environment_entries) errors.emplace_back("environment entry count exceeds native process limit");
    if (total_environment_bytes(*this) > limits.max_environment_bytes) errors.emplace_back("environment bytes exceed native process limit");

    std::set<std::string> names;
    for (const auto& arg : arguments) {
        if (contains_nul(arg)) errors.emplace_back("arguments cannot contain NUL bytes");
    }
    for (const auto& [name, value] : environment) {
        if (!valid_environment_name(name) || contains_nul(value)) errors.emplace_back("invalid environment entry: " + name);
        else if (!names.insert(name).second) errors.emplace_back("duplicate environment entry: " + name);
    }
    return errors;
}

bool NativeProcessRegistry::bind(const SlotManifest& slot,
                                 NativeProcessBinding binding,
                                 std::vector<std::string>* errors) {
    std::vector<std::string> validation;
    if (!slot.validate().empty()) validation.emplace_back("slot manifest is invalid");
    if (slot.transport != SlotTransport::LocalProcess) validation.emplace_back("native process binding requires LOCAL_PROCESS slot transport");
    auto binding_errors = binding.validate();
    validation.insert(validation.end(), binding_errors.begin(), binding_errors.end());
    if (!validation.empty()) {
        if (errors) *errors = std::move(validation);
        return false;
    }

    const auto key = slot.immutable_id();
    if (bindings_.contains(key)) {
        if (errors) errors->push_back("slot already has a native process binding");
        return false;
    }
    bindings_.emplace(key, std::move(binding));
    return true;
}

std::optional<NativeProcessBinding> NativeProcessRegistry::find(std::string_view slot_immutable_id) const {
    const auto found = bindings_.find(std::string(slot_immutable_id));
    if (found == bindings_.end()) return std::nullopt;
    return found->second;
}

std::size_t NativeProcessRegistry::size() const noexcept { return bindings_.size(); }

NativeLocalProcessExecutor::NativeLocalProcessExecutor(const NativeProcessRegistry& registry) noexcept
    : registry_(registry) {}

ForgeExecutorReport NativeLocalProcessExecutor::operator()(
    const SlotManifest& slot,
    const ForgeExecutionRequest& request,
    ForgeOutputSink& output) const {
    ForgeExecutorReport failure;
    if (slot.transport != SlotTransport::LocalProcess) return failure;

    const auto binding = registry_.find(slot.immutable_id());
    if (!binding) return failure;

    const auto argument_count = binding->arguments.size() +
        (binding->payload_mode == NativePayloadMode::SingleArgument ? 1U : 0U);
    if (argument_count > binding->limits.max_arguments ||
        total_argument_bytes(*binding, request.payload) > binding->limits.max_argument_bytes ||
        binding->environment.size() > binding->limits.max_environment_entries ||
        total_environment_bytes(*binding) > binding->limits.max_environment_bytes) {
        return failure;
    }

#ifdef _WIN32
    return run_windows(*binding, request, output);
#else
    return run_posix(*binding, request, output);
#endif
}

std::string_view to_string(NativePayloadMode mode) noexcept {
    switch (mode) {
    case NativePayloadMode::None: return "NONE";
    case NativePayloadMode::SingleArgument: return "SINGLE_ARGUMENT";
    }
    return "NONE";
}

} // namespace guff
