#include "guff/data_leech.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <string>

int main() {
    namespace fs = std::filesystem;

    const auto base = fs::temp_directory_path() / "guff-l5-leech";
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::create_directories(base / "repo");

    const auto allowed = base / "repo" / "a.cpp";
    const auto sibling = base / "secret.txt";
    {
        std::ofstream output(allowed);
        output << "alpha beta gamma delta";
    }
    {
        std::ofstream output(sibling);
        output << "secret";
    }

    guff::SourceGrant grant;
    grant.grant_id = "project-source";
    grant.kind = guff::SourceKind::RepoFile;
    grant.scope = guff::GrantScope::Project;
    grant.root = base / "repo";
    grant.recursive = true;
    grant.max_source_bytes = 1024U;
    grant.max_slice_bytes = 5U;
    assert(grant.validate().empty());

    guff::DataLeech leech;
    const auto first = leech.observe_file(grant, allowed);
    assert(first.state == guff::DeltaState::FirstSeen);
    assert(first.current.has_value());

    const auto same = leech.observe_file(grant, allowed, first.current);
    assert(same.state == guff::DeltaState::Unchanged);
    assert(!same.changed());

    {
        std::ofstream output(allowed, std::ios::app);
        output << '!';
    }
    const auto changed = leech.observe_file(grant, allowed, first.current);
    assert(changed.state == guff::DeltaState::Modified);
    assert(changed.changed());

    const auto denied = leech.observe_file(grant, sibling);
    assert(denied.state == guff::DeltaState::PermissionDenied);

    std::string error;
    const auto slice = leech.slice_file(grant, allowed, 6U, 100U, &error);
    assert(slice.has_value());
    assert(slice->data == "beta ");
    assert(slice->truncated);
    assert(error.empty());

    guff::SourceGrant tool;
    tool.grant_id = "compiler";
    tool.kind = guff::SourceKind::ToolOutput;
    tool.locator_prefix = "tool://cmake/";
    tool.max_source_bytes = 1024U;
    tool.max_slice_bytes = 8U;

    const auto tool_first = leech.observe_text(
        tool, "tool://cmake/build", "error: x\nline2");
    assert(tool_first.state == guff::DeltaState::FirstSeen);

    const auto tool_slice = leech.slice_text(
        tool, "tool://cmake/build", "error: x\nline2", 0U, 100U, &error);
    assert(tool_slice.has_value());
    assert(tool_slice->data == "error: x");
    assert(tool_slice->truncated);

    const auto tool_denied = leech.observe_text(tool, "tool://other/x", "bad");
    assert(tool_denied.state == guff::DeltaState::PermissionDenied);

    guff::ContextArena arena({.max_slices = 2U, .max_total_bytes = 13U});
    assert(arena.add(*slice));
    assert(!arena.add(*slice));
    assert(arena.rejected() == 1U);
    assert(arena.add(*tool_slice));
    assert(arena.used_bytes() == 13U);

    auto extra = *tool_slice;
    extra.offset = 1U;
    extra.data = "x";
    assert(!arena.add(std::move(extra)));
    assert(arena.slices().size() == 2U);

    arena.clear();
    assert(arena.used_bytes() == 0U);
    assert(arena.rejected() == 0U);

    fs::remove_all(base, ec);
    return 0;
}
