#include "guff/clubhouse.hpp"
#include "guff/sha256.hpp"

#include <cassert>
#include <string>
#include <vector>

namespace {

guff::SlotManifest xenon_manifest() {
    guff::SlotManifest slot;
    slot.slot_name = "xenon";
    slot.display_name = "XENON Music Trinity";
    slot.version = "1.0.0";
    slot.kind = guff::SlotKind::Audio;
    slot.transport = guff::SlotTransport::LocalProcess;
    slot.entrypoint = "xenon://native";
    slot.capabilities = {
        guff::SlotCapability::AudioGenerate,
        guff::SlotCapability::AudioAnalyze,
    };
    slot.allowed_layers = {
        guff::RealityLayer::Application,
        guff::RealityLayer::Representation,
    };
    slot.required_permissions = {"audio:generate", "device:execute"};
    slot.max_payload_bytes = 4096U;
    slot.tags = {"music", "native-cpp", "music"};
    return slot;
}

} // namespace

int main() {
    auto xenon = xenon_manifest();
    assert(xenon.validate().empty());
    assert(xenon.immutable_id().starts_with("guff:slot:sha256:"));

    auto reordered = xenon;
    reordered.capabilities = {
        guff::SlotCapability::AudioAnalyze,
        guff::SlotCapability::AudioGenerate,
        guff::SlotCapability::AudioAnalyze,
    };
    reordered.allowed_layers = {
        guff::RealityLayer::Representation,
        guff::RealityLayer::Application,
    };
    reordered.required_permissions = {"device:execute", "audio:generate", "audio:generate"};
    reordered.tags = {"native-cpp", "music"};
    assert(reordered.immutable_id() == xenon.immutable_id());

    guff::ClubhouseRegistry clubhouse;
    std::vector<std::string> errors;
    assert(clubhouse.register_slot(xenon, &errors));
    assert(errors.empty());
    assert(clubhouse.size() == 1U);
    assert(clubhouse.find("xenon").has_value());
    assert(clubhouse.find(xenon.immutable_id()).has_value());

    errors.clear();
    assert(!clubhouse.register_slot(reordered, &errors));
    assert(!errors.empty());

    guff::SlotInvocation invoke;
    invoke.invocation_id = "invoke-1";
    invoke.slot_id = "xenon";
    invoke.capability = guff::SlotCapability::AudioGenerate;
    invoke.layer = guff::RealityLayer::Application;
    invoke.input_sha256 = guff::sha256("generate four bars");
    invoke.payload_bytes = 128U;
    invoke.permission_tokens = {"audio:generate"};

    auto denied = clubhouse.resolve(invoke);
    assert(denied.status == guff::InvocationStatus::PermissionMissing);
    assert(denied.missing_permissions.size() == 1U);
    assert(denied.missing_permissions.front() == "device:execute");

    invoke.permission_tokens.push_back("device:execute");
    auto ready = clubhouse.resolve(invoke);
    assert(ready.ready());
    assert(ready.slot.has_value());
    assert(ready.slot->slot_name == "xenon");

    invoke.layer = guff::RealityLayer::Simulation;
    assert(clubhouse.resolve(invoke).status == guff::InvocationStatus::LayerMismatch);
    invoke.layer = guff::RealityLayer::Application;

    invoke.capability = guff::SlotCapability::WorldMutate;
    assert(clubhouse.resolve(invoke).status == guff::InvocationStatus::CapabilityMissing);
    invoke.capability = guff::SlotCapability::AudioGenerate;

    invoke.payload_bytes = 4097U;
    assert(clubhouse.resolve(invoke).status == guff::InvocationStatus::PayloadTooLarge);

    invoke.payload_bytes = 64U;
    invoke.slot_id = "missing-slot";
    assert(clubhouse.resolve(invoke).status == guff::InvocationStatus::SlotNotFound);

    auto disabled = xenon_manifest();
    disabled.slot_name = "xenon-disabled";
    disabled.enabled = false;
    assert(clubhouse.register_slot(disabled));
    invoke.slot_id = "xenon-disabled";
    assert(clubhouse.resolve(invoke).status == guff::InvocationStatus::SlotDisabled);

    auto bad = xenon_manifest();
    bad.slot_name = "bad";
    bad.required_permissions = {"NOT VALID!"};
    assert(!bad.validate().empty());

    return 0;
}
