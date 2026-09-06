cmake_minimum_required(VERSION 3.25)
project(GOLF_GUFF VERSION 0.30.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(GUFF_BUILD_TESTS "Build GOLF GUFF tests" ON)
option(GUFF_ENABLE_SANITIZERS "Enable AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

if(GUFF_ENABLE_SANITIZERS AND NOT MSVC)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

add_library(guff_core STATIC
    src/reality.cpp
    src/recursor.cpp
    src/caddy.cpp
    src/caddy_router.cpp
    src/route_trace.cpp
    src/data_leech.cpp
    src/symbiosis_ledger.cpp
    src/zenkai.cpp
    src/dojo.cpp
    src/clubhouse.cpp
    src/forge.cpp
    src/native_process.cpp
    src/artifact_vault.cpp
    src/gguf_inference.cpp
    src/kernel_task.cpp
    src/benchmark_probe.cpp
    src/replay_proof.cpp
    src/execution_session.cpp
    src/session_journal.cpp
    src/recovery_protocol.cpp
    src/authority_receipt.cpp
    src/authority_ledger.cpp
    src/authority_delegation.cpp
    src/session_key.cpp
    src/runtime_lease.cpp
    src/runtime_attestation.cpp
    src/runtime_identity_store.cpp
    src/policy_engine.cpp
    src/policy_registry.cpp
    src/policy_registry_query.cpp
    src/operator_console.cpp
    src/release_gate.cpp
    src/authority_gate.cpp
    src/sha256.cpp
    src/model_manifest.cpp
    src/model_registry.cpp
    src/hardware_profile.cpp
    src/scorecard.cpp
    src/scorecard_store.cpp
)

target_include_directories(guff_core PUBLIC include)
target_compile_features(guff_core PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(guff_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(guff_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32)
    target_link_libraries(guff_core PRIVATE advapi32 psapi)
endif()

add_executable(GOLF-GUFF src/main.cpp)
target_link_libraries(GOLF-GUFF PRIVATE guff_core)

add_executable(GOLF-GUFF-OPERATOR src/operator_main.cpp)
target_link_libraries(GOLF-GUFF-OPERATOR PRIVATE guff_core)

add_executable(GOLF-GUFF-RELEASE-CHECK src/release_main.cpp)
target_link_libraries(GOLF-GUFF-RELEASE-CHECK PRIVATE guff_core)

if(GUFF_BUILD_TESTS)
    enable_testing()

    add_executable(guff_smoke tests/smoke.cpp)
    target_link_libraries(guff_smoke PRIVATE guff_core)
    add_test(NAME guff.smoke COMMAND guff_smoke)

    add_executable(guff_model_identity tests/model_identity.cpp)
    target_link_libraries(guff_model_identity PRIVATE guff_core)
    add_test(NAME guff.model_identity COMMAND guff_model_identity)

    add_executable(guff_scorecard tests/scorecard.cpp)
    target_link_libraries(guff_scorecard PRIVATE guff_core)
    add_test(NAME guff.scorecard COMMAND guff_scorecard)

    add_executable(guff_caddy_router tests/caddy_router.cpp)
    target_link_libraries(guff_caddy_router PRIVATE guff_core)
    add_test(NAME guff.caddy_router COMMAND guff_caddy_router)

    add_executable(guff_scorecard_store tests/scorecard_store.cpp)
    target_link_libraries(guff_scorecard_store PRIVATE guff_core)
    add_test(NAME guff.scorecard_store COMMAND guff_scorecard_store)

    add_executable(guff_route_trace tests/route_trace.cpp)
    target_link_libraries(guff_route_trace PRIVATE guff_core)
    add_test(NAME guff.route_trace COMMAND guff_route_trace)

    add_executable(guff_data_leech tests/data_leech.cpp)
    target_link_libraries(guff_data_leech PRIVATE guff_core)
    add_test(NAME guff.data_leech COMMAND guff_data_leech)

    add_executable(guff_symbiosis_ledger tests/symbiosis_ledger.cpp)
    target_link_libraries(guff_symbiosis_ledger PRIVATE guff_core)
    add_test(NAME guff.symbiosis_ledger COMMAND guff_symbiosis_ledger)

    add_executable(guff_zenkai tests/zenkai.cpp)
    target_link_libraries(guff_zenkai PRIVATE guff_core)
    add_test(NAME guff.zenkai COMMAND guff_zenkai)

    add_executable(guff_dojo tests/dojo.cpp)
    target_link_libraries(guff_dojo PRIVATE guff_core)
    add_test(NAME guff.dojo COMMAND guff_dojo)

    add_executable(guff_clubhouse tests/clubhouse.cpp)
    target_link_libraries(guff_clubhouse PRIVATE guff_core)
    add_test(NAME guff.clubhouse COMMAND guff_clubhouse)

    add_executable(guff_forge tests/forge.cpp)
    target_link_libraries(guff_forge PRIVATE guff_core)
    add_test(NAME guff.forge COMMAND guff_forge)

    add_executable(guff_native_process tests/native_process.cpp)
    target_link_libraries(guff_native_process PRIVATE guff_core)
    add_test(NAME guff.native_process COMMAND guff_native_process)

    add_executable(guff_native_telemetry tests/native_telemetry.cpp)
    target_link_libraries(guff_native_telemetry PRIVATE guff_core)
    add_test(NAME guff.native_telemetry COMMAND guff_native_telemetry)

    add_executable(guff_artifact_vault tests/artifact_vault.cpp)
    target_link_libraries(guff_artifact_vault PRIVATE guff_core)
    add_test(NAME guff.artifact_vault COMMAND guff_artifact_vault)

    add_executable(guff_artifact_gguf_bridge tests/artifact_gguf_bridge.cpp)
    target_link_libraries(guff_artifact_gguf_bridge PRIVATE guff_core)
    add_test(NAME guff.artifact_gguf_bridge COMMAND guff_artifact_gguf_bridge)

    add_executable(guff_gguf_inference tests/gguf_inference.cpp)
    target_link_libraries(guff_gguf_inference PRIVATE guff_core)
    add_test(NAME guff.gguf_inference COMMAND guff_gguf_inference)

    add_executable(guff_kernel_task tests/kernel_task.cpp)
    target_link_libraries(guff_kernel_task PRIVATE guff_core)
    add_test(NAME guff.kernel_task COMMAND guff_kernel_task)

    add_executable(guff_benchmark_probe tests/benchmark_probe.cpp)
    target_link_libraries(guff_benchmark_probe PRIVATE guff_core)
    add_test(NAME guff.benchmark_probe COMMAND guff_benchmark_probe)

    add_executable(guff_replay_proof tests/replay_proof.cpp)
    target_link_libraries(guff_replay_proof PRIVATE guff_core)
    add_test(NAME guff.replay_proof COMMAND guff_replay_proof)

    add_executable(guff_execution_session tests/execution_session.cpp)
    target_link_libraries(guff_execution_session PRIVATE guff_core)
    add_test(NAME guff.execution_session COMMAND guff_execution_session)

    add_executable(guff_session_journal tests/session_journal.cpp)
    target_link_libraries(guff_session_journal PRIVATE guff_core)
    add_test(NAME guff.session_journal COMMAND guff_session_journal)

    add_executable(guff_recovery_protocol tests/recovery_protocol.cpp)
    target_link_libraries(guff_recovery_protocol PRIVATE guff_core)
    add_test(NAME guff.recovery_protocol COMMAND guff_recovery_protocol)

    add_executable(guff_authority_receipt tests/authority_receipt.cpp)
    target_link_libraries(guff_authority_receipt PRIVATE guff_core)
    add_test(NAME guff.authority_receipt COMMAND guff_authority_receipt)

    add_executable(guff_authority_ledger tests/authority_ledger.cpp)
    target_link_libraries(guff_authority_ledger PRIVATE guff_core)
    add_test(NAME guff.authority_ledger COMMAND guff_authority_ledger)

    add_executable(guff_authority_gate tests/authority_gate.cpp)
    target_link_libraries(guff_authority_gate PRIVATE guff_core)
    add_test(NAME guff.authority_gate COMMAND guff_authority_gate)

    add_executable(guff_authority_delegation tests/authority_delegation.cpp)
    target_link_libraries(guff_authority_delegation PRIVATE guff_core)
    add_test(NAME guff.authority_delegation COMMAND guff_authority_delegation)

    add_executable(guff_session_key tests/session_key.cpp)
    target_link_libraries(guff_session_key PRIVATE guff_core)
    add_test(NAME guff.session_key COMMAND guff_session_key)

    add_executable(guff_runtime_lease tests/runtime_lease.cpp)
    target_link_libraries(guff_runtime_lease PRIVATE guff_core)
    add_test(NAME guff.runtime_lease COMMAND guff_runtime_lease)

    add_executable(guff_runtime_attestation tests/runtime_attestation.cpp)
    target_link_libraries(guff_runtime_attestation PRIVATE guff_core)
    add_test(NAME guff.runtime_attestation COMMAND guff_runtime_attestation)

    add_executable(guff_runtime_identity_store tests/runtime_identity_store.cpp)
    target_link_libraries(guff_runtime_identity_store PRIVATE guff_core)
    add_test(NAME guff.runtime_identity_store COMMAND guff_runtime_identity_store)

    add_executable(guff_policy_engine tests/policy_engine.cpp)
    target_link_libraries(guff_policy_engine PRIVATE guff_core)
    add_test(NAME guff.policy_engine COMMAND guff_policy_engine)

    add_executable(guff_policy_registry tests/policy_registry.cpp)
    target_link_libraries(guff_policy_registry PRIVATE guff_core)
    add_test(NAME guff.policy_registry COMMAND guff_policy_registry)

    add_executable(guff_operator_console tests/operator_console.cpp)
    target_link_libraries(guff_operator_console PRIVATE guff_core)
    add_test(NAME guff.operator_console COMMAND guff_operator_console)
    add_test(NAME guff.operator_cli
             COMMAND GOLF-GUFF-OPERATOR "${CMAKE_CURRENT_BINARY_DIR}/operator-empty-state")

    add_executable(guff_release_gate tests/release_gate.cpp)
    target_link_libraries(guff_release_gate PRIVATE guff_core)
    add_test(NAME guff.release_gate COMMAND guff_release_gate)

    add_executable(guff_release_adversarial tests/release_adversarial.cpp)
    target_link_libraries(guff_release_adversarial PRIVATE guff_core)
    add_test(NAME guff.release_adversarial COMMAND guff_release_adversarial)

    add_test(NAME guff.release_cli_fail_closed
             COMMAND GOLF-GUFF-RELEASE-CHECK "${CMAKE_CURRENT_BINARY_DIR}/release-empty-state")
    set_tests_properties(guff.release_cli_fail_closed PROPERTIES WILL_FAIL TRUE)
endif()
