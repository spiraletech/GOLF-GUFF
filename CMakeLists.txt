cmake_minimum_required(VERSION 3.25)
project(GOLF_GUFF VERSION 0.17.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(GUFF_BUILD_TESTS "Build GOLF GUFF tests" ON)

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
    src/execution_session.cpp
    src/session_journal.cpp
    src/recovery_protocol.cpp
    src/authority_receipt.cpp
    src/authority_ledger.cpp
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

add_executable(GOLF-GUFF src/main.cpp)
target_link_libraries(GOLF-GUFF PRIVATE guff_core)

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
endif()
