cmake_minimum_required(VERSION 3.25)
project(GOLF_GUFF VERSION 0.10.0 LANGUAGES CXX)

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
endif()
