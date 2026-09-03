cmake_minimum_required(VERSION 3.25)
project(GOLF_GUFF VERSION 0.4.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(GUFF_BUILD_TESTS "Build GOLF GUFF tests" ON)

add_library(guff_core STATIC
    src/reality.cpp
    src/recursor.cpp
    src/caddy.cpp
    src/caddy_router.cpp
    src/sha256.cpp
    src/model_manifest.cpp
    src/model_registry.cpp
    src/hardware_profile.cpp
    src/scorecard.cpp
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
endif()
