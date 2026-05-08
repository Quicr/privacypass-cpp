cmake_minimum_required(VERSION 3.20)
project(privacy_pass VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options
option(PRIVACY_PASS_BUILD_TESTS "Build unit tests" ON)
option(PRIVACY_PASS_BUILD_BENCHMARKS "Build benchmarks" ON)
option(PRIVACY_PASS_BUILD_MOQ "Build MOQ extension" ON)
option(PRIVACY_PASS_BUILD_EXAMPLES "Build examples" ON)
option(PRIVACY_PASS_ENABLE_SANITIZERS "Enable address and undefined sanitizers" OFF)

# Sanitizer flags (applied globally since they affect linking)
if(PRIVACY_PASS_ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# Helper function to apply strict warning flags to our targets only
function(privacy_pass_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()

# Dependencies
find_package(OpenSSL REQUIRED)

include(FetchContent)

# Silence MSVC deprecation warnings for spdlog's bundled fmt library
if(MSVC)
    add_compile_definitions(_SILENCE_STDEXT_ARR_ITERS_DEPRECATION_WARNING)
endif()

# Disable spdlog's own warnings-as-errors to avoid issues with third-party code
set(SPDLOG_ENABLE_WARNINGS OFF CACHE BOOL "" FORCE)

# Fetch spdlog
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.14.1
)
FetchContent_MakeAvailable(spdlog)

# Fetch doctest if building tests
if(PRIVACY_PASS_BUILD_TESTS)
    include(FetchContent)
    FetchContent_Declare(
        doctest
        GIT_REPOSITORY https://github.com/doctest/doctest.git
        GIT_TAG v2.4.12
    )
    FetchContent_MakeAvailable(doctest)
endif()

# Fetch Google Benchmark if building benchmarks
if(PRIVACY_PASS_BUILD_BENCHMARKS)
    include(FetchContent)
    FetchContent_Declare(
        benchmark
        GIT_REPOSITORY https://github.com/google/benchmark.git
        GIT_TAG v1.8.3
    )
    set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(benchmark)
endif()

# Core library
add_library(privacy_pass_core
    src/core/types.cpp
    src/core/token_challenge.cpp
    src/core/token_request.cpp
    src/core/token_response.cpp
    src/core/token.cpp
    src/core/serialization.cpp
)
privacy_pass_set_warnings(privacy_pass_core)

target_include_directories(privacy_pass_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(privacy_pass_core PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_link_libraries(privacy_pass_core PRIVATE
    spdlog::spdlog
)

# Crypto library
add_library(privacy_pass_crypto
    src/crypto/blind_rsa.cpp
    src/crypto/voprf.cpp
    src/crypto/hash.cpp
    src/crypto/random.cpp
)
privacy_pass_set_warnings(privacy_pass_crypto)

target_link_libraries(privacy_pass_crypto PUBLIC
    privacy_pass_core
)
target_link_libraries(privacy_pass_crypto PRIVATE spdlog::spdlog)

# HTTP layer
add_library(privacy_pass_http
    src/http/auth_scheme.cpp
    src/http/header_parser.cpp
)
privacy_pass_set_warnings(privacy_pass_http)

target_link_libraries(privacy_pass_http PUBLIC
    privacy_pass_core
)
target_link_libraries(privacy_pass_http PRIVATE spdlog::spdlog)

# Client library
add_library(privacy_pass_client
    src/core/client.cpp
)
privacy_pass_set_warnings(privacy_pass_client)

target_link_libraries(privacy_pass_client PUBLIC
    privacy_pass_core
    privacy_pass_crypto
)
target_link_libraries(privacy_pass_client PRIVATE spdlog::spdlog)

# Issuer library
add_library(privacy_pass_issuer
    src/core/issuer.cpp
)
privacy_pass_set_warnings(privacy_pass_issuer)

target_link_libraries(privacy_pass_issuer PUBLIC
    privacy_pass_core
    privacy_pass_crypto
)
target_link_libraries(privacy_pass_issuer PRIVATE spdlog::spdlog)

# Origin library
add_library(privacy_pass_origin
    src/core/origin.cpp
)
privacy_pass_set_warnings(privacy_pass_origin)

target_link_libraries(privacy_pass_origin PUBLIC
    privacy_pass_core
    privacy_pass_crypto
)
target_link_libraries(privacy_pass_origin PRIVATE spdlog::spdlog)

# Token Provider library (high-level abstraction)
add_library(privacy_pass_provider
    src/core/token_provider.cpp
)
privacy_pass_set_warnings(privacy_pass_provider)

target_link_libraries(privacy_pass_provider PUBLIC
    privacy_pass_client
    privacy_pass_issuer
)
target_link_libraries(privacy_pass_provider PRIVATE spdlog::spdlog)

# Token Authenticator library (high-level abstraction)
add_library(privacy_pass_authenticator
    src/core/token_authenticator.cpp
)
privacy_pass_set_warnings(privacy_pass_authenticator)

target_link_libraries(privacy_pass_authenticator PUBLIC
    privacy_pass_origin
)
target_link_libraries(privacy_pass_authenticator PRIVATE spdlog::spdlog)

# Combined library target
add_library(privacy_pass INTERFACE)
target_link_libraries(privacy_pass INTERFACE
    privacy_pass_core
    privacy_pass_crypto
    privacy_pass_http
    privacy_pass_client
    privacy_pass_issuer
    privacy_pass_origin
    privacy_pass_provider
    privacy_pass_authenticator
)

# MOQ extension library (optional)
if(PRIVACY_PASS_BUILD_MOQ)
    add_library(privacy_pass_moq
        extensions/moq/src/auth_scope.cpp
        extensions/moq/src/authorization_info.cpp
    )

    target_include_directories(privacy_pass_moq PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/extensions/moq/include>
        $<INSTALL_INTERFACE:include>
    )

    target_link_libraries(privacy_pass_moq PUBLIC
        privacy_pass_core
    )
    target_link_libraries(privacy_pass_moq PRIVATE spdlog::spdlog)
    privacy_pass_set_warnings(privacy_pass_moq)
endif()

# Tests
if(PRIVACY_PASS_BUILD_TESTS)
    enable_testing()

    set(TEST_SOURCES
        tests/test_main.cpp
        tests/test_types.cpp
        tests/test_serialization.cpp
        tests/test_crypto.cpp
        tests/test_blind_rsa.cpp
        tests/test_voprf.cpp
        tests/test_token_challenge.cpp
        tests/test_token_request.cpp
        tests/test_token.cpp
        tests/test_client.cpp
        tests/test_issuer.cpp
        tests/test_origin.cpp
        tests/test_integration.cpp
        tests/test_http.cpp
    )
    if(PRIVACY_PASS_BUILD_MOQ)
        list(APPEND TEST_SOURCES tests/test_moq.cpp)
    endif()

    add_executable(privacy_pass_tests ${TEST_SOURCES})
    privacy_pass_set_warnings(privacy_pass_tests)

    target_link_libraries(privacy_pass_tests PRIVATE
        privacy_pass
        doctest::doctest
    )
    if(PRIVACY_PASS_BUILD_MOQ)
        target_link_libraries(privacy_pass_tests PRIVATE privacy_pass_moq)
    endif()

    add_test(NAME privacy_pass_tests COMMAND privacy_pass_tests)
endif()

# Benchmarks
if(PRIVACY_PASS_BUILD_BENCHMARKS)
    add_executable(privacy_pass_benchmarks
        benchmarks/bench_main.cpp
        benchmarks/bench_crypto.cpp
        benchmarks/bench_token_issuance.cpp
        benchmarks/bench_serialization.cpp
    )
    privacy_pass_set_warnings(privacy_pass_benchmarks)

    target_link_libraries(privacy_pass_benchmarks PRIVATE
        privacy_pass
        benchmark::benchmark
    )
endif()

# Examples
if(PRIVACY_PASS_BUILD_EXAMPLES)
    add_executable(example_basic_flow examples/basic_flow.cpp)
    target_link_libraries(example_basic_flow PRIVATE privacy_pass)
    privacy_pass_set_warnings(example_basic_flow)

    if(PRIVACY_PASS_BUILD_MOQ)
        add_executable(example_moq_client examples/moq_client.cpp)
        target_link_libraries(example_moq_client PRIVATE privacy_pass privacy_pass_moq)
        privacy_pass_set_warnings(example_moq_client)

        add_executable(example_moq_relay examples/moq_relay.cpp)
        target_link_libraries(example_moq_relay PRIVATE privacy_pass privacy_pass_moq)
        privacy_pass_set_warnings(example_moq_relay)

        add_executable(example_moq_blind_rsa_auth examples/moq_blind_rsa_auth.cpp)
        target_link_libraries(example_moq_blind_rsa_auth PRIVATE privacy_pass privacy_pass_moq)
        privacy_pass_set_warnings(example_moq_blind_rsa_auth)
    endif()
endif()

# Install (simplified - without export)
include(GNUInstallDirs)

set(INSTALL_TARGETS
    privacy_pass_core
    privacy_pass_crypto
    privacy_pass_http
    privacy_pass_client
    privacy_pass_issuer
    privacy_pass_origin
    privacy_pass_provider
    privacy_pass_authenticator
)
if(PRIVACY_PASS_BUILD_MOQ)
    list(APPEND INSTALL_TARGETS privacy_pass_moq)
endif()

install(TARGETS ${INSTALL_TARGETS}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if(PRIVACY_PASS_BUILD_MOQ)
    install(DIRECTORY extensions/moq/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()
