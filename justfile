# Privacy Pass C++ - Build Commands

default:
    @just --list

# Build options
build_type := "Release"
moq := "ON"
sanitizers := "OFF"
backend := "openssl"

# BoringSSL path (override with: just boringssl_dir=/path/to/boringssl ...)
boringssl_dir := env("BORINGSSL_DIR", "../boringssl")

# OpenSSL path (override with: just openssl_dir=/path/to/openssl ...)
# Leave empty to use system default
openssl_dir := env("OPENSSL_DIR", "")

# Resolved build directory per backend
build_dir := if backend == "boringssl" { "build-boringssl" } else { "build" }

# ── Configure ────────────────────────────────────────────────────────────────

# Configure CMake for the selected backend
configure:
    cmake -B {{build_dir}} \
        -DCMAKE_BUILD_TYPE={{build_type}} \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DPRIVACY_PASS_BUILD_MOQ={{moq}} \
        -DPRIVACY_PASS_ENABLE_SANITIZERS={{sanitizers}} \
        -DPRIVACY_PASS_CRYPTO_BACKEND={{backend}} \
        {{ if backend == "boringssl" { "-DOPENSSL_ROOT_DIR=" + boringssl_dir + " -DOPENSSL_INCLUDE_DIR=" + boringssl_dir + "/include -DOPENSSL_CRYPTO_LIBRARY=" + boringssl_dir + "/build/libcrypto.a -DOPENSSL_SSL_LIBRARY=" + boringssl_dir + "/build/libssl.a" } else if openssl_dir != "" { "-DOPENSSL_ROOT_DIR=" + openssl_dir } else { "" } }}

# ── Build ────────────────────────────────────────────────────────────────────

# Build all targets
build: configure
    cmake --build {{build_dir}} --parallel

# Build debug (shorthand for build_type=Debug sanitizers=ON)
build-debug:
    just build_type=Debug sanitizers=ON backend={{backend}} build

# Full rebuild
rebuild:
    just clean backend={{backend}} && just moq={{moq}} build_type={{build_type}} sanitizers={{sanitizers}} backend={{backend}} build

# ── Test ─────────────────────────────────────────────────────────────────────

# Run tests
test: build
    cd {{build_dir}} && ctest --output-on-failure

# Run tests with verbose output
test-verbose: build
    cd {{build_dir}} && ./privacy_pass_tests --success

# Run a specific test suite
test-suite suite: build
    cd {{build_dir}} && ./privacy_pass_tests --test-suite="{{suite}}"

# Run crypto provider tests only
test-crypto: build
    cd {{build_dir}} && ./privacy_pass_tests --test-suite="Crypto Provider"

# ── Benchmarks ───────────────────────────────────────────────────────────────

# Run benchmarks
bench: build
    cd {{build_dir}} && ./privacy_pass_benchmarks

# Run provider-labeled benchmarks (for cross-backend comparison)
bench-provider: build
    cd {{build_dir}} && ./privacy_pass_benchmarks --benchmark_filter="BM_Provider_"

# Run benchmarks with specific filter
bench-filter filter: build
    cd {{build_dir}} && ./privacy_pass_benchmarks --benchmark_filter={{filter}}

# Save benchmark results as JSON
bench-json: build
    cd {{build_dir}} && ./privacy_pass_benchmarks --benchmark_out={{backend}}_bench.json --benchmark_out_format=json

# ── Multi-backend ────────────────────────────────────────────────────────────

# Build and test with OpenSSL (system default)
test-openssl:
    just backend=openssl test

# Build and test with OpenSSL 1.1 (requires openssl_dir or OPENSSL_DIR set)
test-openssl11 dir="/usr/local/opt/openssl@1.1":
    just backend=openssl openssl_dir={{dir}} test

# Build and test with OpenSSL 3.x (requires openssl_dir or OPENSSL_DIR set)
test-openssl3 dir="/usr/local/opt/openssl@3":
    just backend=openssl openssl_dir={{dir}} test

# Build and test with BoringSSL
test-boringssl:
    just backend=boringssl test

# Build and test all backends (system OpenSSL + BoringSSL)
test-all:
    just backend=openssl test
    just backend=boringssl test

# Build and test all crypto variants (OpenSSL 1.1, OpenSSL 3.x, BoringSSL)
test-all-crypto openssl11_dir="/usr/local/opt/openssl@1.1" openssl3_dir="/usr/local/opt/openssl@3":
    just test-openssl11 dir={{openssl11_dir}}
    just test-openssl3 dir={{openssl3_dir}}
    just test-boringssl

# Run provider benchmarks on both backends
bench-all:
    just backend=openssl bench-provider
    @echo ""
    just backend=boringssl bench-provider

# Save benchmark JSON for both backends
bench-all-json:
    just backend=openssl bench-json
    just backend=boringssl bench-json

# ── BoringSSL setup ──────────────────────────────────────────────────────────

# Clone and build BoringSSL (one-time setup)
setup-boringssl:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -d "{{boringssl_dir}}" ]; then
        git clone https://boringssl.googlesource.com/boringssl "{{boringssl_dir}}"
    fi
    cmake -B "{{boringssl_dir}}/build" -S "{{boringssl_dir}}" -GNinja -DCMAKE_BUILD_TYPE=Release
    cmake --build "{{boringssl_dir}}/build" --target crypto ssl
    echo "BoringSSL built at {{boringssl_dir}}"

# ── Cleanup ──────────────────────────────────────────────────────────────────

# Clean build directory for selected backend
clean:
    rm -rf {{build_dir}}

# Clean all build directories
clean-all:
    rm -rf build build-boringssl

# ── Code quality ─────────────────────────────────────────────────────────────

# Format code
format:
    find include src tests benchmarks examples extensions -name "*.cpp" -o -name "*.hpp" | xargs clang-format -i

# Check formatting
format-check:
    find include src tests benchmarks examples extensions -name "*.cpp" -o -name "*.hpp" | xargs clang-format --dry-run --Werror

# Static analysis
lint:
    find src -name '*.cpp' -exec clang-tidy {} -- -I include -std=c++23 \;

# Generate compile_commands.json for IDE support
compile-commands: configure
    cp {{build_dir}}/compile_commands.json .

# ── Dependencies ─────────────────────────────────────────────────────────────

# Install dependencies (macOS)
deps-macos:
    brew install openssl@3 spdlog cmake

# Install dependencies (Ubuntu)
deps-ubuntu:
    sudo apt-get update && sudo apt-get install -y libssl-dev libspdlog-dev cmake

# ── Debug / analysis ─────────────────────────────────────────────────────────

# Run memory check with valgrind
memcheck: build-debug
    valgrind --leak-check=full --show-leak-kinds=all {{build_dir}}/privacy_pass_tests

# Generate documentation
docs:
    doxygen Doxyfile

# Run all checks
check: format-check lint test
