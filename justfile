# Privacy Pass C++ - Build Commands

set shell := ["zsh", "-cu"]

default:
    @just --list

# Build directory and options
build_dir := "build"
build_type := "Release"
moq := "ON"
sanitizers := "OFF"

# Configure CMake
configure:
    cmake -B {{build_dir}} -DCMAKE_BUILD_TYPE={{build_type}} -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DPRIVACY_PASS_BUILD_MOQ={{moq}} -DPRIVACY_PASS_ENABLE_SANITIZERS={{sanitizers}}

# Build all targets
build: configure
    cmake --build {{build_dir}} --parallel

# Build debug (shorthand for build_type=Debug sanitizers=ON)
build-debug:
    just build_type=Debug sanitizers=ON build

# Run tests
test: build
    cd {{build_dir}} && ctest --output-on-failure

# Run tests with verbose output
test-verbose: build
    cd {{build_dir}} && ./privacy_pass_tests --success

# Run benchmarks
bench: build
    cd {{build_dir}} && ./privacy_pass_benchmarks

# Run benchmarks with specific filter
bench-filter filter: build
    cd {{build_dir}} && ./privacy_pass_benchmarks --benchmark_filter={{filter}}

# Clean build directory
clean:
    rm -rf {{build_dir}}

# Full rebuild
rebuild:
    just clean && just moq={{moq}} build_type={{build_type}} sanitizers={{sanitizers}} build

# Format code
format:
    find include src tests benchmarks -name "*.cpp" -o -name "*.hpp" | xargs clang-format -i

# Check formatting
format-check:
    find include src tests benchmarks -name "*.cpp" -o -name "*.hpp" | xargs clang-format --dry-run --Werror

# Static analysis
lint:
    clang-tidy src/**/*.cpp -- -I include -std=c++20

# Generate compile_commands.json for IDE support
compile-commands: configure
    cp {{build_dir}}/compile_commands.json .

# Install dependencies (macOS)
deps-macos:
    brew install openssl@3 spdlog cmake

# Install dependencies (Ubuntu)
deps-ubuntu:
    sudo apt-get update && sudo apt-get install -y libssl-dev libspdlog-dev cmake

# Run memory check with valgrind
memcheck: build-debug
    valgrind --leak-check=full --show-leak-kinds=all {{build_dir}}/privacy_pass_tests

# Generate documentation
docs:
    doxygen Doxyfile

# Run all checks
check: format-check lint test
