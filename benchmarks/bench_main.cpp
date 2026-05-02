// SPDX-FileCopyrightText: Copyright (c) 2025 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include <benchmark/benchmark.h>
#include <privacy_pass/privacy_pass.hpp>

int main(int argc, char** argv) {
    privacy_pass::initialize();

    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    privacy_pass::shutdown();
    return 0;
}
