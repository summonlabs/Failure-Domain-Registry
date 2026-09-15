// Failure Domain Registry — the shared entry point for the test executables.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every test executable links this translation unit through the shared test
// support library, so no individual suite has to define main. Arguments of the
// form "--name value" are captured by the harness and are readable from a suite
// with fdrtest::option().

#include "test_harness.hpp"

int main(int argc, char** argv) { return fdrtest::run_all(argc, argv); }
