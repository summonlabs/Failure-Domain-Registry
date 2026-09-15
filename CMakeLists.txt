# Failure Domain Registry - build, test, install and packaging rules.
#
# Copyright 2026 Summon Software Labs.
# Licensed under the Apache License, Version 2.0.
#
# Everything here is target based: no directory-global flags are set, so the
# library, the tools, the benchmarks and the tests each carry exactly the
# options they need, and nothing this project uses for itself can leak into the
# installed package.

cmake_minimum_required(VERSION 3.20)

project(FailureDomainRegistry
        VERSION 1.0.1
        DESCRIPTION "Correlated-failure classification runtime for the Distributed Fabric Infrastructure stack"
        LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

option(BUILD_SHARED_LIBS "Build failure_domain_registry as a shared library instead of a static one" OFF)

option(FDR_BUILD_TESTS "Build the Failure Domain Registry test suite" ON)
option(FDR_BUILD_TOOLS "Build the Failure Domain Registry command line tools" ON)
option(FDR_BUILD_EXAMPLES "Build the Failure Domain Registry example programs" ON)
option(FDR_BUILD_BENCHMARKS "Build the Failure Domain Registry benchmarks" ON)
option(FDR_WARNINGS_AS_ERRORS "Treat every compiler warning as an error" ON)
option(FDR_SANITIZERS "Build with AddressSanitizer, and UndefinedBehaviorSanitizer on GCC and Clang" OFF)
option(FDR_ANALYZE "Build with the MSVC static analyzer" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CheckCXXCompilerFlag)
include(CTest)

set(FDR_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/FailureDomainRegistry"
    CACHE STRING "Install destination of the Failure Domain Registry CMake package files")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Applies the project build policy to one target. Every entry is PRIVATE, so
# none of it is part of the installed package.
function(fdr_configure_target target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc)
    if(FDR_WARNINGS_AS_ERRORS AND NOT FDR_ANALYZE)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    target_compile_definitions(${target} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_compile_options(${target} PRIVATE $<$<CONFIG:Debug>:/RTC1>)
    target_compile_definitions(${target} PRIVATE $<$<CONFIG:Debug>:_ITERATOR_DEBUG_LEVEL=2>)
    target_compile_options(${target} PRIVATE
      $<$<CONFIG:Release>:/O2>
      $<$<CONFIG:Release>:/Gy>
      $<$<CONFIG:Release>:/Gw>)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
    if(FDR_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
  if(MSVC AND FDR_ANALYZE)
    target_compile_options(${target} PRIVATE /analyze /analyze:WX-)
  endif()
  if(FDR_SANITIZERS)
    target_compile_options(${target} PRIVATE ${FDR_SANITIZER_COMPILE_OPTIONS})
    target_link_options(${target} PRIVATE ${FDR_SANITIZER_LINK_OPTIONS})
  endif()
endfunction()

function(fdr_add_executable target)
  add_executable(${target} ${ARGN})
  target_link_libraries(${target} PRIVATE failure_domain_registry)
  fdr_configure_target(${target})
endfunction()

# ---------------------------------------------------------------------------
# Sanitizers and static analysis
# ---------------------------------------------------------------------------

if(FDR_SANITIZERS)
  if(MSVC)
    check_cxx_compiler_flag("/fsanitize=address" FDR_COMPILER_HAS_ASAN)
    if(NOT FDR_COMPILER_HAS_ASAN)
      message(FATAL_ERROR
        "FDR_SANITIZERS=ON cannot be used with ${CMAKE_CXX_COMPILER_ID} "
        "${CMAKE_CXX_COMPILER_VERSION}: a program built with /fsanitize=address does not "
        "compile and link here. Either the toolset predates AddressSanitizer support "
        "(Visual Studio 2019 16.9) or the optional C++ AddressSanitizer component is not "
        "installed. Reconfigure with -DFDR_SANITIZERS=OFF or install that component.")
    endif()
    set(FDR_SANITIZER_COMPILE_OPTIONS /fsanitize=address /Zi)
    set(FDR_SANITIZER_LINK_OPTIONS /fsanitize=address)
    message(STATUS "FailureDomainRegistry: AddressSanitizer enabled (MSVC)")
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    check_cxx_compiler_flag("-fsanitize=address,undefined" FDR_COMPILER_HAS_ASAN_UBSAN)
    if(NOT FDR_COMPILER_HAS_ASAN_UBSAN)
      message(FATAL_ERROR
        "FDR_SANITIZERS=ON cannot be used with ${CMAKE_CXX_COMPILER_ID} "
        "${CMAKE_CXX_COMPILER_VERSION}: the sanitizer runtime is unavailable. "
        "Reconfigure with -DFDR_SANITIZERS=OFF.")
    endif()
    set(FDR_SANITIZER_COMPILE_OPTIONS -fsanitize=address,undefined -fno-omit-frame-pointer)
    set(FDR_SANITIZER_LINK_OPTIONS -fsanitize=address,undefined)
    message(STATUS "FailureDomainRegistry: AddressSanitizer and UndefinedBehaviorSanitizer enabled")
  else()
    message(FATAL_ERROR
      "FDR_SANITIZERS=ON is supported with MSVC (/fsanitize=address) and with GCC or Clang "
      "(-fsanitize=address,undefined); the configured compiler is "
      "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}. "
      "Reconfigure with -DFDR_SANITIZERS=OFF.")
  endif()
endif()

# ---------------------------------------------------------------------------
# failure_domain_registry
# ---------------------------------------------------------------------------

set(FDR_SOURCES
  src/version.cpp
  src/ids.cpp
  src/entity.cpp
  src/domain_class.cpp
  src/lifecycle.cpp
  src/relation.cpp
  src/provenance.cpp
  src/authority.cpp
  src/limits.cpp
  src/errors.cpp
  src/digest.cpp
  src/explanation.cpp
  src/domain.cpp
  src/membership.cpp
  src/derivation.cpp
  src/coverage.cpp
  src/registry.cpp
  src/registry_authority.cpp
  src/registry_query.cpp
  src/registry_digest.cpp
  src/registry_mutations.cpp
  src/registry_derivation.cpp
  src/persistence.cpp
  src/frame.cpp
  src/transport.cpp
  src/message_codec.cpp
  src/coordinator.cpp
  src/publisher.cpp
  src/discovery.cpp
  src/synthetic.cpp)

add_library(failure_domain_registry ${FDR_SOURCES})
add_library(SummonSoftwareLabs::FailureDomainRegistry ALIAS failure_domain_registry)

set_target_properties(failure_domain_registry PROPERTIES
  # Consumers link SummonSoftwareLabs::FailureDomainRegistry: the exported name
  # is the project name, the artifact keeps the library name.
  EXPORT_NAME FailureDomainRegistry
  OUTPUT_NAME failure_domain_registry
  VERSION ${PROJECT_VERSION}
  SOVERSION 1
  VISIBILITY_INLINES_HIDDEN ON
  POSITION_INDEPENDENT_CODE ON)

if(BUILD_SHARED_LIBS)
  set_target_properties(failure_domain_registry PROPERTIES CXX_VISIBILITY_PRESET hidden)
  target_compile_definitions(failure_domain_registry PRIVATE FAILURE_DOMAIN_REGISTRY_BUILD_SHARED)
  target_compile_definitions(failure_domain_registry INTERFACE FAILURE_DOMAIN_REGISTRY_USE_SHARED)
endif()

target_include_directories(failure_domain_registry
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_compile_features(failure_domain_registry PUBLIC cxx_std_20)

if(WIN32)
  # Winsock plus the Plug and Play APIs the discovery translation unit reads.
  # PRIVATE: none of this belongs to the public interface.
  target_link_libraries(failure_domain_registry PRIVATE ws2_32 setupapi cfgmgr32 ole32)
endif()

fdr_configure_target(failure_domain_registry)

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

if(FDR_BUILD_TOOLS)
  fdr_add_executable(fdr-cli tools/fdr_cli.cpp)
  fdr_add_executable(fdr-coordinator tools/coordinator_main.cpp)
  fdr_add_executable(fdr-publisher tools/publisher_main.cpp)
endif()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------

if(FDR_BUILD_EXAMPLES)
  file(GLOB FDR_EXAMPLE_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/examples/*.cpp")
  foreach(example_source IN LISTS FDR_EXAMPLE_SOURCES)
    get_filename_component(example_stem "${example_source}" NAME_WE)
    fdr_add_executable(fdr-example-${example_stem} "${example_source}")
  endforeach()
  if(NOT FDR_EXAMPLE_SOURCES)
    message(STATUS "FailureDomainRegistry: FDR_BUILD_EXAMPLES is ON but examples/ has no program yet")
  endif()
endif()

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

if(FDR_BUILD_BENCHMARKS)
  fdr_add_executable(fdr-benchmarks benchmarks/benchmark_registry.cpp)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(BUILD_TESTING AND FDR_BUILD_TESTS)
  # One executable per translation unit in tests/. tests/support is the shared
  # harness; tests/package_consumer is a standalone downstream project that is
  # configured separately against the installed package.
  file(GLOB FDR_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp")
  file(GLOB FDR_TEST_SUPPORT_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/support/*.cpp")

  if(FDR_TEST_SUPPORT_SOURCES)
    add_library(failure_domain_registry_test_support STATIC ${FDR_TEST_SUPPORT_SOURCES})
    set_target_properties(failure_domain_registry_test_support PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_link_libraries(failure_domain_registry_test_support PUBLIC failure_domain_registry)
    target_include_directories(failure_domain_registry_test_support PUBLIC
      "${CMAKE_CURRENT_SOURCE_DIR}/tests"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/support")
    fdr_configure_target(failure_domain_registry_test_support)
  endif()

  foreach(test_source IN LISTS FDR_TEST_SOURCES)
    # tests/test_ids.cpp -> fdr-test-ids
    get_filename_component(test_stem "${test_source}" NAME_WE)
    string(REGEX REPLACE "^test_" "" test_suffix "${test_stem}")
    set(test_target "fdr-test-${test_suffix}")

    fdr_add_executable(${test_target} "${test_source}")
    if(TARGET failure_domain_registry_test_support)
      target_link_libraries(${test_target} PRIVATE failure_domain_registry_test_support)
    endif()

    # The multi-process suite drives the real tools, so they must exist first.
    if(TARGET fdr-coordinator AND TARGET fdr-publisher)
      add_dependencies(${test_target} fdr-coordinator fdr-publisher)
    endif()

    if(test_stem STREQUAL "test_multiprocess" AND TARGET fdr-coordinator AND TARGET fdr-publisher)
      add_test(NAME ${test_target}
               COMMAND ${test_target} multiprocess
                       --coordinator $<TARGET_FILE:fdr-coordinator>
                       --publisher $<TARGET_FILE:fdr-publisher>)
    else()
      add_test(NAME ${test_target} COMMAND ${test_target})
    endif()
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Installation and packaging
# ---------------------------------------------------------------------------

install(TARGETS failure_domain_registry
        EXPORT FailureDomainRegistryTargets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT FailureDomainRegistryTargets
        NAMESPACE SummonSoftwareLabs::
        DESTINATION ${FDR_INSTALL_CMAKEDIR})

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/FailureDomainRegistryConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/FailureDomainRegistryConfig.cmake"
  INSTALL_DESTINATION "${FDR_INSTALL_CMAKEDIR}"
  PATH_VARS CMAKE_INSTALL_INCLUDEDIR)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/FailureDomainRegistryConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/FailureDomainRegistryConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/FailureDomainRegistryConfigVersion.cmake"
        DESTINATION ${FDR_INSTALL_CMAKEDIR})

# The build tree is usable by a sibling project without installing first.
export(EXPORT FailureDomainRegistryTargets
       NAMESPACE SummonSoftwareLabs::
       FILE "${CMAKE_CURRENT_BINARY_DIR}/FailureDomainRegistryTargets.cmake")
