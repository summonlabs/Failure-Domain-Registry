# Standalone downstream project.
#
# This is deliberately NOT part of the FailureDomainRegistry build: it stands in
# for a real consumer, is configured on its own against an installed package and
# never references the source tree. Nothing here is installed by the library
# project, and nothing here may assume a build directory.
#
#   cmake -S tests/package_consumer -B <dir> -DCMAKE_PREFIX_PATH=<install prefix>
#   cmake --build <dir>

cmake_minimum_required(VERSION 3.20)

project(FailureDomainRegistryPackageConsumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The consumer keeps the same warning policy as the library it consumes, so a
# downstream build notices a header that warns before a release does.
if(MSVC)
  add_compile_options(/W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc /WX)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# CONFIG mode: the installed package carries the exported target, its include
# directory and the C++20 requirement. Nothing else is needed.
find_package(FailureDomainRegistry CONFIG REQUIRED)

add_executable(fdr-package-consumer main.cpp)
target_link_libraries(fdr-package-consumer PRIVATE SummonSoftwareLabs::FailureDomainRegistry)
