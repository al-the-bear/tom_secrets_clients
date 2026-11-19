# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
#
# The conformance runner of the C client, built with the library from the
# repository (clients/c).
cmake_minimum_required(VERSION 3.16)
project(conformance_runner_c LANGUAGES C)

set(TSM_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../clients/c ${CMAKE_CURRENT_BINARY_DIR}/tsm)

add_executable(conformance-runner-c runner.c)
target_link_libraries(conformance-runner-c PRIVATE tsm::tsm)
# The runner uses the library's JSON and platform layer.
target_include_directories(conformance-runner-c PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../clients/c/src)
set_target_properties(conformance-runner-c PROPERTIES
  C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
  # One place for the binary in every generator (multi-config ones too).
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin
  RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin)
if(WIN32)
  # The portable C functions, not MSVC's _s variants.
  target_compile_definitions(conformance-runner-c PRIVATE WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
else()
  target_compile_definitions(conformance-runner-c PRIVATE _POSIX_C_SOURCE=200809L)
  if(APPLE)
    target_compile_definitions(conformance-runner-c PRIVATE _DARWIN_C_SOURCE)
  endif()
endif()
