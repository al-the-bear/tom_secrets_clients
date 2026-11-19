# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
#
# The conformance runner of the C++ client, built with the client (and the C
# library under it) from the repository.
cmake_minimum_required(VERSION 3.16)
project(conformance_runner_cpp LANGUAGES C CXX)

option(TSM_WERROR "Treat warnings as errors" OFF)
set(TSM_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../clients/cpp ${CMAKE_CURRENT_BINARY_DIR}/tsm_cpp)

add_executable(conformance-runner-cpp runner.cpp)
target_link_libraries(conformance-runner-cpp PRIVATE tsm::cpp)
# The runner uses the C library's JSON.
target_include_directories(conformance-runner-cpp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../clients/c/src)
set_target_properties(conformance-runner-cpp PROPERTIES
  CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF
  # One place for the binary in every generator (multi-config ones too).
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin
  RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin)
if(WIN32)
  target_compile_definitions(conformance-runner-cpp PRIVATE WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS NOMINMAX)
endif()
if(MSVC)
  target_compile_options(conformance-runner-cpp PRIVATE /W4 $<$<BOOL:${TSM_WERROR}>:/WX>)
else()
  target_compile_options(conformance-runner-cpp PRIVATE -Wall -Wextra -Wpedantic $<$<BOOL:${TSM_WERROR}>:-Werror>)
endif()
