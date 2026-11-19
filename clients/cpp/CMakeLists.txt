# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
#
# The C++ client of the Tom Secrets Manager: the header-only library tsm::cpp
# (tsm/tsm.hpp, C++17) over the C client tsm::tsm, and its tests (ctest).
cmake_minimum_required(VERSION 3.16)
project(tom_secrets_client_cpp VERSION 0.1.0 LANGUAGES C CXX)

option(TSM_WERROR "Treat warnings as errors" OFF)
option(TSM_CPP_BUILD_TESTS "Build the C++ client's tests" ${PROJECT_IS_TOP_LEVEL})

if(NOT TARGET tsm)
  set(TSM_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../c ${CMAKE_CURRENT_BINARY_DIR}/tsm_c)
endif()

add_library(tsm_cpp INTERFACE)
add_library(tsm::cpp ALIAS tsm_cpp)
target_include_directories(tsm_cpp INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(tsm_cpp INTERFACE tsm::tsm)
target_compile_features(tsm_cpp INTERFACE cxx_std_17)

install(TARGETS tsm_cpp EXPORT tsm-cpp-targets)
install(DIRECTORY include/ DESTINATION include)

if(TSM_CPP_BUILD_TESTS)
  enable_testing()
  function(tsm_cpp_test name source standard)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE tsm::cpp)
    # The tests reach the C library's internals (JSON, frames, sockets).
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../c/src)
    set_target_properties(${name} PROPERTIES CXX_STANDARD ${standard} CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
    if(WIN32)
      target_compile_definitions(${name} PRIVATE WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS NOMINMAX)
    else()
      target_compile_definitions(${name} PRIVATE _POSIX_C_SOURCE=200809L)
      if(APPLE)
        target_compile_definitions(${name} PRIVATE _DARWIN_C_SOURCE)
      endif()
    endif()
    if(MSVC)
      target_compile_options(${name} PRIVATE /W4 $<$<BOOL:${TSM_WERROR}>:/WX>)
    else()
      target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic $<$<BOOL:${TSM_WERROR}>:-Werror>)
    endif()
    add_test(NAME ${name} COMMAND ${name} WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
  endfunction()
  tsm_cpp_test(tsm_cpp_tests tests/tests.cpp 17)
  # The design's call with C++20 designated initializers compiles and runs.
  tsm_cpp_test(tsm_cpp_designated tests/designated.cpp 20)
endif()
