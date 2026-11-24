# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
#
# The C client of the Tom Secrets Manager: the static library tsm (target
# tsm::tsm), its tests (ctest) and, as a subproject, nothing else.
cmake_minimum_required(VERSION 3.16)
project(tom_secrets_client_c VERSION 0.2.0 LANGUAGES C)

option(TSM_WERROR "Treat warnings as errors" OFF)
option(TSM_BUILD_TESTS "Build the tests" ${PROJECT_IS_TOP_LEVEL})

add_library(tsm STATIC
  src/client.c
  src/discovery.c
  src/frames.c
  src/json.c
  src/platform.c
  src/reference.c
  src/util.c
  src/value.c)
add_library(tsm::tsm ALIAS tsm)
target_include_directories(tsm
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>
  PRIVATE src)
set_target_properties(tsm PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)

if(WIN32)
  target_link_libraries(tsm PUBLIC ws2_32)
  target_compile_definitions(tsm PRIVATE WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
else()
  find_package(Threads REQUIRED)
  target_link_libraries(tsm PUBLIC Threads::Threads)
  target_compile_definitions(tsm PRIVATE _POSIX_C_SOURCE=200809L)
  if(APPLE)
    target_compile_definitions(tsm PRIVATE _DARWIN_C_SOURCE)
  endif()
  find_library(TSM_MATH m)
  if(TSM_MATH)
    target_link_libraries(tsm PUBLIC ${TSM_MATH})
  endif()
endif()

if(MSVC)
  target_compile_options(tsm PRIVATE /W4 $<$<BOOL:${TSM_WERROR}>:/WX>)
else()
  target_compile_options(tsm PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion
    $<$<BOOL:${TSM_WERROR}>:-Werror>)
endif()

install(TARGETS tsm EXPORT tsm-targets ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
install(EXPORT tsm-targets NAMESPACE tsm:: DESTINATION lib/cmake/tsm)
install(FILES cmake/tsmConfig.cmake DESTINATION lib/cmake/tsm)

if(TSM_BUILD_TESTS)
  enable_testing()
  add_executable(tsm_tests tests/tests.c)
  target_link_libraries(tsm_tests PRIVATE tsm)
  # The tests reach the library's internals (frames, JSON).
  target_include_directories(tsm_tests PRIVATE src)
  set_target_properties(tsm_tests PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  if(WIN32)
    # The portable C functions (sscanf, getenv), not MSVC's _s variants.
    target_compile_definitions(tsm_tests PRIVATE WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
  else()
    target_compile_definitions(tsm_tests PRIVATE _POSIX_C_SOURCE=200809L)
    if(APPLE)
      target_compile_definitions(tsm_tests PRIVATE _DARWIN_C_SOURCE)
    endif()
  endif()
  if(MSVC)
    target_compile_options(tsm_tests PRIVATE /W4 $<$<BOOL:${TSM_WERROR}>:/WX>)
  else()
    target_compile_options(tsm_tests PRIVATE -Wall -Wextra $<$<BOOL:${TSM_WERROR}>:-Werror>)
  endif()
  add_test(NAME tsm_tests COMMAND tsm_tests WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()
