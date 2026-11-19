# The installed C client of the Tom Secrets Manager: find_package(tsm), then
# link tsm::tsm.
include(CMakeFindDependencyMacro)
if(NOT WIN32)
  find_dependency(Threads)
endif()
include("${CMAKE_CURRENT_LIST_DIR}/tsm-targets.cmake")
