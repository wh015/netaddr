cmake_minimum_required(VERSION 3.7)

set(PROJECT_NAME netaddr)

project(${PROJECT_NAME} LANGUAGES CXX)

if(NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

set(CMAKE_VERBOSE_MAKEFILE ON CACHE BOOL "ON" FORCE)

include(sanitizers OPTIONAL)

option(WITH_TESTS "Build common tests." ON)
option(WITH_BENCHMARKS "Build benchmarks." OFF)
option(WITH_PROFILING "Enable compile options for perf profiling (Linux only)." OFF)

if(NOT MSVC)
    if(WITH_PROFILING)
        add_compile_options(
            -fno-omit-frame-pointer # to collect stacktrace
            -g # to see the source code when annotating
        )
    endif()
endif()

add_compile_options(-msse4.2)

set(BINARY_HEADERS_DIR "${CMAKE_BINARY_DIR}/include/${PROJECT_NAME}")
set(SOURCE_HEADERS_DIR "${CMAKE_SOURCE_DIR}/include/${PROJECT_NAME}")
set(TARGET_HEADERS
    "${SOURCE_HEADERS_DIR}/raw.h"
    "${SOURCE_HEADERS_DIR}/parser4.h"
    "${SOURCE_HEADERS_DIR}/parser6.h"
    "${SOURCE_HEADERS_DIR}/subnet.h"
    "${SOURCE_HEADERS_DIR}/address.h"
)

add_library(${PROJECT_NAME} INTERFACE ${TARGET_HEADERS})
target_include_directories(${PROJECT_NAME} INTERFACE "${CMAKE_BINARY_DIR}/include")
target_include_directories(${PROJECT_NAME} INTERFACE "${CMAKE_SOURCE_DIR}/include")

include(GNUInstallDirs)
install(
    FILES ${TARGET_HEADERS}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}")

if(WITH_TESTS OR WITH_BENCHMARKS)
    enable_testing()

    if(WITH_TESTS)
        add_subdirectory("${CMAKE_SOURCE_DIR}/tests")
    endif()

    if(WITH_BENCHMARKS)
        add_subdirectory("${CMAKE_SOURCE_DIR}/benchmarks")
    endif()
endif()
