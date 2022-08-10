# need 3.0 for multiple line strings
cmake_minimum_required(VERSION 3.0)
project(mbedtls_SGX "C" "CXX")

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package(SGX REQUIRED)

set(MBEDTLS_VERSION 2.24.0)

set(COMPILE_EXAMPLES NO CACHE BOOL "Build examples")

set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/${PROJECT_NAME}-${MBEDTLS_VERSION})

set(MBEDTLS_LIB_DIR ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})
set(MBEDTLS_SRC_DIR ${PROJECT_SOURCE_DIR}/external/mbedtls)

add_definitions(-DMBEDTLS_CONFIG_FILE=<config-sgx.h>)

add_subdirectory(trusted)
add_subdirectory(ocall)

if (COMPILE_EXAMPLES)
    add_subdirectory(example)
endif()


message(STATUS "=> SGX_MODE: " ${SGX_MODE})
message(STATUS "=> SGX_HW: " ${SGX_HW})
