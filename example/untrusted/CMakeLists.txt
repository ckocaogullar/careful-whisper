set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11")

if(EXISTS "${SGX_PATH}/include/sgx_uae_launch.h")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_SGX_UAE_LAUNCH_H")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_SGX_UAE_LAUNCH_H")
endif(EXISTS "${SGX_PATH}/include/sgx_uae_launch.h")

include_directories(${PROJECT_SOURCE_DIR})

set(CLIENT_SRC_FILES Enclave_u.c s_client.cpp Utils.cpp hexutil.c msgio.cpp common.cpp logfile.c crypto.c benchmark.cpp)

set_directory_properties(PROPERTIES
        ADDITIONAL_MAKE_CLEAN_FILES "Enclave_u.c; Enclave_u.h")

add_custom_command(
        OUTPUT Enclave_u.c Enclave_u.h
        COMMAND ${SGX_EDGER8R} --untrusted Enclave.edl
        --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../enclave/ # enclave.edl
        --search-path ${SGX_PATH}/include
        --search-path ${SGX_LIBRARY_PATH}
        --search-path ${CMAKE_SOURCE_DIR}/trusted # mbedtls_sgx.edl
        --search-path /usr/lib/x86_64-linux-gnu/ # libssl.so
        COMMENT "Generating Enclave_u.{c,h}"
)


add_executable(s_client ${CLIENT_SRC_FILES})
add_executable(s_server Enclave_u.c s_server.cpp Utils.cpp)
add_executable(m_server m_server.cpp mbedtls_error.c Enclave_u.c Utils.cpp)


include_directories(
        ${SGX_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${MBEDTLS_SRC_DIR}/include
        ${CMAKE_SOURCE_DIR}/trusted/config
        ${CMAKE_SOURCE_DIR}/trusted/include
        ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(s_client
        -L${SGX_LIBRARY_PATH} /home/cerkoc01/Workspace/careful-whisper/libsgx_uae_service.so -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${MBEDTLS_SGX_LIB_U} -lpthread -l:libsgx_ukey_exchange.a -lsgx_tkey_exchange -l:libssl.so -l:libcrypto.so )

target_link_libraries(s_server
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${MBEDTLS_SGX_LIB_U} -lpthread)

target_link_libraries(m_server
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${MBEDTLS_SGX_LIB_U} -lpthread)

add_dependencies(s_client enclave)
add_dependencies(s_server enclave)
add_dependencies(m_server enclave)
