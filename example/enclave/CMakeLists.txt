set(SOURCE_FILES
        Enclave_t.c
        ecalls.cpp
        Log.c
        pprint.c
        s_client.c
        s_server.c
        hexstring.c
        ssl_conn_hdlr.cpp)




add_definitions(-DENCLAVE_STD_ALT)

set_directory_properties(PROPERTIES
        ADDITIONAL_MAKE_CLEAN_FILES "Enclave_t.c; Enclave_t.h")

add_custom_command(
        OUTPUT Enclave_t.c Enclave_t.h
        COMMAND ${SGX_EDGER8R} --trusted Enclave.edl
        --search-path ${SGX_PATH}/include
	--search-path ${CMAKE_CURRENT_SOURCE_DIR}
        --search-path ${CMAKE_SOURCE_DIR}/trusted
        COMMENT "Generating Enclave_t.{c,h}")

include_directories(${PROJECT_SOURCE_DIR})

add_library(enclave SHARED ${SOURCE_FILES})

include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_SOURCE_DIR}/trusted/config
	${CMAKE_SOURCE_DIR}/trusted/include
        ${MBEDTLS_SRC_DIR}/include
        ${SGX_PATH}/include
        ${SGX_PATH}/include/tlibc
        ${SGX_PATH}/include/libcxx
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -nostdinc -fvisibility=hidden -fpie -fstack-protector")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++03 -nostdinc++")

set_target_properties(enclave PROPERTIES PREFIX "")

target_link_libraries(enclave "${SGX_COMMON_CFLAGS} \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
    -Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive \
    -Wl,--start-group ${MBEDTLS_SGX_LIB_T} -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tkey_exchange /home/cerkoc01/Workspace/careful-whisper/libsgx_uae_service.so -l${SGX_TSVC_LIB} -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0")

add_custom_command(TARGET enclave
        POST_BUILD
        COMMAND ${SGX_ENCLAVE_SIGNER} sign
        -key ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_private.pem
        -config ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.config.xml
        -enclave enclave.so
        -out enclave.signed.so
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Signing the enclave => ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/enclave.signed.so")

add_dependencies(enclave ${PROJECT_NAME}_t)
add_dependencies(enclave ${PROJECT_NAME}_u)
