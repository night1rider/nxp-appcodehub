cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolfssl-tls-hello-server)

# Check if the symbolic link __repo__ exists
if(NOT EXISTS "${CMAKE_SOURCE_DIR}/__repo__")
    # Create a symbolic link from __repo__ to the ZEPHYR_BASE environment variable
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E create_symlink $ENV{ZEPHYR_BASE}/.. ${CMAKE_SOURCE_DIR}/__repo__
        COMMAND_ECHO STDOUT
    )
endif()

target_sources(app PRIVATE src/main.c)
target_sources(app PRIVATE __repo__/modules/crypto/wolfssl/wolfcrypt/benchmark/benchmark.c)
target_include_directories(app PRIVATE src)

add_definitions(-DWOLFSSL_USER_SETTINGS)



# Build wolfSSL with ML-KEM and ML-DSA support, then build the client application
add_custom_command(
    TARGET app POST_BUILD
    COMMAND cd ../__repo__/modules/crypto/wolfssl && ./autogen.sh && ./configure --enable-mlkem --enable-dilithium && make
    COMMENT "Building wolfSSL with ML-KEM and ML-DSA support"
)

# Build the client-tls13-filetransfer application
add_custom_command(
    TARGET app POST_BUILD
    COMMAND gcc ${CMAKE_SOURCE_DIR}/client-tls13-filetransfer.c -o ${CMAKE_SOURCE_DIR}/client-tls13-filetransfer -I${CMAKE_SOURCE_DIR}/__repo__/modules/crypto/wolfssl -L${CMAKE_SOURCE_DIR}/__repo__/modules/crypto/wolfssl/src/.libs -lwolfssl
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building client-tls13-filetransfer application"
    DEPENDS ${CMAKE_SOURCE_DIR}/client-tls13-filetransfer.c
)
