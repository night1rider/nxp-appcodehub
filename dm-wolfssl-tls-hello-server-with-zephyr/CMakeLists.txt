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
target_include_directories(app PRIVATE src)

add_definitions(-DWOLFSSL_USER_SETTINGS)



# Check if the command is executed by redirecting output to a file (Unix-like systems)
add_custom_command(
    TARGET app POST_BUILD
    COMMAND cd ../__repo__/modules/crypto/wolfssl && ./autogen.sh && ./configure && make
    COMMENT "Echoing HELLO_WORLD after building the app target"
)