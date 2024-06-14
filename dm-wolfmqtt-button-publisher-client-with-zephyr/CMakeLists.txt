cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(MCXN947-mqtt-client-wolfMQTT)

# Check if the symbolic link __repo__ exists
if(NOT EXISTS "${CMAKE_SOURCE_DIR}/__repo__")
    # Create a symbolic link from __repo__ to the ZEPHYR_BASE environment variable
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E create_symlink $ENV{ZEPHYR_BASE}/.. ${CMAKE_SOURCE_DIR}/__repo__
        COMMAND_ECHO STDOUT
    )
endif()


target_sources(app PRIVATE src/main.c)
#FILE(GLOB app_sources __repo__/modules/lib/wolfmqtt/examples/mqttclient/*.c __repo__/modules/lib/wolfmqtt/examples/*.c __repo__/modules/lib/wolfmqtt/examples/samples/*.c)
#target_sources(app PRIVATE ${app_sources})

target_include_directories(app PRIVATE __repo__/modules/lib/wolfmqtt/zephyr/client_tls)
target_include_directories(app PRIVATE src)


add_definitions(-DWOLFMQTT_ZEPHYR)
add_definitions(-DWOLFMQTT_USER_SETTINGS)
add_definitions(-DWOLFSSL_USER_SETTINGS)