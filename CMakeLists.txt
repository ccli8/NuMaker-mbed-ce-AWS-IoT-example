# Copyright (c) 2022 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.19)
cmake_policy(VERSION 3.19)

# Set default path for Mbed OS library (no force-write for override)
set(MBED_OS_PATH ${CMAKE_CURRENT_SOURCE_DIR}/mbed-os CACHE INTERNAL "")

# Set default path for mbed_app.json5 (no force-write for override)
set(MBED_APP_JSON_PATH mbed_app.json5 CACHE INTERNAL "")

# Set default path for custom_targets.json5 (no force-write for override)
set(CUSTOM_TARGETS_PATH custom_targets CACHE INTERNAL "")
set(CUSTOM_TARGETS_JSON_PATH ${CUSTOM_TARGETS_PATH}/custom_targets.json5 CACHE INTERNAL "")

# Include Mbed toolchain setup file
include(mbed-os/tools/cmake/mbed_toolchain_setup.cmake)

set(APP_PROJECT NUMAKER_MBED_CE_AWS_IOT_EXAMPLE)
set(APP_TARGET NuMaker-mbed-ce-AWS-IoT-example)

# Set up project name
project(${APP_PROJECT})

# Include Mbed project setup file
include(mbed_project_setup)

# Add for custom targets
add_subdirectory(${CUSTOM_TARGETS_PATH})

# Add Mbed OS library
add_subdirectory(${MBED_OS_PATH})

# Add other libraries
add_subdirectory(MQTT)

# Add RHE6616TP01 LCD
if("COMPONENT_RHE6616TP01_LCD=1" IN_LIST MBED_TARGET_DEFINITIONS)
    add_subdirectory(drivers/COMPONENT_RHE6616TP01_LCD)
endif()

# Add BME680 sensor
if("COMPONENT_BME680=1" IN_LIST MBED_TARGET_DEFINITIONS)
    add_subdirectory(drivers/COMPONENT_BME680)
endif()

# User-provided MBEDTLS_USER_CONFIG_FILE for mbedtls
target_include_directories(mbed-mbedtls
    PUBLIC
        .
)

add_executable(${APP_TARGET})

target_include_directories(${APP_TARGET}
    PRIVATE
        .
        my-tlssocket
        pre-main
)

target_sources(${APP_TARGET}
    PRIVATE
        configs/awsiot_credentials.c
        main.cpp
        my-tlssocket/MyTLSSocket.cpp
        pre-main/dispatch_host_command.cpp
        pre-main/fetch_host_command.cpp
        pre-main/mbed_main.cpp
        pre-main/mem_stats.cpp
        pre-main/provision.cpp
        pre-main/pump_host_command.cpp
)

if("NUVOTON" IN_LIST MBED_TARGET_LABELS)
    target_sources(${APP_TARGET}
        PRIVATE
            "targets/TARGET_NUVOTON/platform_entropy.cpp"
    )
endif()

target_link_libraries(${APP_TARGET}
    PRIVATE
        mbed-os
        mbed-mbedtls
        mbed-netsocket
        mbed-storage-kv-global-api
        MQTT
        $<$<IN_LIST:COMPONENT_RHE6616TP01_LCD=1,${MBED_TARGET_DEFINITIONS}>:rhe6616tp01-lcd>
        $<$<IN_LIST:COMPONENT_BME680=1,${MBED_TARGET_DEFINITIONS}>:bme680>
)

# Must call this for each target to set up bin file creation, code upload, etc
mbed_set_post_build(${APP_TARGET})
