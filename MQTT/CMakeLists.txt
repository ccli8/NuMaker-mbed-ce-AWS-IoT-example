# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(MQTT INTERFACE)

add_subdirectory(FP)
add_subdirectory(MQTTPacket)

target_include_directories(MQTT
    INTERFACE
        .
)

target_link_libraries(MQTT
    INTERFACE
        FP
        MQTTPacket
)
