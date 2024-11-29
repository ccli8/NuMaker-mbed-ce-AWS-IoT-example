# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(MQTTPacket INTERFACE)

target_include_directories(MQTTPacket
    INTERFACE
        .
)

target_sources(MQTTPacket
    INTERFACE
        MQTTUnsubscribeServer.c
        MQTTUnsubscribeClient.c
        MQTTSubscribeServer.c
        MQTTSubscribeClient.c
        MQTTSerializePublish.c
        MQTTPacket.c
        MQTTFormat.c
        MQTTDeserializePublish.c
        MQTTConnectServer.c
        MQTTConnectClient.c
)

