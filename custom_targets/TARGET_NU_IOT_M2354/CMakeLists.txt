# Copyright (c) 2020-2021 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

target_include_directories(mbed-nu-iot-m2354
    INTERFACE
        .
)

if(NOT TARGET mbed-m2354-tfm)
    add_library(mbed-m2354-tfm INTERFACE)
endif()

if("TFM_S_FW" IN_LIST MBED_TARGET_LABELS)
    add_subdirectory(COMPONENT_TFM_S_FW)
endif()

