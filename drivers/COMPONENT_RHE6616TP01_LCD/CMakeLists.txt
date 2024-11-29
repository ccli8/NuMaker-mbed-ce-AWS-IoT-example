# Copyright (c) 2020-2021 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(rhe6616tp01-lcd STATIC EXCLUDE_FROM_ALL)

if("M2354" IN_LIST MBED_TARGET_LABELS)
    add_subdirectory(TARGET_M2354)
endif()
