# Copyright (c) 2020-2021 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

target_include_directories(rhe6616tp01-lcd
    PUBLIC
        .
)

target_sources(rhe6616tp01-lcd
    PRIVATE
        lcd_api.c
        lcdlib.c
)

target_link_libraries(rhe6616tp01-lcd
    PUBLIC
        mbed-os
)
