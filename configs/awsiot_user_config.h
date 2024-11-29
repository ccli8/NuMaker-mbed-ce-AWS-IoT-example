/*
 * Copyright (c) 2024, Nuvoton Technology Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __AWSIOT_USER_CONFIG_H__
#define __AWSIOT_USER_CONFIG_H__

/* Select MQTTS or HTTPS exclusively */
#define AWS_IOT_MQTTS_TEST  1
#define AWS_IOT_HTTPS_TEST  0
#if (AWS_IOT_MQTTS_TEST && AWS_IOT_HTTPS_TEST)  \
    || (!AWS_IOT_MQTTS_TEST && !AWS_IOT_HTTPS_TEST)
#error "Select MQTTS or HTTPS exclusively"
#endif

#if AWS_IOT_MQTTS_TEST
#define AWS_IOT_MQTT_SERVER_NAME                "a1fljoeglhtf61-ats.iot.us-east-2.amazonaws.com"
#define AWS_IOT_MQTT_SERVER_PORT                8883
#define AWS_IOT_MQTT_THINGNAME                  "Nuvoton-Mbed-D001"
#endif

#if AWS_IOT_HTTPS_TEST
#define AWS_IOT_HTTPS_SERVER_NAME               "a1fljoeglhtf61-ats.iot.us-east-2.amazonaws.com"
#define AWS_IOT_HTTPS_SERVER_PORT               8443
#define AWS_IOT_HTTPS_THINGNAME                 "Nuvoton-Mbed-D001"
#endif

#endif
