/*
 * Copyright (c) 2019-2020, Nuvoton Technology Corporation
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

#include "mbed.h"

#define ETHERNET 1
#define WIFI 2
#define MESH 3
#define CELLULAR 4

EthInterface *EthInterface::get_default_instance()
{
    return get_target_default_instance();
}

WiFiInterface *WiFiInterface::get_default_instance()
{
    return get_target_default_instance();
}

#include "ESP8266Interface.h"

#define ESP8266_AT_ONBOARD      1   // On-board ESP8266
#define ESP8266_AT_EXTERN       2   // External ESP8266

#ifndef ESP8266_AT_SEL
#warning "ESP8266_AT_SEL missing. Defaults to ESP8266_AT_ONBOARD."
#define ESP8266_AT_SEL          ESP8266_AT_ONBOARD
#endif

WiFiInterface *WiFiInterface::get_target_default_instance()
{
    /* ESP8266Interface(TX, RX, debug, RTS, CTS, RST); */

#if ESP8266_AT_SEL == ESP8266_AT_ONBOARD

    #if TARGET_NUMAKER_IOT_M487
    static ESP8266Interface esp(PH_8, PH_9, false, NC, NC, PH_3);

    #elif TARGET_NUMAKER_PFM_M2351
    static DigitalOut esp_pwr_off(PD_7, 1);     // Disable power to on-board ESP8266
    static ESP8266Interface esp(PD_1, PD_0, false, PD_3, PD_2, NC);

    if ((int) esp_pwr_off) {                    // Turn on on-board ESP8266
        wait_ms(50);
        esp_pwr_off = 0;
        wait_ms(50);
    }

    #else
    static ESP8266Interface esp;

    #endif

#elif ESP8266_AT_SEL == ESP8266_AT_EXTERN

    #if TARGET_NUMAKER_PFM_NANO130
    static ESP8266Interface esp(D1, D0, false, PB_6, PB_7, D2);

    #elif TARGET_NUMAKER_PFM_NUC472
    static ESP8266Interface esp(PD_15, PF_0, false, PD_14, PD_13, D2);

    #elif TARGET_NUMAKER_PFM_M453
    static ESP8266Interface esp(A3, A2, false, A5, A4, D2);

    #elif TARGET_NUMAKER_PFM_M487 || TARGET_NUMAKER_IOT_M487
    static ESP8266Interface esp(D1, D0, false, A2, A3, D2);

    #elif TARGET_NUMAKER_PFM_M2351
    static ESP8266Interface esp(D1, D0, false, A3, A2, D2);

    #else
    static ESP8266Interface esp;

    #endif

#endif

    return &esp;
}

NetworkInterface *NetworkInterface::get_default_instance()
{
    return get_target_default_instance();
}

#if MBED_CONF_TARGET_NETWORK_DEFAULT_INTERFACE_TYPE == ETHERNET
NetworkInterface *NetworkInterface::get_target_default_instance()
{
    return EthInterface::get_default_instance();
}

#elif MBED_CONF_TARGET_NETWORK_DEFAULT_INTERFACE_TYPE == WIFI
NetworkInterface *NetworkInterface::get_target_default_instance()
{
    /* WiFi is not expected to work unless we have configuration parameters.
     * We do not hook up to WifiInterface::get_default_instance() unless
     * we have at least an access point name.
     */
#ifdef MBED_CONF_NSAPI_DEFAULT_WIFI_SSID
    WiFiInterface *wifi = WiFiInterface::get_default_instance();
    if (!wifi) {
        return NULL;
    }
#ifndef MBED_CONF_NSAPI_DEFAULT_WIFI_PASSWORD
#define MBED_CONF_NSAPI_DEFAULT_WIFI_PASSWORD NULL
#endif
#ifndef MBED_CONF_NSAPI_DEFAULT_WIFI_SECURITY
#define MBED_CONF_NSAPI_DEFAULT_WIFI_SECURITY NONE
#endif
#define concat_(x,y) x##y
#define concat(x,y) concat_(x,y)
#define SECURITY concat(NSAPI_SECURITY_,MBED_CONF_NSAPI_DEFAULT_WIFI_SECURITY)
    wifi->set_credentials(MBED_CONF_NSAPI_DEFAULT_WIFI_SSID, MBED_CONF_NSAPI_DEFAULT_WIFI_PASSWORD, SECURITY);
    return wifi;
#else
    return NULL;
#endif
}

#endif
