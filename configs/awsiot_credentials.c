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

#include "awsiot_credentials.h"

/*
 * PEM-encoded root CA certificate
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN CERTIFICATE-----\n"
 * "...base64 data...\n"
 * "-----END CERTIFICATE-----";
 */
const char AWSIOT_ROOTCA_CERT[] = "-----BEGIN CERTIFICATE-----\n"
    "<AWSIOT_ROOTCA_CERT>\n"
    "-----END CERTIFICATE-----\n";

/*
 * PEM-encoded device certificate
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN CERTIFICATE-----\n"
 * "...base64 data...\n"
 * "-----END CERTIFICATE-----";
 */
const char AWSIOT_DEVICE_CERT[] = "-----BEGIN CERTIFICATE-----\n"
    "<AWSIOT_DEVICE_CERT>\n"
    "-----END CERTIFICATE-----\n";

/*
 * PEM-encoded device private key
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN RSA PRIVATE KEY-----\n"
 * "...base64 data...\n"
 * "-----END RSA PRIVATE KEY-----";
 */
const char AWSIOT_DEVICE_PRIVKEY[] = "-----BEGIN RSA PRIVATE KEY-----\n"
    "<AWSIOT_DEVICE_PRIVKEY>\n"
    "-----END RSA PRIVATE KEY-----\n";

const void *awsiot_rootca_cert = AWSIOT_ROOTCA_CERT;
const size_t awsiot_rootca_cert_len = sizeof(AWSIOT_ROOTCA_CERT);
const void *awsiot_device_cert = AWSIOT_DEVICE_CERT;
const size_t awsiot_device_cert_len = sizeof(AWSIOT_DEVICE_CERT);
const void *awsiot_device_privkey = AWSIOT_DEVICE_PRIVKEY;
const size_t awsiot_device_privkey_len = sizeof(AWSIOT_DEVICE_PRIVKEY);
