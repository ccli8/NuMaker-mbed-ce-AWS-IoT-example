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

#ifndef __AWSIOT_CREDENTIALS_H__
#define __AWSIOT_CREDENTIALS_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* AWS IoT certificats or keys in PEM or DER format
 *
 * NOTE: If PEM format, the length will also include the terminating
 *       null byte for passing to mbedtls straight.
 */
extern const void *awsiot_rootca_cert;
extern const size_t awsiot_rootca_cert_len;
extern const void *awsiot_device_cert;
extern const size_t awsiot_device_cert_len;
extern const void *awsiot_device_privkey;
extern const size_t awsiot_device_privkey_len;

#ifdef __cplusplus
}
#endif

#endif
