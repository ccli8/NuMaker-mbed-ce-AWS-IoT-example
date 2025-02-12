/*
 *  Copyright (C) 2006-2016, Arm Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_ENTROPY_HARDWARE_ALT) && \
    !defined(MBEDTLS_ENTROPY_NV_SEED) && !defined(MBEDTLS_TEST_NULL_ENTROPY)
#error "This hardware does not have an entropy source."
#endif /* !MBEDTLS_ENTROPY_HARDWARE_ALT && !MBEDTLS_ENTROPY_NV_SEED &&
        * !MBEDTLS_TEST_NULL_ENTROPY */

#if !defined(MBEDTLS_SHA1_C)
#define MBEDTLS_SHA1_C
#endif /* !MBEDTLS_SHA1_C */

/*
 *  This value is sufficient for handling 2048 bit RSA keys.
 *
 *  Set this value higher to enable handling larger keys, but be aware that this
 *  will increase the stack usage.
 */
#if (MBEDTLS_MPI_MAX_SIZE < 256)
#undef MBEDTLS_MPI_MAX_SIZE
#define MBEDTLS_MPI_MAX_SIZE        256
#endif

#define MBEDTLS_MPI_WINDOW_SIZE     1

#if defined(TARGET_STM32F439xI) && defined(MBEDTLS_CONFIG_HW_SUPPORT)
#undef MBEDTLS_AES_ALT
#endif /* TARGET_STM32F439xI && MBEDTLS_CONFIG_HW_SUPPORT */

/* Maximum length (in bytes) of incoming plaintext fragments */
#define MBEDTLS_SSL_IN_CONTENT_LEN      8192 

/* Maximum length (in bytes) of outgoing plaintext fragments */
#define MBEDTLS_SSL_OUT_CONTENT_LEN     8192 
