/* wolfssl_user_settings.h
 *
 * Copyright (C) 2014-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfSSH.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif


/* #define WOLFCRYPT_TEST */
/* #define WOLFCRYPT_BENCHMARK */
#define NO_MAIN_DRIVER

#undef  WOLFSSL_ZEPHYR
#define WOLFSSL_ZEPHYR

#undef  WOLFSSL_SMALL_STACK
#define WOLFSSL_SMALL_STACK



#undef  TFM_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT

#undef  ECC_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

#undef  WC_RSA_BLINDING
#define WC_RSA_BLINDING

#undef  HAVE_AESGCM
#define HAVE_AESGCM

#undef  WOLFSSL_SHA512
#define WOLFSSL_SHA512

#undef  WOLFSSL_SHA384
#define WOLFSSL_SHA384

#undef  NO_DSA
#define NO_DSA

#undef  HAVE_ECC
#define HAVE_ECC

#undef  TFM_ECC256
#define TFM_ECC256

#undef  WOLFSSL_BASE64_ENCODE
#define WOLFSSL_BASE64_ENCODE

#undef  NO_RC4
#define NO_RC4

#undef  WOLFSSL_SHA224
#define WOLFSSL_SHA224

#undef  WOLFSSL_SHA3
/* #define WOLFSSL_SHA3 */

#undef  HAVE_POLY1305
#define HAVE_POLY1305

#undef  HAVE_ONE_TIME_AUTH
#define HAVE_ONE_TIME_AUTH

#undef  HAVE_CHACHA
#define HAVE_CHACHA

#undef  HAVE_HASHDRBG
#define HAVE_HASHDRBG

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SUPPORTED_CURVES
#define HAVE_SUPPORTED_CURVES

#undef  HAVE_EXTENDED_MASTER
#define HAVE_EXTENDED_MASTER

#undef  NO_PSK
#define NO_PSK

#undef  NO_MD4
#define NO_MD4

#undef  NO_PWDBASED
#define NO_PWDBASED

#undef  USE_FAST_MATH
#define USE_FAST_MATH

#undef  WOLFSSL_NO_ASM
#define WOLFSSL_NO_ASM

#undef  WOLFSSL_X86_BUILD
#define WOLFSSL_X86_BUILD

#undef  WC_NO_ASYNC_THREADING
#define WC_NO_ASYNC_THREADING

#undef  NO_DES3
#define NO_DES3

#undef  WOLFSSL_STATIC_MEMORY
#define WOLFSSL_STATIC_MEMORY

#undef  WOLFSSL_TLS13
#define WOLFSSL_TLS13

#undef  HAVE_HKDF
#define HAVE_HKDF

#undef  WC_RSA_PSS
#define WC_RSA_PSS

#undef  HAVE_FFDHE_2048
#define HAVE_FFDHE_2048

#undef NO_FILESYSTEM
#define NO_FILESYSTEM

#undef WOLFSSL_SMALL_STACK
#define WOLFSSL_SMALL_STACK

#undef WOLFSSH_SCP
#define WOLFSSH_SCP

#undef NO_APITEST_MAIN_DRIVER
#define NO_APITEST_MAIN_DRIVER

#undef NO_TESTSUITE_MAIN_DRIVER
#define NO_TESTSUITE_MAIN_DRIVER

#undef NO_UNITTEST_MAIN_DRIVER
#define NO_UNITTEST_MAIN_DRIVER

#undef NO_MAIN_DRIVER
#define NO_MAIN_DRIVER

#undef WS_NO_SIGNAL
#define WS_NO_SIGNAL

#undef WS_USE_TEST_BUFFERS
#define WS_USE_TEST_BUFFERS

#undef NO_WOLFSSL_DIR
#define NO_WOLFSSL_DIR

#undef WOLFSSH_NO_NONBLOCKING
#define WOLFSSH_NO_NONBLOCKING

#define DEFAULT_WINDOW_SZ (128 * 128)
#define WOLFSSH_MAX_SFTP_RW 8192

#undef NO_FILESYSTEM
#define NO_FILESYSTEM

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
