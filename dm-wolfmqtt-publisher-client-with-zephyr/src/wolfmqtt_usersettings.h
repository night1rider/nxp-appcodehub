/* user_settings.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFMQTT_ZEPHYR_SAMPLE_SETTINGS_H
#define WOLFMQTT_ZEPHYR_SAMPLE_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_WOLFSSL_SETTINGS_FILE
#include CONFIG_WOLFSSL_SETTINGS_FILE
#endif

#undef NO_FILESYSTEM
#define NO_FILESYSTEM
#define WOLFMQTT_V5
#define ENABLE_MQTT_TLS


#if defined(CONFIG_WOLFSSL_DEBUG)
#undef  DEBUG_WOLFSSL
#define DEBUG_WOLFSSL
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFMQTT_ZEPHYR_SAMPLE_SETTINGS_H */