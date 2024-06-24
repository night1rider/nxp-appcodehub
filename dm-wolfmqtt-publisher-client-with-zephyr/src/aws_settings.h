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

#ifndef WOLFMQTT_AWS_SETTINGS_H
#define WOLFMQTT_AWS_SETTINGS_H

/* Configuration */
#define APP_NAME                "awsiot"
#define APP_HARDWARE            "mqtt_tls_demo"       /* Name of the application hardware */
#define APP_FIRMWARE_VERSION    LIBWOLFMQTT_VERSION_STRING  /* Firmware version from wolfMQTT */
/* Maximum size for network read/write callbacks */
#ifndef MAX_BUFFER_SIZE
#define MAX_BUFFER_SIZE         512
#endif
/* MQTT broker address */
#define MQTT_HOST        "a2dujmi05ideo2-ats.iot.us-west-2.amazonaws.com"    
/* Device ID for the MQTT client */
#define MQTT_DEVICE_ID          "demoDevice"        
/* Quality of Service level for MQTT */
#define MQTT_QOS                MQTT_QOS_1               
/* Keep alive interval in seconds */
#define MQTT_KEEP_ALIVE_SEC     1   
/* Command timeout in milliseconds */
#define MQTT_CMD_TIMEOUT_MS     1000
#define MQTT_CON_TIMEOUT_MS     5000

#define MQTT_CLIENT_ID       "WolfMQTTClientSimple"
#define MQTT_TOPIC_NAME      "wolfMQTT/example/testTopic"
#define MQTT_PUBLISH_MSG     "Test Publish"

/* Topic for publishing messages */
#define MQTT_PUBLISH_TOPIC      "$aws/things/" MQTT_DEVICE_ID "/shadow/update"  
/* Topic for subscribing to messages */
#define MQTT_SUBSCRIBE_TOPIC    MQTT_PUBLISH_TOPIC  
/* Maximum size of the publish message */
#define MQTT_PUBLISH_MSG_SZ     400
#define WOLFMQTT_DEFAULT_TLS    1
#define MQTT_USERNAME        NULL
#define MQTT_PASSWORD        NULL
#ifdef ENABLE_MQTT_TLS
    #define MQTT_USE_TLS     1
    #define MQTT_PORT        8883
#else
    #define MQTT_USE_TLS     0
    #define MQTT_PORT        1883
#endif
#define MQTT_MAX_PACKET_SZ   512
#define INVALID_SOCKET_FD    -1
#define PRINT_BUFFER_SIZE    80


/* Demo Certificates */
static const char* root_ca =
"-----BEGIN CERTIFICATE-----\n"
"MIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCB\n"
"yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\n"
"ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp\n"
"U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW\n"
"ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0\n"
"aG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCByjEL\n"
"MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW\n"
"ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2ln\n"
"biwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJp\n"
"U2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9y\n"
"aXR5IC0gRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1\n"
"nmAMqudLO07cfLw8RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbex\n"
"t0uz/o9+B1fs70PbZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIz\n"
"SdhDY2pSS9KP6HBRTdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQG\n"
"BO+QueQA5N06tRn/Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+\n"
"rCpSx4/VBEnkjWNHiDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/\n"
"NIeWiu5T6CUVAgMBAAGjgbIwga8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E\n"
"BAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAH\n"
"BgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVy\n"
"aXNpZ24uY29tL3ZzbG9nby5naWYwHQYDVR0OBBYEFH/TZafC3ey78DAJ80M5+gKv\n"
"MzEzMA0GCSqGSIb3DQEBBQUAA4IBAQCTJEowX2LP2BqYLz3q3JktvXf2pXkiOOzE\n"
"p6B4Eq1iDkVwZMXnl2YtmAl+X6/WzChl8gGqCBpH3vn5fJJaCGkgDdk+bW48DW7Y\n"
"5gaRQBi5+MHt39tBquCWIMnNZBU4gcmU7qKEKQsTb47bDN0lAtukixlE0kF6BWlK\n"
"WE9gyn6CagsCqiUXObXbf+eEZSqVir2G3l6BFoMtEMze/aiCKm0oHw0LxOXnGiYZ\n"
"4fQRbxC1lfznQgUy286dUV4otp6F01vvpX1FQHKOtw5rDgb7MzVIcbidJ4vEZV8N\n"
"hnacRHr2lVz2XTIIM6RUthg/aFzyQkqFOFSDX9HoLPKsEdao7WNq\n"
"-----END CERTIFICATE-----";

#if 0
static const char* device_pub_key =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqsAKVhbfQEWblC8Pvgub\n"
"qpJasVoCEsSfvLF4b5DIAsoMeieP26y6Vyd3njRyuigSQ6jP+mo3GyqSfeCbqfJ2\n"
"dx3BNICEk7P46Bu37ewoI24pScnT+5Rcfw//dh8WHDq0d0933i4vOKEKA6ft51Ax\n"
"Y6KzvNrwxo6bml0Vi2DBx3WLGw+MDiHXk2L0geSYSNjFz/u9dkgEUPhEGbNZuw2y\n"
"xhwbNfaiPe2ld5Fir6iUybuj93xfWqqNls77V6Qj7mI8pamdGFtQnkP+6l2XTa6J\n"
"bunCqZo1PURtUXch5db6rMq/6rRZrlJM7NngPI1vv8jF4T3G4mjyT8I4KxQK1s90\n"
"9QIDAQAB\n"
"-----END PUBLIC KEY-----";
#endif

static const char* device_priv_key =
#ifndef WOLFSSL_ENCRYPTED_KEYS
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEpAIBAAKCAQEAqsAKVhbfQEWblC8PvgubqpJasVoCEsSfvLF4b5DIAsoMeieP\n"
"26y6Vyd3njRyuigSQ6jP+mo3GyqSfeCbqfJ2dx3BNICEk7P46Bu37ewoI24pScnT\n"
"+5Rcfw//dh8WHDq0d0933i4vOKEKA6ft51AxY6KzvNrwxo6bml0Vi2DBx3WLGw+M\n"
"DiHXk2L0geSYSNjFz/u9dkgEUPhEGbNZuw2yxhwbNfaiPe2ld5Fir6iUybuj93xf\n"
"WqqNls77V6Qj7mI8pamdGFtQnkP+6l2XTa6JbunCqZo1PURtUXch5db6rMq/6rRZ\n"
"rlJM7NngPI1vv8jF4T3G4mjyT8I4KxQK1s909QIDAQABAoIBAQCAkkI2ONq6Rq+z\n"
"kQxFifAZLELmMGRHRY8SQn/xYg95KjLi+E82loVpguprUgrhabL3B3IzmS8NYa0U\n"
"47/S5COX5evJYMxze5z9CYIhwSUoKJcmXLcmRLyxYJZ3l0jK0Nl6zXfw8M3V0kz8\n"
"G8Lj3lqSL70vg5yxpkg8n8LNRHoleXvz/57HzllIUx2S6Dopc29ALJiR1lVFdPc1\n"
"z5vs6O+2e0TDmPpVTNKQMI8E+02i/W5BfJ21A7VJW0OFx9ozQU43E95VT9U3/pOz\n"
"NLjdIKXmr3Miw7+TWljwF0Ak7SL0AN/nLKHYt6PIIgs9YU1xqP44u/rtqBCeSSVE\n"
"2OBmAUcxAoGBAOo6CfZER7tLayhFNSw1Zt3UBsru+xZnCR1DBuPYn+qMJbbv/LAf\n"
"4zy14vQO9lY2d3k5Vd/zZSpIcXS12adqn7kN2d5PI4XZEVMH3O1aRcGxl1UETiQE\n"
"wiEeB5u4OdjoRxKk59MzMrGLYUaZMuyyhaw6t18ujw7DeS2IRoPgsYjzAoGBALqf\n"
"bnG0yMcwmcmsmsURB5OX9eXmSBld2ypaDUDComxTOKGo0reWwE8/tEm0VcQn2GcX\n"
"Uk5sbjvf3ZgOnDvBuUBr3yfXEW6OOw5mOaJeBJn3mncDcsaV5bujwfG6QS/KA6Ad\n"
"1JzdJDtT1Be+DoeEwInBx6WNMrCH5dXWC7CChwR3AoGAXjPVidxQVT2x7VJYXl1j\n"
"79e0m62eApaSDdjFTqHzPyv6hybiJBvPEr28d5gE7wuc5X5v0VBc4bKdHul8jl7N\n"
"ummdtFFz4gM5eoFxE2z5HTvFt4Wxv77CLPuc574iVeClpRP5wPGYc9uw1eoLlzL9\n"
"nBVJZtic5L0tYWiro6KdBI0CgYBE3zWpLOiz6hG3RcXQWFqNc5VCBNwy0FpjpNwj\n"
"PDEo/QV3U5CARFgwZvgoAy9rtrC8SvULECUWX6WtyiaKPxIY3jZ6w3ohbMgKpls6\n"
"uqvEDoaoyVMASq1/tA2NIgmQk2MHIjsmsM4APw2UvYUrKijMLgF57UP5tg1x/w5N\n"
"U750PQKBgQC9zAxKw4cNqNBCqySmdIFmfhYwpiAqHpUX1XcjjEY9b4Ym9OwQbK+f\n"
"5aGgRkmSW/Fc1ab33Gj2liLXCDN8bziri3KfMW6n9Dxhk8ppue7N5vNpjaoMLU2e\n"
"tT/aucPRjdDp9JPzZQaewIDz7OG8bJtwLfx25FiR2oWDz2kD02joag==\n"
"-----END RSA PRIVATE KEY-----";
#else
"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
"MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIpsU/SSIa4OoCAggA\n"
"MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBDvD4YFDn8hY+f4s88K0duqBIIE\n"
"0E4TFcEYQYD1ltbYf5xHbEA3j0Vjs/5w9YL4K7JqrR9R7HTlxCFavNl/l7Rga3rk\n"
"IiAz5cuSYxusUnIkDlBqcB3XQefKkl1G2E1DtExCdo02eDI4EdJ4N4zDLt5wmnL8\n"
"w10WWMU3ZkRfrD4XPz0cuuBWD5LFI9QKLJ93tUhBQtjtrZSxPG7x2tmD9YotjIiV\n"
"/PQ5Vd6agIoHyfXdRz9CIMZU25iV1tm5s2WN0JiLW3MH4Zw1bpyGDEoN8EwtnQjc\n"
"/GN6Z384o4jr+ut8z356ilSESvr6mcxTcDZoO64xWvbIRjWIyRmtv8tMd1Qtamfo\n"
"6bQCpV3I/dxBfshqPDWk/S1g9NxoPETm/yDz98Jukj8+NoJ2r4w0+y9CWyObBBUX\n"
"cAiwxluYrP7xKRMunC77WxgD2P1N29N+8QK23YcJnUQJ/TcMXSXb/W/3GbnoHhS+\n"
"KyUk05fWpswFXxtglGGjxN5wh7uOXSFY3bq/KbO/riHZ++Fwe9vSAUUaRvZUF948\n"
"alfAMRUBG2r4cIi/kQRdsQQ5icwZwsCTo2W8xvKqw26x145egEx0Jsb27Eoapcvr\n"
"vOutbe4JXMhKhrGwZohDZ4EgcM5ue7zobYwIo8DKnqTbb6UtgaVoYJm1m/YtCavy\n"
"X9xz8eXruwI00BXf+9Aj1Ryn7wn0Pcw/EoNjYAHAQB2J8yvI97FPDtwFeXm+abZg\n"
"sMMoYhQbFRd2G+xPmqltEgMv88C/cYXJGufTvYdBZNmqyZSMVu8YTxpHnM/fOODw\n"
"yB6sx5VriEkMvh5So7X1xH0UXJ1HI8LGzJKEKNPrSQKZW0KofPsCZsAbgkoDZ/HV\n"
"ji6uMHgXYbZRJEhYbTnQNE26elniTMkQXa0tw9atbjsFwk609Nbz63KeQWyvnAC+\n"
"Q3IoXWWt42APNmOBGdg1xRIWolXtmWFMCI58eY9YCJkwUQjWy4vS85waWY2kA8tq\n"
"4W15XEXYwuhWoyOqNubhkEs+PT+CaEh2M9C4exfBAnTy9fYYx2lm1OC8CX+L8OZU\n"
"mhOU7EdRuah5wnTEATUu4i2Zm5+R7oF+12QHk5vaoZAbkl4xChVdD44UneREzDLb\n"
"WV27YlN0RApeFCoYf+BQi8YzBXZahxG4g74Yu7sfjOKJj+VAT3ilLlhKelLBqjlw\n"
"ZUV9F+mLKo91k3omAr+M4mp72DqH8OiWnhvQaBY1QADrez4kA0krfewHcKosKMMK\n"
"EIc9zD0FAsBgFCGgmOxyPD9Xu8tbkD7rxJZsEfHxXj3LgO8AYC2e/743D5WivqWR\n"
"8wNlSn53ED7BuNBTbnaWhfElqqpyPYtUDi3G+R87dv48Yec1xMdUu0aRb65QeerT\n"
"O2TL6F+KOlKWklBSzibCLBNLTBkXsf1aQb1FxQtGJjrTkA0FEqEvGgGtHHfMoRFq\n"
"T1kvzEocWJGQv78eCpREl35vho4Aj+0MgUvGPfBlijoWFYHCm2LRGOLv1yWLRrOS\n"
"LHaxJ2tK/0sXxIoxUQqLcwrobnA4l2drdPB+EeBpYBlYhhsp/F3IRQ3ylOpIPBgd\n"
"AOaroBlSDin5rLfa7T0YvzcAcNvodVjszIGrSeECx1l4VdiL+M73MvvW4GyfIE2S\n"
"P7wyuvA665ZFyqsV1ZerHCKyhX3G0xCj+V6wMjAWyHlh\n"
"-----END ENCRYPTED PRIVATE KEY-----";
#endif

static const char* device_cert =
"-----BEGIN CERTIFICATE-----\n"
"MIIDWjCCAkKgAwIBAgIVANIzUucLFUREa2BiJUXoRv6Z4XaIMA0GCSqGSIb3DQEB\n"
"CwUAME0xSzBJBgNVBAsMQkFtYXpvbiBXZWIgU2VydmljZXMgTz1BbWF6b24uY29t\n"
"IEluYy4gTD1TZWF0dGxlIFNUPVdhc2hpbmd0b24gQz1VUzAeFw0xNjExMzAxODIz\n"
"MzNaFw00OTEyMzEyMzU5NTlaMB4xHDAaBgNVBAMME0FXUyBJb1QgQ2VydGlmaWNh\n"
"dGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCqwApWFt9ARZuULw++\n"
"C5uqklqxWgISxJ+8sXhvkMgCygx6J4/brLpXJ3eeNHK6KBJDqM/6ajcbKpJ94Jup\n"
"8nZ3HcE0gISTs/joG7ft7CgjbilJydP7lFx/D/92HxYcOrR3T3feLi84oQoDp+3n\n"
"UDFjorO82vDGjpuaXRWLYMHHdYsbD4wOIdeTYvSB5JhI2MXP+712SARQ+EQZs1m7\n"
"DbLGHBs19qI97aV3kWKvqJTJu6P3fF9aqo2WzvtXpCPuYjylqZ0YW1CeQ/7qXZdN\n"
"rolu6cKpmjU9RG1RdyHl1vqsyr/qtFmuUkzs2eA8jW+/yMXhPcbiaPJPwjgrFArW\n"
"z3T1AgMBAAGjYDBeMB8GA1UdIwQYMBaAFJZuFLsbLnLXbHrfXutsILjrIB5qMB0G\n"
"A1UdDgQWBBTHoiSGnE/lSskzSaWXWflJWIC/szAMBgNVHRMBAf8EAjAAMA4GA1Ud\n"
"DwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAlchZ7iW3kr6ny20ySEUhc9Dl\n"
"gEcihl6gcY7Oew0xWoUzuXBkSoOVbjPRiy9RbaLA94QgoxtZCpkF0F81Jro878+m\n"
"a5Cx0Ifj66ZAaeR3FSCtjSyLgg12peZux+VXchq3MwNb8iTD1nruIJ8kLPM+7fQy\n"
"nbGM69r7lUZ1539t9O44OB0aIRDRC+ZpYINnWjiuO7hK27oZs3HCk484C+OjRusJ\n"
"jKrLFSjEdbaUj3ukMv0sGO693Z5DqTL2t9ylM2LuE9iyiWF7DBHhuDLHsZfirjk3\n"
"7/MBDwfbv7td8GOy6C2BennS5tWOL06+8lYErP4ECEQqW6izI2Cup+O01rrjkQ==\n"
"-----END CERTIFICATE-----";



#endif /* WOLFMQTT_AWS_SETTINGS_H */