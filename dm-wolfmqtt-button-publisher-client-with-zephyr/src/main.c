/* main.c
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

/* User Settings file */
#include "wolfmqtt_usersettings.h"  /* For wolfssl/mqtt zephyr configuration */

/* wolfSSL Includes Start */
#include <wolfssl/ssl.h>            /* Basic functionality for TLS */
#include <wolfssl/certs_test.h>     /* Needed for Cert Buffers */
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/hmac.h>
/* wolfSSL Includes End */

/* wolfMQTT Include Start */
#include <wolfmqtt/mqtt_client.h>
#include <wolfmqtt/version.h>
#include "examples/mqttclient/mqttclient.h"
#include "aws_settings.h"
/* wolfMQTT Include End */

/* Standard Packages Start */
#include <stdio.h>
#include <time.h>
/* Standard Packages End */

/* Zephyr Includes Start */
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/dhcpv4.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_config.h>
#include <zephyr/net/net_ip.h>
/* Zephyr Includes End */

/* Other */
/* Other end */

/* Program Defines Start */
#define DEFAULT_PORT 11111  /* Define the port we want to use for the network */
#define LOCAL_DEBUG 0       /* Use for wolfSSL's internal Debugging */

/* Use DHCP auto IP assignment or static assignment */
#undef DHCP_ON
#define DHCP_ON 1  /* Set to true (1) if you want auto assignment IP, */ 
                   /* set false (0) for statically define. */
                   /* Make sure to avoid IP conflicts on the network you */
                   /* assign this to, check the defaults before using. */
                   /* If unsure leave DHCP_ON set to 1 */
 
#if DHCP_ON == 0
/* Define Static IP, Gateway, and Netmask */
    #define STATIC_IPV4_ADDR  "192.168.1.70"
    #define STATIC_IPV4_GATEWAY "192.168.1.1"
    #define STATIC_IPV4_NETMASK "255.255.255.0"
#endif

/* Set the TLS Version Currently only 2 or 3 is available for this */
/* application, defaults to TLSv3 */
#undef TLS_VERSION
#define TLS_VERSION 3

/* This just sets up the correct function for the application via macros */
#undef TLS_METHOD
#if TLS_VERSION == 3
    #define TLS_METHOD wolfTLSv1_3_server_method()
#elif TLS_VERSION == 2
    #define TLS_METHOD wolfTLSv1_2_server_method()
#else 
    #define TLS_METHOD wolfTLSv1_3_server_method()
#endif

#define NET_IPV4_ADDR_LEN 16
/* wolfMQTT Defines Start */

/* wolfMQTT Defines End */

/* Datatype Start */

/* Datatype End */

/* Set up the network using the zephyr network stack */
int startNetwork() {
    struct net_if *iface = net_if_get_default();
    char buf[NET_IPV4_ADDR_LEN];
    #if DHCP_ON == 0
        struct in_addr addr, netmask, gw;
    #endif
    if (!(iface)) { // See if a network interface (ethernet) is available
        printf("No network interface determined\n");
        return 1;
    }
    if (net_if_flag_is_set(iface, NET_IF_DORMANT)) {
        printf("Waiting on network interface to be available\n");
        while(!net_if_is_up(iface)) {
            k_sleep(K_MSEC(100));
        }
    }
    #if DHCP_ON == 1
        printf("\nStarting DHCP to obtain IP address\n");
        net_dhcpv4_start(iface);
        (void)net_mgmt_event_wait_on_iface(iface, NET_EVENT_IPV4_DHCP_BOUND, \
                                            NULL, NULL, NULL, K_FOREVER);
    #elif DHCP_ON == 0
        /* Static IP Configuration */
        if (net_addr_pton(AF_INET, STATIC_IPV4_ADDR, &addr) < 0 ||
            net_addr_pton(AF_INET, STATIC_IPV4_NETMASK, &netmask) < 0 ||
            net_addr_pton(AF_INET, STATIC_IPV4_GATEWAY, &gw) < 0) {
            printf("Invalid IP address settings.\n");
            return -1;
        }
        net_if_ipv4_set_netmask_by_addr(iface, &addr, &netmask);
        net_if_ipv4_set_gw(iface, &gw);
        net_if_ipv4_addr_add(iface, &addr, NET_ADDR_MANUAL, 0);
    #else
        #error "Please set DHCP_ON to true (1) or false (0), if unsure set to true (1)"
    #endif
    /* Display IP address that was assigned when done */
    printf("IP Address is: %s\n", net_addr_ntop(AF_INET, \
                    &iface->config.ip.ipv4->unicast[0].ipv4.address.in_addr, \
                    buf, sizeof(buf)));
    return 0;
}

/* Function to load certificates into the wolfSSL context */
void setup_ctx(MQTTCtx* mqttCtx) {
    char pubMsg[MQTT_PUBLISH_MSG_SZ] = {0};
    XMEMSET(mqttCtx, 0, sizeof(MQTTCtx));
    mqttCtx->app_name = APP_NAME;
    mqttCtx->host = MQTT_BROKER_HOST;
    mqttCtx->qos = MQTT_QOS;
    mqttCtx->clean_session = 1;
    mqttCtx->keep_alive_sec = MQTT_KEEP_ALIVE_SEC;
    mqttCtx->client_id = MQTT_DEVICE_ID;
    mqttCtx->topic_name = MQTT_SUBSCRIBE_TOPIC;
    mqttCtx->cmd_timeout_ms = MQTT_CMD_TIMEOUT_SEC;
    mqttCtx->debug_on = 1;
    mqttCtx->app_ctx = pubMsg;
    /* Need MQTT v5 for these*/
    #ifdef WOLFMQTT_V5
        mqttCtx->max_packet_size = MAX_BUFFER_SIZE;
        mqttCtx->topic_alias = 1;
        mqttCtx->topic_alias_max = 1;
    #endif
    /* Set the default TLS version */
    #ifdef WOLFMQTT_DEFAULT_TLS
        mqttCtx->use_tls = WOLFMQTT_DEFAULT_TLS;
    #endif
    #ifdef ENABLE_MQTT_TLS
        mqttCtx->ca_file = root_ca;
        mqttCtx->mtls_keyfile = device_cert;
        mqttCtx->mtls_certfile = device_cert;
    #endif
    mqttCtx->app_name = APP_HARDWARE;
    mqttCtx->message = DEFAULT_MESSAGE;
    return;
}

/* Function to publish a message */
int mqtt_publish(MQTTCtx *mqttCtx, const char *topic, const char *message) {
    MqttPublish publish;
    XMEMSET(&publish, 0, sizeof(MqttPublish));
    publish.retain = 0;
    publish.qos = mqttCtx->qos;
    publish.topic_name = topic;
    publish.buffer = (byte*)message;
    publish.total_len = XSTRLEN(message);

    int rc = MqttClient_Publish(&mqttCtx->client, &publish);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("MqttClient_Publish failed with return code: %d\n", rc);
        return rc;
    }
    printf("Published: %s to topic: %s\n", message, topic);
    return MQTT_CODE_SUCCESS;
}

int mqtt_example(MQTTCtx *mqttCtx) {
    MqttConnect connect;
    XMEMSET(&connect, 0, sizeof(MqttConnect));
    connect.client_id = mqttCtx->client_id;
    connect.keep_alive_sec = mqttCtx->keep_alive_sec;
    connect.clean_session = mqttCtx->clean_session;

    /* Connect to the broker */
    int rc = MqttClient_Connect(&mqttCtx->client, &connect);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("MqttClient_Connect failed with return code: %d\n", rc);
        return rc;
    }
    printf("Connected to broker\n");

    /* Publish a message */
    rc = mqtt_publish(mqttCtx, mqttCtx->topic_name, mqttCtx->app_ctx);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("mqtt_publish failed with return code: %d\n", rc);
        return rc;
    }

    /* Disconnect from the broker */
    rc = MqttClient_Disconnect(&mqttCtx->client);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("MqttClient_Disconnect failed with return code: %d\n", rc);
        return rc;
    }
    printf("Disconnected from broker\n");

    return MQTT_CODE_SUCCESS;
}

/* Initialize Server for a client connection */
int startClient(void) {
    int rc;
    MQTTCtx mqttCtx;

    /* Init a default structure */
    setup_ctx(&mqttCtx);
    rc = mqtt_example(&mqttCtx);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("MQTT example failed\n");
        return rc;
    }

    return 0;
}

int main(void) {
    printf("\nRunning wolfSSL example from the %s!\n", CONFIG_BOARD);
    
    /* Start up the network */
    if (startNetwork() != 0) {
        printf("Network Initialization via DHCP Failed\n");
        return 1;
    }

    if (startClient() != 0) {
        printf("Client has Failed!\n");
        return 1;
    }

    return 0;
}
