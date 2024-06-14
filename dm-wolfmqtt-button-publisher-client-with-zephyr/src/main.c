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
#include "wolfssl_usersettings.h"
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
#include "aws_settings.h"
#include "examples/mqttclient/mqttclient.h"
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
#define TLS_VERSION 2

/* This just sets up the correct function for the application via macros */
#undef TLS_METHOD
#if TLS_VERSION == 3
    #define TLS_METHOD wolfTLSv1_3_server_method()
#elif TLS_VERSION == 2
    #define TLS_METHOD wolfTLSv1_2_server_method()
#else 
    #define TLS_METHOD wolfTLSv1_3_server_method()
#endif

/* wolfMQTT Defines Start */

/* wolfMQTT Defines End */

/* Datatype Start */

/* Datatype End */











/* Define a macro for logging */
#define LOG_INFO(fmt, ...) printf("INFO: " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("ERROR: " fmt "\n", ##__VA_ARGS__)

static MqttNet net_ctx;
static MqttClient mqtt_client;
static MqttConnect mqtt_connect;
static MqttSubscribe mqtt_subscribe;
static MqttMessage mqtt_message;
static WOLFSSL_CTX *ssl_ctx;
static WOLFSSL *ssl;

/* Callback function declarations */
static int mqtt_msg_callback(MqttClient *client, MqttMessage *msg, unsigned char msg_new, unsigned char msg_done);
int mqtt_tls_cb(MqttClient *client); // Ensure this matches the declaration in the header file

static int mqtt_net_connect(void *context, const char* host, word16 port, int timeout_ms);
static int mqtt_net_read(void *context, byte* buf, int buf_len, int timeout_ms);
static int mqtt_net_write(void *context, const byte* buf, int buf_len, int timeout_ms);
static int mqtt_net_disconnect(void *context);

static void broker_init(void);
static void mqtt_client_init_custom(void);
static void set_mqtt_connection_params(void);
static int tls_setup(void);
static int mqtt_client_connect(void);
static void send_mqtt_connect_packet(void);
static bool is_connection_successful(int rc);
static void subscribe_to_topics(void);
static void publish_to_topics(void);
static void wait_for_messages(void);
static bool check_for_commands(void);
static bool disconnect_needed(void);
static void mqtt_disconnect(void);
static void cleanup_resources(void);
char* resolve_hostname(const char *hostname);
static int mqtt_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store);





/* Step 0: Zephyr Network Stack Setup */
/* Set up the network using the zephyr network stack */
int startNetwork() {
    struct net_if *iface = net_if_get_default();
    char buf[NET_IPV4_ADDR_LEN];

    #if DHCP_ON == 0
        struct in_addr addr, netmask, gw;
    #endif

    if (!iface) { // Check if a network interface (ethernet) is available
        printf("No network interface determined\n");
        return 1;
    }

    if (net_if_flag_is_set(iface, NET_IF_DORMANT)) {
        printf("Waiting on network interface to be available\n");
        while (!net_if_is_up(iface)) {
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













/* Step A: Initialize Network */
static void broker_init(void) {
    // Set up network callbacks
    LOG_INFO("Initializing network context...");
    XMEMSET(&net_ctx, 0, sizeof(MqttNet));
    net_ctx.context = NULL;
    net_ctx.connect = mqtt_net_connect;
    net_ctx.read = mqtt_net_read;
    net_ctx.write = mqtt_net_write;
    net_ctx.disconnect = mqtt_net_disconnect;
    LOG_INFO("Network context initialized successfully");
}

static int mqtt_net_connect(void *context, const char* host, word16 port, int timeout_ms) {
    LOG_INFO("Connecting to broker at %s:%d", host, port);

    struct sockaddr_in broker;
    broker.sin_family = AF_INET;
    broker.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &broker.sin_addr) <= 0) {
        LOG_ERROR("Invalid address or address not supported");
        return MQTT_CODE_ERROR_NETWORK;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG_ERROR("Failed to create socket");
        return MQTT_CODE_ERROR_NETWORK;
    }

    if (connect(sock, (struct sockaddr *)&broker, sizeof(broker)) < 0) {
        LOG_ERROR("Failed to connect to broker");
        close(sock);
        return MQTT_CODE_ERROR_NETWORK;
    }

    LOG_INFO("Connected to broker successfully, socket: %d", sock);
    net_ctx.context = (void *)(intptr_t)sock; // Ensure correct casting of the socket context
    return MQTT_CODE_SUCCESS;
}

static int mqtt_net_read(void *context, byte* buf, int buf_len, int timeout_ms) {
    int sock = (int)(intptr_t)context; // Ensure correct casting of the socket context
    LOG_INFO("Reading from socket %d", sock);

    int bytes_read = recv(sock, buf, buf_len, 0);
    if (bytes_read < 0) {
        LOG_ERROR("Failed to read from socket");
        return MQTT_CODE_ERROR_NETWORK;
    }

    LOG_INFO("Read %d bytes from socket", bytes_read);
    return bytes_read;
}

static int mqtt_net_write(void *context, const byte* buf, int buf_len, int timeout_ms) {
    int sock = (int)(intptr_t)context; // Ensure correct casting of the socket context
    LOG_INFO("Writing to socket %d", sock);

    int bytes_sent = send(sock, buf, buf_len, 0);
    if (bytes_sent < 0) {
        LOG_ERROR("Failed to write to socket");
        return MQTT_CODE_ERROR_NETWORK;
    }

    LOG_INFO("Sent %d bytes to socket", bytes_sent);
    return bytes_sent;
}

static int mqtt_net_disconnect(void *context) {
    int sock = (int)(intptr_t)context; // Ensure correct casting of the socket context
    LOG_INFO("Disconnecting socket %d", sock);

    if (close(sock) < 0) {
        LOG_ERROR("Failed to close socket");
        return MQTT_CODE_ERROR_NETWORK;
    }

    LOG_INFO("Socket %d disconnected successfully", sock);
    return MQTT_CODE_SUCCESS;
}








/* Step B: Initialize MQTT Client */
static void mqtt_client_init_custom(void) {
    LOG_INFO("Initializing MQTT client...");

    uint8_t tx_buf[1024];
    uint8_t rx_buf[1024];

    int rc = MqttClient_Init(&mqtt_client, &net_ctx, mqtt_msg_callback, tx_buf, sizeof(tx_buf), rx_buf, sizeof(rx_buf), MQTT_CMD_TIMEOUT_SEC);
    if (rc != MQTT_CODE_SUCCESS) {
        LOG_ERROR("Failed to initialize MQTT client, return code: %d", rc);
        return;
    }

    LOG_INFO("MQTT client initialized successfully");
}

/* MQTT Message Callback */
static int mqtt_msg_callback(MqttClient *client, MqttMessage *msg, unsigned char msg_new, unsigned char msg_done) {
    if (msg_new) {
        LOG_INFO("Received a message: %.*s", msg->topic_name_len, msg->topic_name);
    }
    if (msg_done) {
        LOG_INFO("Message done.");
    }
    return MQTT_CODE_SUCCESS;
}






/* Step C: Set MQTT Connection Parameters */
static void set_mqtt_connection_params(void) {
    LOG_INFO("Setting MQTT connection parameters...");

    XMEMSET(&mqtt_connect, 0, sizeof(MqttConnect));
    mqtt_connect.keep_alive_sec = MQTT_KEEP_ALIVE_SEC;
    mqtt_connect.clean_session = 1;
    mqtt_connect.client_id = (byte*)MQTT_DEVICE_ID;
    mqtt_connect.enable_lwt = 0;

    LOG_INFO("MQTT connection parameters set successfully");
}






/* Step D: Setup TLS for AWS IoT */
static int tls_setup(void) {
    LOG_INFO("Setting up TLS for AWS IoT...");

    wolfSSL_Init();
   	wolfSSL_Debugging_ON(); 
	ssl_ctx = wolfSSL_CTX_new(TLS_METHOD);
    if (!ssl_ctx) {
        LOG_ERROR("Failed to create WOLFSSL_CTX");
        return -1;
    }
    //wolfSSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, 0); // TODO: Fix this
	wolfSSL_CTX_set_verify(ssl_ctx, WOLFSSL_VERIFY_PEER, mqtt_tls_verify_cb);
    if (wolfSSL_CTX_load_verify_buffer(ssl_ctx, (const byte*)root_ca, (long)XSTRLEN(root_ca), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS){
        LOG_ERROR("Failed to load CA certificate");
        return -1;
    }

    if (wolfSSL_CTX_use_certificate_buffer(ssl_ctx, (const unsigned char*)device_cert, XSTRLEN(device_cert), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        LOG_ERROR("Failed to load device certificate");
        return -1;
    }

    if (wolfSSL_CTX_use_PrivateKey_buffer(ssl_ctx, (const unsigned char*)device_priv_key, XSTRLEN(device_priv_key), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        LOG_ERROR("Failed to load device private key");
        return -1;
    }

    ssl = wolfSSL_new(ssl_ctx);
    if (!ssl) {
        LOG_ERROR("Failed to create WOLFSSL object");
        return -1;
    }
    LOG_INFO("TLS setup successful");
    return 0;
}








/* Step E: Connect via MqttClient_NetConnect */
static int mqtt_client_connect(void) {
    LOG_INFO("Connecting to MQTT broker...");
	
    int rc = MqttClient_NetConnect(&mqtt_client, resolve_hostname(MQTT_BROKER_HOST), MQTT_PORT, 2000, MQTT_USE_TLS, mqtt_tls_cb);
    if (rc != MQTT_CODE_SUCCESS) {
        LOG_ERROR("Failed to connect to broker, return code: %d", rc);
        return rc;
    }

    LOG_INFO("Connected to MQTT broker successfully");
    return MQTT_CODE_SUCCESS;
}


char* resolve_hostname(const char *hostname) {
    static char ip_str[NET_IPV4_ADDR_LEN];
    struct addrinfo hints, *res;
    struct sockaddr_in *addr;
    int err;

    // Initialize hints
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // Specify IPv4 address

    // Resolve hostname to IP address
    err = getaddrinfo(hostname, NULL, &hints, &res);
    if (err != 0) {
        printf("getaddrinfo() failed: %d\n", err);
        return NULL;
    }

    // Convert the IP address to a human-readable form
    addr = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));

    // Free the address info
    freeaddrinfo(res);

    return ip_str;
}


/* TLS Callback Function */
int mqtt_tls_cb(MqttClient *client) {



    LOG_INFO("********* Entered the callback for TLS");
    int fd = (int)(intptr_t)client->net->context; // Correctly cast the context to an integer file descriptor
    wolfSSL_set_fd(ssl, fd);
    return WOLFSSL_SUCCESS;
}

static int mqtt_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ];

    PRINTF("MQTT TLS Verify Callback: PreVerify %d, Error %d (%s)", preverify,
        store->error, store->error != 0 ?
            wolfSSL_ERR_error_string(store->error, buffer) : "none");
    PRINTF("  Subject's domain name is %s", store->domain);

    if (store->error != 0) {
        /* Allowing to continue */
        /* Should check certificate and return 0 if not okay */
        PRINTF("  Allowing cert anyways");
    }

    return 1;
}





/* Step F: Send MQTT Connect Packet */
/*
static int send_mqtt_connect_packet(void) {
    return MqttClient_Connect(&client, &connect);
}
*/










/* Step G: Check Connection Successful */
/*
static bool is_connection_successful(int rc) {
    return rc == MQTT_CODE_SUCCESS;
}
*/










/* Step H: Subscribe to Topics */
/*
static void subscribe_to_topics(void) {
    XMEMSET(&subscribe, 0, sizeof(MqttSubscribe));
    subscribe.packet_id = mqtt_get_packetid();
    subscribe.topic_count = 1;
    subscribe.topics[0].topic_filter = (const uint8_t*)MQTT_SUBSCRIBE_TOPIC;
    subscribe.topics[0].qos = MQTT_QOS;
    MqttClient_Subscribe(&client, &subscribe);
}
*/









/* Step I: Publish to Topics */
/*
static void publish_to_topics(void) {
    MqttPublish publish;
    XMEMSET(&publish, 0, sizeof(MqttPublish));
    publish.retain = 0;
    publish.qos = MQTT_QOS;
    publish.duplicate = 0;
    publish.packet_id = mqtt_get_packetid();
    publish.topic_name = (const uint8_t*)MQTT_PUBLISH_TOPIC;
    publish.topic_name_len = (uint16_t)XSTRLEN(MQTT_PUBLISH_TOPIC);
    publish.buffer = (uint8_t*)"Hello from Zephyr";
    publish.total_len = (uint16_t)XSTRLEN("Hello from Zephyr");
    MqttClient_Publish(&client, &publish);
}
*/













/* Step J: Wait for Messages */
/*
static void wait_for_messages(void) {
    while (1) {
        MqttClient_WaitMessage(&client, &message, MQTT_CMD_TIMEOUT_SEC);
        k_sleep(K_MSEC(1000));
    }
}
*/













/* Step K: Handle Messages */
/*
static void handle_messages(void) {
    // This is done in the mqtt_msg_callback function
}
*/














/* Step L: Check for Commands */
/*
static bool check_for_commands(void) {
    // Implement command checking logic if needed
    return false;
}
*/














/* Step M: Disconnect if needed */
/*
static bool disconnect_needed(void) {
    // Implement logic to decide if disconnection is needed
    return false;
}
*/















/* Step N: Disconnect */
/*
static void mqtt_disconnect(void) {
    MqttClient_Disconnect(&client);
}
*/


















/* Step O: Cleanup Resources */
/*
static void cleanup_resources(void) {
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
}
*/











/* MQTT Message Callback */
/*
static void mqtt_msg_callback(MqttClient *client, MqttMessage *msg, byte msg_new, byte msg_done) {
    if (msg_new) {
        printf("Received a message: %.*s\n", msg->topic_name_len, msg->topic_name);
    }
    if (msg_done) {
        printf("Message done.\n");
    }
}
*/



/* Cleanup resources */
static void cleanup_resources(void) {
    if (ssl) {
        wolfSSL_free(ssl);
        ssl = NULL;
    }
    if (ssl_ctx) {
        wolfSSL_CTX_free(ssl_ctx);
        ssl_ctx = NULL;
    }
    wolfSSL_Cleanup();
}









int main(void) {
    printf("\nRunning wolfSSL example from the %s!\n", CONFIG_BOARD);
    
    /* Start up the network */
    if (startNetwork() != 0) {
        printf("Network Initialization via DHCP Failed\n");
        return 1;
    }


   LOG_INFO("Running wolfSSL example from the %s!", CONFIG_BOARD);

    // Step A: Initialize Network
    LOG_INFO("Step A: Initializing network context");
    broker_init();

    // Step B: Initialize MQTT Client
    LOG_INFO("Step B: Initializing MQTT client");
    mqtt_client_init_custom();

    // Step C: Set MQTT Connection Parameters
    LOG_INFO("Step C: Setting MQTT connection parameters");
    set_mqtt_connection_params();

    // Step D: Setup TLS for AWS IoT
    LOG_INFO("Step D: Setting up TLS for AWS IoT");
    if (tls_setup() != 0) {
        LOG_ERROR("TLS setup failed");
        return 1;
    }

    // Step E: Connect via MqttClient_NetConnect
    LOG_INFO("Step E: Connecting to MQTT broker");
    if (mqtt_client_connect() != MQTT_CODE_SUCCESS) {
        LOG_ERROR("Failed to connect to broker");
        cleanup_resources();
        return 1;
    }
/*
    // Step F: Send MQTT Connect Packet
    LOG_INFO("Step F: Sending MQTT connect packet");
    rc = send_mqtt_connect_packet();
    if (!is_connection_successful(rc)) {
        LOG_ERROR("Failed to send connect packet, rc: %d", rc);
        cleanup_resources();
        return 1;
    }

    // Step G: Check Connection Successful
    LOG_INFO("Step G: Checking if connection is successful");
    if (!is_connection_successful(rc)) {
        LOG_ERROR("MQTT connection failed, rc: %d", rc);
        cleanup_resources();
        return 1;
    }

    // Step H: Subscribe to Topics
    LOG_INFO("Step H: Subscribing to topics");
    subscribe_to_topics();

    // Step I: Publish to Topics
    LOG_INFO("Step I: Publishing to topics");
    publish_to_topics();

    // Step J: Wait for Messages
    LOG_INFO("Step J: Waiting for messages");
    wait_for_messages();

    // Step L: Check for Commands
    LOG_INFO("Step L: Checking for commands");
    if (check_for_commands()) {
        LOG_INFO("Command received, handling...");
        // Implement command handling logic here if needed
    }

    // Step M: Disconnect if needed
    LOG_INFO("Step M: Checking if disconnection is needed");
    if (disconnect_needed()) {
        LOG_INFO("Disconnecting from MQTT broker");
        mqtt_disconnect();
    }

    // Step O: Cleanup Resources
    LOG_INFO("Step O: Cleaning up resources");
    cleanup_resources();
*/
    return 0;
}
