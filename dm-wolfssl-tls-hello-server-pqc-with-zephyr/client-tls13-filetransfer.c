/* client-tls13-filetransfer.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/stat.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define DEFAULT_PORT 11111
#define CA_FILE   "mldsa44_root_cert.pem"
#define BUFFER_SIZE 256

static int send_file(WOLFSSL* ssl, const char* filename)
{
    FILE* file = NULL;
    struct stat file_stat;
    uint32_t file_size;
    uint32_t file_size_network;
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    int ret = 0;
    uint32_t total_sent = 0;
    char ack[4];

    if (stat(filename, &file_stat) != 0) {
        fprintf(stderr, "ERROR: Cannot stat file %s\n", filename);
        return -1;
    }

    file_size = (uint32_t)file_stat.st_size;
    file_size_network = htonl(file_size);

    printf("Sending file %s (size: %u bytes)\n", filename, file_size);

    if ((ret = wolfSSL_write(ssl, &file_size_network, sizeof(file_size_network))) != sizeof(file_size_network)) {
        fprintf(stderr, "ERROR: Failed to send file size for %s\n", filename);
        return -1;
    }

    file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "ERROR: Cannot open file %s\n", filename);
        return -1;
    }

    while (total_sent < file_size) {
        bytes_read = fread(buffer, 1, BUFFER_SIZE, file);
        if (bytes_read == 0) {
            if (feof(file)) {
                break;
            } else {
                fprintf(stderr, "ERROR: Failed to read from file %s\n", filename);
                ret = -1;
                goto cleanup;
            }
        }

        if ((ret = wolfSSL_write(ssl, buffer, bytes_read)) != (int)bytes_read) {
            fprintf(stderr, "ERROR: Failed to send file data for %s\n", filename);
            ret = -1;
            goto cleanup;
        }

        if ((ret = wolfSSL_read(ssl, ack, sizeof(ack))) != sizeof(ack)) {
            fprintf(stderr, "ERROR: Failed to receive ack for file %s\n", filename);
            return -1;
        }

        total_sent += bytes_read;
        printf("Successfully sent %u bytes for file %s\n", total_sent, filename);
    }

    ret = 0;

cleanup:
    if (file) {
        fclose(file);
    }
    return ret;
}

int main(int argc, char** argv)
{
    int ret = 0;
    int sockfd = SOCKET_INVALID;
    struct sockaddr_in servAddr;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    if (argc != 4) {
        printf("usage: %s <IPv4 address> <certificate.pem> <key.pem>\n", argv[0]);
        return 0;
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        ret = -1; 
        goto exit;
    }

    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(DEFAULT_PORT);

    if (inet_pton(AF_INET, argv[1], &servAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid address\n");
        ret = -1; 
        goto exit;
    }

    if ((ret = connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr))) == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        goto exit;
    }

    if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto exit;
    }

    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1; 
        goto exit;
    }

    if ((ret = wolfSSL_CTX_load_verify_locations(ctx, CA_FILE, NULL)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n", CA_FILE);
        goto exit;
    }

    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        ret = -1; 
        goto exit;
    }

    ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_P256_ML_KEM_512);
    if (ret != WOLFSSL_SUCCESS) {
        printf("\nERROR: wolfSSL_UseKeyShare error = %d\n", ret);
        return 1;
    }

    if ((ret = wolfSSL_set_fd(ssl, sockfd)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        goto exit;
    }

    if ((ret = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
        goto exit;
    }

    printf("TLS 1.3 connection established successfully\n");

    if (send_file(ssl, argv[2]) != 0) {
        fprintf(stderr, "ERROR: Failed to send certificate\n");
        ret = -1;
        goto exit;
    }

    if (send_file(ssl, argv[3]) != 0) {
        fprintf(stderr, "ERROR: Failed to send key\n");
        ret = -1;
        goto exit;
    }

    printf("Both files sent successfully\n");
    ret = 0;

exit:
    if (sockfd != SOCKET_INVALID)
        close(sockfd);
    if (ssl)
        wolfSSL_free(ssl);
    if (ctx)
        wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return ret;
}
