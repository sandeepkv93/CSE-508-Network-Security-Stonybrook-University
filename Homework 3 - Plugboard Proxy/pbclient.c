#include "pbclient.h"
#include "crypto.h"
#include "pbproxy.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <getopt.h>
#include <netinet/tcp.h>
#include <openssl/aes.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MESSAGE_LENGTH 4096

int create_client_connection(char *destination_address, int destination_port,
                             int *returned_fd) {
    int status;
    int flag = 1;
    int socket_fd = create_socket_for_proxy();
    struct sockaddr_in client =
        create_sockaddr_structure(destination_address, destination_port);

    /* There is no need to bind because it is client connection
        Reference:
       https://stackoverflow.com/questions/7483510/in-which-cases-is-calling-bind-necessarys
    */
    status = connect_to_socket(socket_fd, &client);
    if (status != 0) {
        fprintf(stdout, "\nNot able to connect the client to the server\n");
        fflush(stdout);
        return -1;
    }

    status = set_socket_options(socket_fd, &flag);
    *returned_fd = socket_fd;
    return 0;
}

int client_launch(int soc_fd, char *key) {
    int status = -1;
    int send_bytes, recieved_bytes;
    char plain[MESSAGE_LENGTH], cipher[MESSAGE_LENGTH];
    struct ctr_state client_state;
    AES_KEY session_key;
    struct timespec time;

    status = AES_set_encrypt_key(key, 128, &session_key);
    if (status != 0) {
        fprintf(stdout, "\nNot able to set the key\n");
        fflush(stdout);
        return -1;
    }

    while (1) {
        fd_set mon_fd;

        FD_ZERO(&mon_fd);
        FD_SET(soc_fd, &mon_fd);
        FD_SET(0, &mon_fd);
        status = monitor_and_wait_until_ready(soc_fd, &mon_fd);
        if (status < 0) {
            fprintf(stdout, "\nSocket Monitoring Failed\n");
            fflush(stdout);
            return 0;
        }

        if (FD_ISSET(0, &mon_fd)) {
            recieved_bytes = read(0, plain, sizeof(plain));

            status = encrypt_text(plain, cipher, recieved_bytes, &session_key,
                                  &client_state);
            if (status != 0) {
                fprintf(stdout,
                        "\nNot able to encrypt the data in the client side\n");
                fflush(stdout);
                break;
            }

            send_bytes = write(soc_fd, cipher, recieved_bytes + 8);
            if (send_bytes <= 0) {
                fprintf(stdout, "\nNot able to send data on client socket");
                fflush(stdout);
            } else if (send_bytes < (recieved_bytes + 8)) {
                fprintf(
                    stdout,
                    "\nNot able to send the complete data on client socket");
                fflush(stdout);
            }
            time.tv_sec = 0;
            time.tv_nsec = 10 * 1000;
            nanosleep(&time, NULL);
        }
        if (FD_ISSET(soc_fd, &mon_fd)) {
            recieved_bytes = read(soc_fd, cipher, sizeof(cipher));
            if (recieved_bytes == 0) {
                fprintf(stdout, "\nRemote Server terminated the connection\n");
                fflush(stdout);
                break;
            } else if (recieved_bytes < 0) {
                fprintf(stdout, "\nFailed to recieve data in client socket\n");
                fflush(stdout);
                break;
            }

            status = decrypt_text(cipher, plain, recieved_bytes, &session_key,
                                  &client_state);
            if (status != 0) {
                fprintf(stdout,
                        "\nFailed to decrypt the data in the client side\n");
                fflush(stdout);
                return -1;
            }
            send_bytes = write(1, plain, recieved_bytes - 8);
        }
    }
    close(soc_fd);
    return 0;
}

void handle_client_mode(char *destination_address, int destination_port,
                        char *key) {
    int proxy_socket_file_descriptor = -1;
    int status = create_client_connection(destination_address, destination_port,
                                          &proxy_socket_file_descriptor);
    if (status != 0) {
        fprintf(stdout, "\nFailed to establish the client connection\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    status = client_launch(proxy_socket_file_descriptor, key);
    if (status != 0) {
        fprintf(stdout, "\nCommunication failed between server and client\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }
}