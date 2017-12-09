#include "pbserver.h"
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

void handle_server_mode(char *destination_address, int destination_port,
                        int proxy_port, char *key) {
    int proxy_socket_file_descriptor = -1;
    fprintf(stdout, "\npbproxy setup\n");
    fflush(stdout);
    fprintf(stdout, "Proxy Listening Port: %d\n", proxy_port);
    fflush(stdout);
    fprintf(stdout, "Destination IP: %s\n", destination_address);
    fflush(stdout);
    fprintf(stdout, "Destination Port: %d\n", destination_port);
    fflush(stdout);
    fprintf(stdout, "\n*************************************************\n");
    fflush(stdout);
    int status = create_server_connection(destination_address, proxy_port,
                                          &proxy_socket_file_descriptor);
    if (status != 0) {
        fprintf(stdout, "\nNot able to establish connection with clients\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    status = server_launch(proxy_socket_file_descriptor, destination_port,
                           destination_address, key);
    if (status != 0) {
        fprintf(stdout, "\nCommunication failed\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }
}

int create_server_connection(char *destination_address, int proxy_port,
                             int *proxy_soc_fd) {
    int server_status;
    int proxy_socket_file_descriptor = create_socket_for_proxy();
    struct sockaddr_in server =
        create_sockaddr_structure(destination_address, proxy_port);
    server_status = bind(proxy_socket_file_descriptor,
                         (struct sockaddr *)&server, sizeof(server));
    if (server_status != 0) {
        fprintf(stdout, "\nNot able to bind the socket\n");
        fflush(stdout);
        return -1;
    }

    server_status = listen(proxy_socket_file_descriptor, 10);
    if (server_status != 0) {
        fprintf(stdout, "\nNot able to Listen on socket\n");
        fflush(stdout);
        return -1;
    }
    *proxy_soc_fd = proxy_socket_file_descriptor;

    return 0;
}

int server_launch(int proxy_socket_file_descriptor, int destination_port,
                  char *destination_address, char *key) {
    int status = -1, new_fd;
    struct sockaddr_storage in_data;
    socklen_t in_len;
    struct sockaddr_in *t = NULL;
    char ip_address[129];

    while (1) {
        fd_set mon_fd;

        FD_ZERO(&mon_fd);
        FD_SET(proxy_socket_file_descriptor, &mon_fd);

        status =
            monitor_and_wait_until_ready(proxy_socket_file_descriptor, &mon_fd);
        if (status < 0) {
            fprintf(stdout, "\nNot able to monitor the sockets\n");
            fflush(stdout);
            return -1;
        }

        if (FD_ISSET(proxy_socket_file_descriptor, &mon_fd)) {
            in_len = sizeof(in_data);
            new_fd = accept(proxy_socket_file_descriptor,
                            (struct sockaddr *)&in_data, &in_len);
            if (new_fd < 0) {
                fprintf(stdout, "\nNot able to accept the connections\n");
                fflush(stdout);
                return -1;
            }

            t = (struct sockaddr_in *)&in_data;
            inet_ntop(AF_INET, &(t->sin_addr), ip_address, INET_ADDRSTRLEN);
            fprintf(stdout, "\nSSH Incoming Request Recieved from %s",
                    ip_address);
            fflush(stdout);
            status = proxy_server_handler(new_fd, destination_port,
                                          destination_address, key);
            if (status != 0) {
                fprintf(stdout, "\nNot able to serve. Quitting\n");
                return -1;
            }
            fprintf(stdout, "\nSSH Request Completed for %s\n", ip_address);
            fprintf(stdout,
                    "\n*************************************************\n");
            fflush(stdout);
        }
    }
    return 0;
}