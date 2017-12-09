#include "pbproxy.h"
#include "crypto.h"
#include "pbclient.h"
#include "pbserver.h"
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

#define IDEAL_CRYPTO_KEY_LENGTH 16
#define MESSAGE_LENGTH 4096

int monitor_and_wait_until_ready(int nfd, fd_set *read_fds) {
    return select(nfd + 1, read_fds, NULL, NULL, NULL);
}

int create_socket_for_proxy() {
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        fprintf(stdout, "\nNot able to create the socket for proxy.\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }
    return socket_fd;
}

int set_socket_options(int socket_file_descriptor, int *flag) {
    return setsockopt(socket_file_descriptor, IPPROTO_TCP, TCP_NODELAY,
                      (char *)flag, sizeof(int));
}

struct sockaddr_in create_sockaddr_structure(char *destination_address,
                                             int proxy_port) {
    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;

    /* Converts Destination IP Address from Text to binary */
    inet_pton(AF_INET, destination_address, &sockaddr.sin_addr);
    sockaddr.sin_port = htons(proxy_port);
    return sockaddr;
}

int connect_to_socket(int socket_file_descriptor,
                      struct sockaddr_in *socket_address) {
    return connect(socket_file_descriptor, (struct sockaddr *)socket_address,
                   sizeof(*socket_address));
}

int send_data_from_client_to_server_via_proxy(int updated_file_descriptor,
                                              int destination_socket_fd,
                                              AES_KEY *session_key,
                                              struct ctr_state *server_state) {
    int recieved_bytes;
    int tobe_send_bytes;
    struct timespec time;
    int status;
    char plain[MESSAGE_LENGTH], cipher[MESSAGE_LENGTH];
    recieved_bytes = read(updated_file_descriptor, cipher, sizeof(cipher));
    if (recieved_bytes == 0) {
        return 0;
    } else if (recieved_bytes < 0) {
        fprintf(stdout, "\nNot able to revieve the data\n");
        fflush(stdout);
        return 0;
    }

    status =
        decrypt_text(cipher, plain, recieved_bytes, session_key, server_state);

    if (status != 0) {
        fprintf(stdout, "\nNot able to decrypt the text\n");
        fflush(stdout);
        return -1;
    }
    tobe_send_bytes = write(destination_socket_fd, plain, recieved_bytes - 8);
    if (tobe_send_bytes <= 0) {
        fprintf(stdout, "\nNot able to send the data");
        fflush(stdout);
    } else if (tobe_send_bytes < (recieved_bytes - 8)) {
        fprintf(stdout, "\nNot able to send the complete data");
        fflush(stdout);
    }
    time.tv_sec = 0;
    time.tv_nsec = 10 * 1000;
    nanosleep(&time, NULL);
    return 1;
}

int send_data_from_server_to_client_via_proxy(int updated_file_descriptor,
                                              int destination_socket_fd,
                                              AES_KEY *session_key,
                                              struct ctr_state *server_state) {
    int recieved_bytes;
    int tobe_send_bytes;
    struct timespec time;
    int status;
    char plain[MESSAGE_LENGTH], cipher[MESSAGE_LENGTH];
    recieved_bytes = read(destination_socket_fd, plain, sizeof(plain));
    if (recieved_bytes == 0) {
        fprintf(stdout, "\nSSH Server Terminated the connection");
        fflush(stdout);
        return 0;
    } else if (recieved_bytes < 0) {
        fprintf(stdout, "\nNot able to recieve data on ssh socket\n");
        fflush(stdout);
        return 0;
    }

    status =
        encrypt_text(plain, cipher, recieved_bytes, session_key, server_state);
    if (status != 0) {
        fprintf(stdout, "\nNot able to encrypt the data at the server\n");
        fflush(stdout);
        return -1;
    }

    tobe_send_bytes =
        write(updated_file_descriptor, cipher, recieved_bytes + 8);
    if (tobe_send_bytes <= 0) {
        fprintf(stdout, "\nNot able to send the data to the server");
        fflush(stdout);
    } else if (tobe_send_bytes < (recieved_bytes + 8)) {
        fprintf(stdout, "\nNot able to send the complete data to the server");
        fflush(stdout);
    }
    time.tv_sec = 0;
    time.tv_nsec = 10 * 1000;
    nanosleep(&time, NULL);
    return 1;
}

int proxy_server_handler(int updated_file_descriptor, int destination_port,
                         char *destination_address, char *key) {

    int status, destination_socket_fd;
    struct ctr_state server_state;
    AES_KEY session_key;
    int flag = 1;
    int result;

    status = AES_set_encrypt_key(key, 128, &session_key);
    if (status != 0) {
        fprintf(stdout, "\nNot able to set the encryption key\n");
        fflush(stdout);
        return -1;
    }

    destination_socket_fd = create_socket_for_proxy();
    struct sockaddr_in server =
        create_sockaddr_structure(destination_address, destination_port);
    status = connect_to_socket(destination_socket_fd, &server);

    if (status != 0) {
        fprintf(stdout,
                "\nNot Able to connect to the SSH Port. Check Permission\n");
        fflush(stdout);
        return -1;
    }

    status = set_socket_options(destination_socket_fd, &flag);
    status = set_socket_options(updated_file_descriptor, &flag);
    for (;;) {
        fd_set mon_fd;

        FD_ZERO(&mon_fd);
        FD_SET(destination_socket_fd, &mon_fd);
        FD_SET(updated_file_descriptor, &mon_fd);

        if (updated_file_descriptor > destination_socket_fd)
            status =
                monitor_and_wait_until_ready(updated_file_descriptor, &mon_fd);
        else
            status =
                monitor_and_wait_until_ready(destination_socket_fd, &mon_fd);
        if (status < 0) {
            fprintf(stdout, "\nSocket Monitoring Failed\n");
            fflush(stdout);
            return 0;
        }

        if (FD_ISSET(updated_file_descriptor, &mon_fd)) {
            result = send_data_from_client_to_server_via_proxy(
                updated_file_descriptor, destination_socket_fd, &session_key,
                &server_state);
            if (result == 0)
                break;
            else if (result == -1)
                return result;
        }

        if (FD_ISSET(destination_socket_fd, &mon_fd)) {
            result = send_data_from_server_to_client_via_proxy(
                updated_file_descriptor, destination_socket_fd, &session_key,
                &server_state);
            if (result == 0)
                break;
            else if (result == -1)
                return result;
        }
    }
    close(updated_file_descriptor);
    close(destination_socket_fd);
    return 0;
}

char *read_key_from_key_file(char *crypto_key_file_name) {
    FILE *file = fopen(crypto_key_file_name, "r");
    if (file == NULL) {
        fprintf(
            stdout,
            "\nNot able to find the key file, please specify the correct path "
            "for the key file\n");
        fflush(stdout);
        exit(-1);
    }
    char *key = (char *)malloc(IDEAL_CRYPTO_KEY_LENGTH * sizeof(char));
    fgets(key, IDEAL_CRYPTO_KEY_LENGTH, file);
    key[15] = '\0';
    return key;
}

void get_proxy_port(char *port, int *proxy_port) {
    char *ptr = NULL;
    *proxy_port = (int)strtol(port, &ptr, 10);
    if (*proxy_port < 0 || *proxy_port > 65535) {
        fprintf(stdout,
                "\nDestination Port numbers must be in the range 0-65535\n");
        fflush(stdout);
        exit(0);
    }
}

char *get_destination_address_and_port(int arg_count, int *destination_port,
                                       char **argv) {
    int index = 2 * arg_count + 1;
    char *ptr = NULL;
    char *destination_address =
        (char *)malloc(sizeof(char) * strlen(argv[index]));
    strncpy(destination_address, argv[index], strlen(argv[index]));
    *destination_port = (int)strtol(argv[++index], &ptr, 10);
    if (*destination_port < 0 || *destination_port > 65535) {
        fprintf(stdout, "\nProxy Port numbers must be in the range 0-65535\n");
        fflush(stdout);
        exit(0);
    }
    return destination_address;
}

int main(int argc, char **argv) {
    int commandline_argument_count = 0;
    char option;
    char *key = NULL;
    char *destination_address;
    int destination_port = -1;
    int proxy_port = -1;

    if (argc < 4) {
        fprintf(stdout, "\nToo less Command Line Arguments\n");
        fflush(stdout);
        return 0;
    }

    while ((option = getopt(argc, argv, "l:k:")) != -1) {
        if (option == 'k') {
            key = read_key_from_key_file(optarg);
        } else if (option == 'l') {
            get_proxy_port(optarg, &proxy_port);
        } else if (option == '?') {
            fprintf(stdout, "\nUnknown option specified\n");
            fflush(stdout);
        } else if (option == ':') {
            fprintf(stdout, "\nMissing Argument\n");
            fflush(stdout);
        }
        ++commandline_argument_count;
    }
    destination_address = get_destination_address_and_port(
        commandline_argument_count, &destination_port, argv);

    if (proxy_port == -1) {
        handle_client_mode(destination_address, destination_port, key);
    } else {
        handle_server_mode(destination_address, destination_port, proxy_port,
                           key);
    }
    return 0;
}
