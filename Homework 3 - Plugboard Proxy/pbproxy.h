#include <openssl/aes.h>
#include <sys/types.h>
#ifndef PBPROXY_H
#define PBPROXY_H

int monitor_and_wait_until_ready(int nfd, fd_set *read_fds);
int create_socket_for_proxy();
int set_socket_options(int socket_file_descriptor, int *flag);
struct sockaddr_in create_sockaddr_structure(char *destination_address,
                                             int proxy_port);
int connect_to_socket(int socket_file_descriptor,
                      struct sockaddr_in *socket_address);
int proxy_server_handler(int new_fd, int destination_port,
                         char *destination_address, char *key);

#endif