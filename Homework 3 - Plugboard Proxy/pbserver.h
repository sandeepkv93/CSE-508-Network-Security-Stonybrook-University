#ifndef PBSERVER_H
#define PBSERVER_H

void handle_server_mode(char *destination_address, int destination_port,
                        int proxy_port, char *key);
int server_launch(int proxy_socket_file_descriptor, int destination_port,
                  char *destination_address, char *key);
int create_server_connection(char *destination_address, int proxy_port,
                             int *proxy_soc_fd);

#endif