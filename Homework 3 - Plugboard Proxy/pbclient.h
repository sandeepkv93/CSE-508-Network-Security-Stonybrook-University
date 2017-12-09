#ifndef PBCLIENT_H
#define PBCLIENT_H

void handle_client_mode(char *destination_address, int destination_port,
                        char *key);
int client_launch(int soc_fd, char *key);
int create_client_connection(char *destination_address, int destination_port,
                             int *ret);

#endif