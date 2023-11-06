#ifndef CLIENT_H
#define CLIENT_H

#include "define.h"
#include <arpa/inet.h>
#include <pthread.h>

typedef struct {
    struct sockaddr_in address;
    int sockfd;
    int uid;
    char username[MAX_USERNAME_LEN];
} client_t;

typedef struct {
    client_t *clients[MAX_CLIENTS];
    pthread_mutex_t clients_mutex;
    int server_port;
    char title[30];
    char password[20];
} chat_server_t;

void add_client(client_t *client, chat_server_t *server);

void remove_client(int uid, chat_server_t *server);

#endif
