#include "client.h"

void add_client(client_t *client, chat_server_t *server) {
    pthread_mutex_lock(&server->clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (!server->clients[i]) {
            server->clients[i] = client;
            break;
        }
    }

    pthread_mutex_unlock(&server->clients_mutex);
}

void remove_client(int uid, chat_server_t *server) {

    pthread_mutex_lock(&server->clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (server->clients[i]) {
            if (server->clients[i]->uid == uid) {
                server->clients[i] = NULL;
                break;
            }
        }
    }

    pthread_mutex_unlock(&server->clients_mutex);
}
