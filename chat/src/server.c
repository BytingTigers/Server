#include <stdio.h>
#include <stdlib.h>

#include "chat.h"
#include "client_handler.h"

#define MAX_CHATROOMS 100

void display_help() { fprintf(stdout, "Usage: start [port]\n"); }

int main(int argc, char *argv[]) {
    if (argc != 2) {
        display_help();
        return -1;
    }

    int server_port = atoi(argv[1]);

    if (server_port == 0) {
        char err_msg[BUFFER_SIZE];
        snprintf(err_msg, sizeof(err_msg),
                 "Cound not convert to a port number: %s", argv[1]);
        perror(err_msg);
        return -1;
    }

    if (server_port < 1 || server_port > 65535) {
        printf("Invalid port: %d\n", server_port);
        return -1;
    }

    chat_server_t server;

    pthread_mutex_init(&server.clients_mutex, NULL);
    memset(server.clients, 0, sizeof(server.clients));
    server.server_port = server_port;

    int client_count = 0;
    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;
    struct sockaddr_in cli_addr;
    pthread_t tid;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(server.server_port);

    if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR: Socket binding failed");
        exit(1);
    }

    if (listen(listenfd, 10) < 0) {
        perror("ERROR: Socket listening failed");
        exit(1);
    }

    printf("<[ MESSAGE SERVER at PORT %d STARTED ]>\n", server_port);

    redisContext *redis_context = redisConnect(REDIS_HOST, REDIS_PORT);
    if (redis_context == NULL || redis_context->err) {
        if (redis_context) {
            printf("Error: %s\n", redis_context->errstr);
            redisFree(redis_context);
        } else {
            printf("Can't allocate redis context\n");
        }
        exit(1);
    }

    redisCommand(redis_context, "SELECT 1");

    while (1) {
        socklen_t clilen = sizeof(cli_addr);
        connfd = accept(listenfd, (struct sockaddr *)&cli_addr, &clilen);

        if ((client_count + 1) == MAX_CLIENTS) {
            close(connfd);
            continue;
        }

        client_t *cli = (client_t *)malloc(sizeof(client_t));
        if (cli == NULL) {
            perror("Failed to allocate memory for new client");
            continue;
        }

        cli->address = cli_addr;
        cli->sockfd = connfd;
        cli->uid = client_count;

        thread_args_t *args = malloc(sizeof(thread_args_t));
        if (args == NULL) {
            perror("Failed to allocate memory for thread arguments");
            free(cli);
            continue;
        }
        args->client = cli;
        args->server = &server;
        args->redis_context = redis_context;

        add_client(cli, &server);
        if (pthread_create(&tid, NULL, &handle_client, (void *)args) != 0) {
            perror("Failed to create thread");
            free(cli);
            free(args);
            continue;
        }

        client_count++;
    }
    pthread_mutex_destroy(&server.clients_mutex);
    close(listenfd);

    return 0;
}
