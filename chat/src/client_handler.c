#include "client_handler.h"
#include "room.h"
#include "ssl.h"
#include <hiredis/hiredis.h>
#include <unistd.h>

/* Remove non-ASCII characters and ASCII control characters from the received
 * string. */
static char *sanitize(const char *str, size_t len) {
    static char buffer[BUFF_LEN + 2];
    unsigned int i, j;

    if (len > BUFF_LEN) {
        fprintf(stderr, "ERROR: message too long\n");
        return NULL;
    }

    memset(buffer, 0, sizeof(buffer));

    for (i = 0, j = 0; i < len; i++) {
        if (str[i] < 0x20 || str[i] > 0x7e)
            continue;
        buffer[j] = str[i];
        j++;
    }

    /* Add a line feed at the end of non-empty strings */
    if (j > 0)
        buffer[j] = 0x0a;

    return buffer;
}

void *handle_client(void *arg) {
    unsigned char recv_buffer[BUFF_LEN], send_buffer[BUFF_LEN];
    int leave_flag = 0;
    int recv_len;

    char *token, *rest;
    char username[MAX_USERNAME_LEN];
    char jwt_string[BUFF_LEN];
    const char delim[] = ":";

    char room_id[MAX_ROOM_ID_LEN];
    char password[MAX_PASSWORD_LEN];

    char *chat_history;

    const unsigned char empty_msg[] = "EMPTY";
    const unsigned char soft_error_msg[] = "ERROR";
    const unsigned char error_msg[] = "ERROR_QUIT";
    const unsigned char success_msg[] = "SUCCESS";
    redisReply *reply;

    thread_args_t *args = (thread_args_t *)arg;

    client_t *cli = args->client;
    chat_server_t *server = args->server;
    redisContext *redis_context = args->redis_context;

    request_t request;
    room_t *room = NULL;

    // ######################
    // # Token verification #
    // ######################
    ssl_recv(recv_buffer, cli->sockfd);
    if (recv_buffer == NULL) {
        close(cli->sockfd);
        remove_client(cli->uid, server);
        free(cli);
        free(args);
        pthread_detach(pthread_self());

        return NULL;
    }

    if (!sanitize(recv_buffer, strlen(recv_buffer))) {
        return NULL;
    }

    // `auth`
    rest = recv_buffer;
    token = strtok_r(rest, delim, &rest);
    if (token == NULL) {
        ssl_send(error_msg, cli->sockfd);

        close(cli->sockfd);
        remove_client(cli->uid, server);
        free(cli);
        free(args);
        pthread_detach(pthread_self());
        return NULL;
    }

    if (strncmp(token, "auth", strlen(token)) != 0) {
        ssl_send(error_msg, cli->sockfd);

        close(cli->sockfd);
        remove_client(cli->uid, server);
        free(cli);
        free(args);
        pthread_detach(pthread_self());
        return NULL;
    }

    // Username
    token = strtok_r(NULL, delim, &rest);
    if (token == NULL) {
        ssl_send(error_msg, cli->sockfd);

        close(cli->sockfd);
        remove_client(cli->uid, server);
        free(cli);
        free(args);
        pthread_detach(pthread_self());
        return NULL;
    }
    strncpy(username, token, MAX_USERNAME_LEN);

    // JWT
    token = strtok_r(NULL, delim, &rest);
    if (token == NULL) {
        ssl_send(error_msg, cli->sockfd);

        close(cli->sockfd);
        remove_client(cli->uid, server);
        free(cli);
        free(args);
        pthread_detach(pthread_self());
        return NULL;
    }
    strncpy(jwt_string, token, strlen(token));
    jwt_string[strcspn(jwt_string, "\n")] = '\0'; // remove last trail char

    if (verify_jwt(jwt_string, username) == 0) {
        ssl_send(error_msg, cli->sockfd);

        close(cli->sockfd);
        remove_client(cli->uid, server);
        free(cli);
        free(args);
        pthread_detach(pthread_self());
        return NULL;
    }
    strncpy(cli->username, username, MAX_USERNAME_LEN - 1);
    cli->username[MAX_USERNAME_LEN - 1] = '\0';

    ssl_send(success_msg, cli->sockfd);

    // ##################
    // # Message handle #
    // ##################

    while (1) {

        // set username sent via socket
        ssl_recv(recv_buffer, cli->sockfd);

        if (recv_buffer == NULL) {
            close(cli->sockfd);
            remove_client(cli->uid, server);
            free(cli);
            free(args);
            pthread_detach(pthread_self());

            return NULL;
        }
        if (!sanitize(recv_buffer, strlen(recv_buffer))) {
            return NULL;
        }

        rest = recv_buffer;
        token = strtok_r(rest, delim, &rest);
        if (token == NULL) {
            ssl_send(error_msg, cli->sockfd);

            close(cli->sockfd);
            remove_client(cli->uid, server);
            free(cli);
            free(args);
            pthread_detach(pthread_self());
            return NULL;
        }

        if (strncmp("join", token, 4) == 0) {
            request = JOIN;
        } else if (strncmp("leave", token, 5) == 0) {
            request = LEAVE;
        } else if (strncmp("send", token, 4) == 0) {
            request = SEND;
        } else if (strncmp("make", token, 4) == 0) {
            request = MAKE;
        } else if (strncmp("quit", token, 4) == 0) {
            request = QUIT;
        } else if (strncmp("list", token, 4) == 0) {
            request = LISTROOM;
        } else {
            continue;
        }

        switch (request) {
        case JOIN:
            token = strtok_r(NULL, delim, &rest);
            if (token == NULL) {
                ssl_send(error_msg, cli->sockfd);

                close(cli->sockfd);
                remove_client(cli->uid, server);
                free(cli);
                free(args);
                pthread_detach(pthread_self());
                return NULL;
            }
            strncpy(room_id, token, MAX_ROOM_ID_LEN);

            token = strtok_r(NULL, delim, &rest);
            if (token == NULL) {
                ssl_send(error_msg, cli->sockfd);

                close(cli->sockfd);
                remove_client(cli->uid, server);
                free(cli);
                free(args);
                pthread_detach(pthread_self());
                return NULL;
            }
            strncpy(password, token, sizeof(password));

            if (room != NULL) {
                leave_room(room, cli);
            }

            room = get_room(redis_context, room_id);

            if (room == NULL) {
                break;
            }

            if (join_room(room, password, cli) == 0) {
                ssl_send(soft_error_msg, cli->sockfd);
                break;
            } else {
                ssl_send(success_msg, cli->sockfd);
            }

            chat_history = get_messages(redis_context, room);
            ssl_send(chat_history, cli->sockfd); // write was used before(could cause error here)
            free(chat_history);

            memset(send_buffer, 0, sizeof(send_buffer));

            snprintf(send_buffer, BUFF_LEN, cli->username);
            send_buffer[sizeof(send_buffer) - 1] = '\0';

            new_message(redis_context, room, send_buffer);

            snprintf(send_buffer, BUFF_LEN, " joined the room!\n",
                     cli->username);
            send_buffer[sizeof(send_buffer) - 1] = '\0';
            new_message(redis_context, room, send_buffer);
            break;

        case LEAVE:
            if (room != NULL) {
                leave_room(room, cli);
            }
            room = NULL;
            break;

        case SEND:
            if (room == NULL) {
                ssl_send(error_msg, cli->sockfd);

                close(cli->sockfd);
                remove_client(cli->uid, server);
                free(cli);
                free(args);
                pthread_detach(pthread_self());
                return NULL;
            }

            token = strtok_r(NULL, delim, &rest);
            if (token == NULL) {
                ssl_send(error_msg, cli->sockfd);

                close(cli->sockfd);
                remove_client(cli->uid, server);
                free(cli);
                free(args);
                pthread_detach(pthread_self());
                return NULL;
            }
            snprintf(send_buffer, sizeof(send_buffer), "[%s] %s\n",
                     cli->username, token);
            send_buffer[sizeof(send_buffer) - 1] = '\0';
            new_message(redis_context, room, send_buffer);
            break;

        case MAKE:
            token = strtok_r(NULL, delim, &rest);
            if (token == NULL) {
                ssl_send(error_msg, cli->sockfd);

                close(cli->sockfd);
                remove_client(cli->uid, server);
                free(cli);
                free(args);
                pthread_detach(pthread_self());
                return NULL;
            }
            strncpy(room_id, token, sizeof(room_id));

            token = strtok_r(NULL, delim, &rest);
            if (token == NULL) {
                ssl_send(error_msg, cli->sockfd);

                close(cli->sockfd);
                remove_client(cli->uid, server);
                free(cli);
                free(args);
                pthread_detach(pthread_self());
                return NULL;
            }
            strncpy(password, token, sizeof(password));
            if (create_room(redis_context, room_id, password) == NULL) {
                ssl_send(soft_error_msg, cli->sockfd);
            } else {
                ssl_send(success_msg, cli->sockfd);
            }
            break;

        case QUIT:
            close(cli->sockfd);
            remove_client(cli->uid, server);
            free(cli);
            free(args);
            pthread_detach(pthread_self());
            return NULL;

        case LISTROOM:
            reply = redisCommand(redis_context, "SMEMBERS rooms");
            memset(send_buffer, 0, sizeof(send_buffer));
            int count = reply->elements;
            if (count == 0) {
                ssl_send(empty_msg, cli->sockfd);
                break;
            }
            int current_len = 0;
            for (int i = 0; i < count; i++) {
                char *room_id = strdup(reply->element[i]->str);
                int len = strlen(room_id);
                if (current_len + len < BUFF_LEN) {
                    strcat(send_buffer, room_id);
                    strcat(send_buffer, ".");
                    current_len += len + 1;
                }
                free(room_id);
            }

            // the last delimiter is not needed
            send_buffer[current_len - 1] = '\0';
            ssl_send(send_buffer, cli->sockfd);
        }
    }

    close(cli->sockfd);
    remove_client(cli->uid, server);
    free(cli);
    free(args);
    pthread_detach(pthread_self());

    return NULL;
}
