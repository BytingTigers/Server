#ifndef CLIENT_HANDLER_H
#define CLIENT_HANDLER_H

#include "client.h"
#include "define.h"
#include "room.h"
#include "verify_jwt.h"
#include <hiredis/hiredis.h>
#include <stdlib.h>
#include <unistd.h>

#define AES_BLOCK_SIZE 16

typedef struct {
    client_t *client;
    chat_server_t *server;
    redisContext *redis_context;
} thread_args_t;

typedef enum { SEND, JOIN, LEAVE, MAKE, QUIT, LISTROOM} request_t;

void *handle_client(void *arg);

#endif
