#ifndef ROOM_H
#define ROOM_H

#include "client.h"
#include "define.h"
#include <hiredis/hiredis.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *id;
    char *password;
    client_t *clients[MAX_CLIENTS_PER_ROOM];
    int client_count;
} room_t;

room_t **_get_rooms(redisContext *redis_context);

room_t *get_room(redisContext *redis_context, const char *id);

room_t *create_room(redisContext *redis_context, const char *id,
                    const char *password);

int join_room(room_t *room, const char *password, client_t *client);

int leave_room(room_t *room, client_t *client);

int new_message(redisContext *redis_context, const room_t *room,
                const unsigned char *msg);

char *get_messages(redisContext *redis_context, const room_t *room);

#endif
