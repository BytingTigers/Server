#include "room.h"
#include "ssl.h"
#include <hiredis/hiredis.h>
#include <hiredis/read.h>

room_t **_get_rooms(redisContext *redis_context) {

    static room_t **rooms = NULL;

    redisReply *reply;

    if (rooms == NULL) {
        rooms = calloc(sizeof(room_t *), MAX_ROOMS_PER_SERVER);

        reply = redisCommand(redis_context, "SMEMBERS rooms");
        if (!reply) {
            free(rooms);
            return NULL;
        }

        for (int i = 0; i < reply->elements; i++) {
            rooms[i] = malloc(sizeof(room_t));
            rooms[i]->id = strdup(reply->element[i]->str);
            memset(rooms[i]->clients, 0,
                   sizeof(client_t *) * MAX_CLIENTS_PER_ROOM);
            rooms[i]->client_count = 0;
        }
        freeReplyObject(reply);

        for (int i = 0; i < MAX_ROOMS_PER_SERVER && rooms[i] != NULL; i++) {
            room_t *cur = rooms[i];
            reply =
                redisCommand(redis_context, "GET room_password:%s", cur->id);

            if (!reply) {
                return NULL;
            }

            if (reply->type == REDIS_REPLY_STRING) {
                cur->password = strdup(reply->str);
            } else {
                cur->password = NULL;
            }
        }
        freeReplyObject(reply);
    }
    return rooms;
}

room_t *get_room(redisContext *redis_context, const char *id) {

    room_t **rooms = _get_rooms(redis_context);
    if(rooms == NULL){
        return NULL;
    }
    
    for (int i = 0; i < MAX_ROOMS_PER_SERVER && rooms[i] != NULL; i++) {
        room_t *cur = rooms[i];
        if (strcmp(cur->id, id) == 0) {
            return cur;
        }
    }
    return NULL;
}

room_t *create_room(redisContext *redis_context, const char *id,
                    const char *password) {


    redisReply *reply = redisCommand(redis_context, "SADD rooms %s", id);

    if (!reply || reply->integer == 0) {
        return NULL;
    }

    reply =
        redisCommand(redis_context, "SET room_password:%s %s", id, password);

    if (!reply) {
        return NULL;
    }

    freeReplyObject(reply);

    room_t **rooms = _get_rooms(redis_context);

    int create_room_index = 0;
    for (int i = 0; i < MAX_ROOMS_PER_SERVER; i++) {
        if (rooms[i] == NULL) {
            create_room_index = i;
            break;
        }
    }

    if (create_room_index == -1) {
        return NULL;
    }

    room_t *new_room = malloc(sizeof(room_t));

    new_room->client_count = 0;
    new_room->id = strdup(id);
    if (password) {
        new_room->password = strdup(password);
    } else {
        new_room->password = NULL;
    }

    for (int i = 0; i < MAX_CLIENTS_PER_ROOM; i++) {
        new_room->clients[i] = NULL;
    }

    rooms[create_room_index] = new_room;

    return new_room;
}

int join_room(room_t *room, const char *password, client_t *client) {

    if (strncmp(room->password, password, strlen(room->password)) != 0) {
        return 0;
    }

    if (room->client_count >= MAX_CLIENTS_PER_ROOM) {
        return 0;
    }

    for (int i = 0; i < MAX_CLIENTS_PER_ROOM; i++) {
        if (room->clients[i] == NULL) {
            room->clients[i] = client;
            room->client_count++;
            return 1;
        }
    }

    return 0;
}

int leave_room(room_t *room, client_t *client) {

    for (int i = 0; i < MAX_CLIENTS_PER_ROOM; i++) {
        if (room->clients[i] == client) {
            room->clients[i] = NULL;
            break;
        }
    }

    room->client_count--;

    return room->client_count;
}

int new_message(redisContext *redis_context, const room_t *room,
                const unsigned char *msg) {


    redisReply *reply =
        redisCommand(redis_context, "LPUSH msgs:%s %s", room->id, msg);

    if (!reply) {
        return 1;
    }

    freeReplyObject(reply);

    for (int i = 0; i < MAX_CLIENTS_PER_ROOM; i++) {
        if (room->clients[i] != NULL) {
            ssl_send(msg, room->clients[i]->sockfd);
        }
    }

    return 0;
}

char *get_messages(redisContext *redis_context, const room_t *room) {

    int count = 0;
    char *res = malloc(BUFF_LEN);

    if (!res) {
        return NULL;
    }

    redisReply *reply =
        redisCommand(redis_context, "LRANGE msgs:%s 0 -1", room->id);

    if (!reply) {
        return NULL;
    }

    if(reply->elements == 0){
        freeReplyObject(reply);
        return NULL;
    }
    
    for (int i = reply->elements - 1; i >= 0; i--) {
        const char *line = reply->element[i]->str;
        strncat(res, line, BUFF_LEN - (count + 1));
        count = strlen(res);
        if (count >= BUFF_LEN - 1) {
            break;
        }
    }

    freeReplyObject(reply);
    return res;
}
