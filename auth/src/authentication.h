#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <stddef.h>
#define SALT_LENGTH 16
#define HASH_LENGTH SHA256_DIGEST_LENGTH

#define SECRET_KEY "OP0GVA1ABbK04hC46NkEYsBAykjUNe0dvf+COdW/YGI="
#define SECRET_KEY_LEN 32

// crypto
#define AES_BLOCK_SIZE 16
#define BUFFER_SIZE 4096

#define REDIS_HOST "localhost"
#define REDIS_PORT 6379

#define DB_HOST "127.0.0.1"
#define DB_USER "root"
#define DB_PASS ""
#define DB_NAME "auth"
#define DB_PORT 3306
#define MAX_USERNAME_LEN 20
#define QUERY_LEN 512

char *hex_to_string(unsigned char *data, size_t dataLength);

char *string_to_hex(const char *hex);

void create_salted_hash(const char *password, unsigned char *salt,
                        unsigned char *hash);

int signup(const char *username, const char *password);

const char *signin(const char *username, const char *password);

char *generate_jwt(const char *username);

int verify_jwt(const char *jwt_string, const char *username);

void ssl_send(unsigned char *plaintext, int sockfd);

void ssl_recv(unsigned char *plaintext, int sockfd);
#endif
