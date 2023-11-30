#include "authentication.h"
#include <hiredis/hiredis.h>
#include <jansson.h>
#include <jwt.h>
#include <mysql/mysql.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char *sanitize_sql_input(const char *input) {

    if (input == NULL) {
        return NULL;
    }

    size_t count = 0;
    for (const char *p = input; *p; p++) {
        if (*p == '\'') {
            count++;
        }
    }

    size_t new_length = strlen(input) + count + 1;
    char *sanitized = malloc(new_length);
    if (sanitized == NULL) {
        return NULL;
    }

    const char *src = input;
    char *dst = sanitized;
    while (*src) {
        if (*src == '\'') {
            *dst++ = '\'';
            *dst++ = '\'';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';

    return sanitized;
}

char *hex_to_string(unsigned char *data, size_t dataLength) {

    char *hexString = calloc(dataLength * 2 + 1, sizeof(char));

    if (!hexString) {
        fprintf(stderr, "Memory allocation error\n");
        exit(1);
    }

    for (size_t i = 0; i < dataLength; i++) {
        sprintf(hexString + (i * 2), "%02x", data[i]);
    }

    hexString[dataLength * 2] = '\0';
    return hexString;
}

char *string_to_hex(const char *hex) {

    if (!hex) {
        return NULL;
    }

    size_t hexLen = strlen(hex) / 2;

    char *hexString = calloc(hexLen + 1, sizeof(char));

    if (!hexString) {
        fprintf(stderr, "Memory allocation error\n");
        exit(1);
    }

    for (size_t i = 0; i < hexLen; i++) {
        sscanf(hex + i * 2, "%2hhx", &hexString[i]);
    }

    hexString[hexLen] = '\0';

    return hexString;
}

void create_salted_hash(const char *password, unsigned char *salt,
                        unsigned char *hash) {

    unsigned char data[SALT_LENGTH + strlen(password)];

    memcpy(data, salt, SALT_LENGTH);
    memcpy(data + SALT_LENGTH, password, strlen(password));

    SHA256(data, SALT_LENGTH + strlen(password), hash);
}

int signup(const char *username, const char *password) {

    MYSQL *conn;
    MYSQL_RES *res;

    char query[QUERY_LEN];

    conn = mysql_init(NULL);

    if (!conn) {
        fprintf(stderr, "mysql_init() failed\n");
        return EXIT_FAILURE;
    }

    if (mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT,
                           NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed\n");
        mysql_close(conn);
        return EXIT_FAILURE;
    }

    char *username_s = sanitize_sql_input(username);
    if (!username_s) {
        fprintf(stderr, "Sanitization for username failed.\n");
        mysql_close(conn);
        return EXIT_FAILURE;
    }
    snprintf(query, sizeof(query), "SELECT * FROM users WHERE username='%s'",
             username_s);
    free(username_s);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return EXIT_FAILURE;
    }

    res = mysql_store_result(conn);
    int num_rows = mysql_num_rows(res);

    if (num_rows > 0) {
        return -1;
    }

    unsigned char *salt, *password_hash;

    salt = calloc(sizeof(char), SALT_LENGTH);
    password_hash = calloc(sizeof(char), HASH_LENGTH);

    if (!salt || !password_hash) {
        fprintf(stderr, "calloc error");
        return -1;
    }

    if (!RAND_bytes(salt, SALT_LENGTH)) {
        fprintf(stderr, "error generating salt.\n");
        return -1;
    }

    create_salted_hash(password, salt, password_hash);

    char *hex_salt = hex_to_string(salt, SALT_LENGTH);
    char *hex_hash = hex_to_string(password_hash, HASH_LENGTH);

    username_s = sanitize_sql_input(username);
    if (!username_s) {
        fprintf(stderr, "Sanitization for username failed.\n");
        mysql_close(conn);
        return EXIT_FAILURE;
    }
    char *hex_hash_s = sanitize_sql_input(hex_hash);
    char *hex_salt_s = sanitize_sql_input(hex_salt);
    snprintf(query, sizeof(query),
             "INSERT INTO users(username, password_hash, salt) "
             "values('%s','%s','%s')",
             username_s, hex_hash_s, hex_salt_s);
    free(username_s);
    free(hex_hash_s);
    free(hex_salt_s);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return EXIT_FAILURE;
    }

    free(salt);
    free(password_hash);
    free(hex_salt);
    free(hex_hash);
    mysql_close(conn);
    mysql_free_result(res);

    return 0;
}

const char *signin(const char *id, const char *password) {
    MYSQL *conn;
    MYSQL_RES *res;

    char query[QUERY_LEN];

    conn = mysql_init(NULL);

    if (!conn) {
        fprintf(stderr, "mysql_init() failed\n");
        return NULL;
    }

    if (mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT,
                           NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed\n");
        mysql_close(conn);
        return NULL;
    }

    char *id_s = sanitize_sql_input(id);
    if (!id_s) {
        fprintf(stderr, "Sanitization for id failed.\n");
        mysql_close(conn);
        return NULL;
    }
    snprintf(query, sizeof(query), "SELECT salt FROM users WHERE username='%s'",
             id_s);
    free(id_s);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return NULL;
    }

    res = mysql_store_result(conn);
    if (mysql_num_rows(res) == 0) {
        return NULL;
    }
    mysql_free_result(res);

    char *string_salt = mysql_fetch_row(res)[0];
    unsigned char *salt = (unsigned char *)string_to_hex(string_salt);
    unsigned char *hash = calloc(HASH_LENGTH, sizeof(char));
    if (!hash || !salt) {
        return NULL;
    }

    create_salted_hash(password, salt, hash);
    char *hash_string = hex_to_string(hash, HASH_LENGTH);

    id = sanitize_sql_input(id);
    hash_string = sanitize_sql_input(hash_string);
    snprintf(
        query, sizeof(query),
        "SELECT salt FROM users WHERE username='%s' and password_hash='%s'", id,
        hash_string);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return NULL;
    }

    res = mysql_store_result(conn);
    int result = mysql_num_rows(res);
    mysql_free_result(res);

    if (result != 1) {
        free(salt);
        free(hash);
        free(hash_string);
        mysql_close(conn);
        return NULL;
    }

    redisContext *redis_context = redisConnect(REDIS_HOST, REDIS_PORT);
    if (redis_context == NULL || redis_context->err) {
        if (redis_context) {
            printf("Error: %s\n", redis_context->errstr);
            redisFree(redis_context);
        } else {
            printf("Can't allocate redis context\n");
        }
        free(salt);
        free(hash);
        free(hash_string);
        mysql_close(conn);
        return NULL;
    }

    redisReply *reply;

    redisCommand(redis_context, "SELECT 2");
    char *jwt = NULL;

    reply = redisCommand(redis_context, "GET %s", id);
    if (reply == NULL) {
        printf("Failed to save jwt to Redis: %s\n", redis_context->errstr);
        redisFree(redis_context);
        free(salt);
        free(hash);
        free(hash_string);
        mysql_close(conn);
        return jwt;
    }
    if (reply->str != NULL) {
        jwt = reply->str;
    } else {
        jwt = strdup(generate_jwt(id));
        reply = redisCommand(redis_context, "SETEX %s %d %s", id, 3600, jwt);

        if (reply == NULL) {
            printf("Failed to save jwt to Redis: %s\n", redis_context->errstr);
            redisFree(redis_context);
            free(salt);
            free(hash);
            free(hash_string);
            mysql_close(conn);
            return NULL;
        } else {
            freeReplyObject(reply);
        }
    }
    redisFree(redis_context);
    free(salt);
    free(hash);
    free(hash_string);
    mysql_close(conn);
    return jwt;
}

char *generate_jwt(const char *username) {
    jwt_t *jwt = NULL;

    char *out = NULL;
    time_t exp = time(NULL) + 3600;

    if (jwt_new(&jwt) != 0) {
        fprintf(stderr, "Error creating JWT object.\n");
        return NULL;
    }

    jwt_add_grant(jwt, "username", username);
    jwt_add_grant_int(jwt, "exp", exp);

    jwt_set_alg(jwt, JWT_ALG_HS256, (unsigned char *)SECRET_KEY,
                SECRET_KEY_LEN);
    out = jwt_encode_str(jwt);

    if (out == NULL) {
        fprintf(stderr, "Error encoding JWT.\n");
        jwt_free(jwt);
        return NULL;
    }

    jwt_free(jwt);
    return out;
}

int verify_jwt(const char *jwt_string, const char *username) {

    jwt_t *jwt = NULL;

    int ret = jwt_decode(&jwt, jwt_string, (unsigned char *)SECRET_KEY,
                         SECRET_KEY_LEN);

    if (ret != 0) {
        fprintf(stderr, "Invalid JWT.\n");
        return 0;
    }

    time_t exp = jwt_get_grant_int(jwt, "exp");
    if (exp < time(NULL)) {
        fprintf(stderr, "JWT has expired.\n");
        jwt_free(jwt);
        return 0;
    }

    const char *token_username = jwt_get_grant(jwt, "username");
    if (!token_username ||
        strncmp(token_username, username, MAX_USERNAME_LEN) != 0) {
        fprintf(stderr, "Username mismatch. \n");
        jwt_free(jwt);
        return 0;
    }

    jwt_free(jwt);
    return 1;
}

void ssl_send(unsigned char *plaintext, int sockfd)
{
    int plaintext_len = strlen((char*)plaintext), ciphertext_len = 0;
    unsigned char buffer[BUFFER_SIZE + AES_BLOCK_SIZE + AES_BLOCK_SIZE]; // ciphertext + padding + iv
    unsigned char ciphertext[BUFFER_SIZE + AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, sizeof(iv));

    EVP_CIPHER_CTX *ctx;
    int len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, SECRET_KEY, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, ciphertext, ciphertext_len);
    memcpy(buffer + BUFFER_SIZE + AES_BLOCK_SIZE, iv, AES_BLOCK_SIZE);

    printf("[AUTH]sending: %s\n", plaintext);

    send(sockfd, buffer, sizeof(buffer), NULL);
}

void ssl_recv(unsigned char *plaintext, int sockfd)
{
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char plaintext_buffer[BUFFER_SIZE];
    unsigned char buffer[BUFFER_SIZE + AES_BLOCK_SIZE + AES_BLOCK_SIZE]; // ciphertext + padding + iv
    unsigned char ciphertext[BUFFER_SIZE + AES_BLOCK_SIZE];

    int ciphertext_len = 0, plaintext_len = 0;
    int recv_len = recv(sockfd, buffer, sizeof(buffer), 0);

    if(recv_len < 0){
        plaintext = NULL;
        return;
    }
    ciphertext_len = recv_len - AES_BLOCK_SIZE;

    memcpy(iv, buffer + BUFFER_SIZE + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    memcpy(ciphertext, buffer, BUFFER_SIZE + AES_BLOCK_SIZE);

    // remove following null bytes
    for(int i=0;i<ciphertext_len;i++){
        if(ciphertext[i] == 0){
            ciphertext_len = i;
            break;
        }
    }

    EVP_CIPHER_CTX *ctx;
    int len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, SECRET_KEY, iv);

    EVP_DecryptUpdate(ctx, plaintext_buffer, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext_buffer + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext_buffer[plaintext_len] = '\0';
    
    memset(plaintext, 0, sizeof(plaintext));
    memcpy(plaintext, plaintext_buffer, strlen((char*)plaintext_buffer));
    printf("[AUTH]received: %s\n", plaintext);
}
