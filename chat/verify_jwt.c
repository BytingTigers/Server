#include "verify_jwt.h"

int verify_jwt(const char *jwt_string, const char *username) {

    jwt_t *jwt = NULL;

    char *key = strdup(SECRET_KEY);
    int ret = jwt_decode(&jwt, jwt_string, NULL, 0);

    if (ret != 0) {
        fprintf(stderr, "Invalid JWT.\n");
        jwt_free(jwt);
        return 0; 
    }

    time_t exp = jwt_get_grant_int(jwt, "exp");
    if (exp < time(NULL)) {
        fprintf(stderr, "JWT has expired.\n");
        jwt_free(jwt);
        return 0;
    }

    const char *token_username = jwt_get_grant(jwt, "username");
    if (!token_username || strcmp(token_username, username) != 0) {
        fprintf(stderr, "Username mismatch. \n");
        jwt_free(jwt);
        return 0;
    }

    jwt_free(jwt);
    return 1;
}
