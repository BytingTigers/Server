#ifndef VERIFY_JWT_H
#define VERIFY_JWT_H

#include "define.h"
#include <hiredis/hiredis.h>
#include <jansson.h>
#include <jwt.h>
#include <mysql/mysql.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int verify_jwt(const char *jwt_string, const char *username);

#endif
