#define CLIENT_TIMEOUT 30
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10
#define MAX_ROOM_ID_LEN 20
#define MAX_USERNAME_LEN 20
#define MAX_PASSWORD_LEN 20

#define BUFF_LEN 4096
#define MAX_CLIENTS_PER_ROOM 1024

#define QUERY_LEN 512
#define SALT_LENGTH 16
#define HASH_LENGTH SHA256_DIGEST_LENGTH

#define SECRET_KEY "OP0GVA1ABbK04hC46NkEYsBAykjUNe0dvf+COdW/YGI="
#define SECRET_KEY_LEN 32

#define REDIS_HOST "localhost"
#define REDIS_PORT 6379

#define DB_HOST "localhost"
#define DB_USER "root"
#define DB_PASS ""
#define DB_NAME "auth"
#define DB_PORT 3306

#define MAX_ROOMS_PER_SERVER 128
