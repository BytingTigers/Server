#include "authentication.h"

int main(){
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, sizeof(iv));

    unsigned char plaintext[]= "hello";
    unsigned char ciphertext[1024];
    encrypt(plaintext, strlen((char*) plaintext), SECRET_KEY, iv, ciphertext);

    printf("Ciphertext:\n");
    for (int i = 0; i < strlen((char *)ciphertext); i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return 0;
}