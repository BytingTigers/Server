#include "authentication.h"
#include <string.h>
#include <stdio.h>

int test_enc(){
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, sizeof(iv));

    unsigned char plaintext[1025]= "hello";
    unsigned char ciphertext[1041];

    int ciphertext_len = 0;
    ciphertext_len = encrypt(plaintext, strlen((char*) plaintext), SECRET_KEY, iv, ciphertext);

    printf("Ciphertext:\n");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    decrypt(ciphertext, ciphertext_len, SECRET_KEY, iv, plaintext);

    printf("Plaintext:\n");
    printf("%s\n", plaintext);
    return 0;
}