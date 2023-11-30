#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include "define.h"
#include "ssl.h"
#include <stdio.h>

void ssl_send(unsigned char *plaintext, int sockfd)
{
    int plaintext_len = strlen((char*)plaintext), ciphertext_len = 0;
    unsigned char buffer[BUFF_LEN + AES_BLOCK_SIZE + AES_BLOCK_SIZE]; // ciphertext + padding + iv
    unsigned char ciphertext[BUFF_LEN + AES_BLOCK_SIZE];
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
    memcpy(buffer + BUFF_LEN + AES_BLOCK_SIZE, iv, AES_BLOCK_SIZE);

    send(sockfd, buffer, sizeof(buffer), NULL);
    printf("[CHAT]sending: %s\n", plaintext);
}

void ssl_recv(unsigned char *plaintext, int sockfd)
{
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char plaintext_buffer[BUFF_LEN];
    unsigned char buffer[BUFF_LEN + AES_BLOCK_SIZE + AES_BLOCK_SIZE]; // ciphertext + padding + iv
    unsigned char ciphertext[BUFF_LEN + AES_BLOCK_SIZE];

    int ciphertext_len = 0, plaintext_len = 0;
    int recv_len = recv(sockfd, buffer, sizeof(buffer), 0);

    if(recv_len < 0){
        plaintext = NULL;
        return;
    }
    ciphertext_len = recv_len - AES_BLOCK_SIZE;

    memcpy(iv, buffer + BUFF_LEN + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    memcpy(ciphertext, buffer, BUFF_LEN + AES_BLOCK_SIZE);

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
    printf("[CHAT]received: %s\n", plaintext);
}
