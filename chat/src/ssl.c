#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include "define.h"
#include "ssl.h"
#include <stdio.h>

void ssl_send(unsigned char *plaintext, int sockfd)
{
    int plaintext_len = strlen((char*)plaintext), ciphertext_len = 0;
    unsigned char buffer[BUFF_LEN + AES_BLOCK_SIZE + AES_BLOCK_SIZE + 2]; // ciphertext + padding + iv + length
    unsigned char ciphertext[BUFF_LEN + AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char length_byte[2];
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
    
    length_byte[0] = (ciphertext_len >> 8) & 0xff;
    length_byte[1] = ciphertext_len & 0xff;

    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, ciphertext, ciphertext_len);
    memcpy(buffer + BUFF_LEN + AES_BLOCK_SIZE, iv, AES_BLOCK_SIZE);
    memcpy(buffer + BUFF_LEN + AES_BLOCK_SIZE + AES_BLOCK_SIZE, length_byte, 2);
    send(sockfd, buffer, sizeof(buffer), NULL);
}

void ssl_recv(unsigned char *plaintext, int sockfd)
{
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char plaintext_buffer[BUFF_LEN];
    unsigned char buffer[BUFF_LEN + AES_BLOCK_SIZE + AES_BLOCK_SIZE + 2]; // ciphertext + padding + iv + length
    unsigned char ciphertext[BUFF_LEN + AES_BLOCK_SIZE];
    unsigned char length_byte[2];

    int ciphertext_len = 0, plaintext_len = 0;
    int recv_len = recv(sockfd, buffer, sizeof(buffer), 0);

    if(recv_len <= 0){
        plaintext = NULL;
        return;
    }

    ciphertext_len = (buffer[BUFF_LEN + AES_BLOCK_SIZE + AES_BLOCK_SIZE] << 8) + buffer[BUFF_LEN + AES_BLOCK_SIZE + AES_BLOCK_SIZE + 1];

    memcpy(iv, buffer + BUFF_LEN + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    memcpy(ciphertext, buffer, BUFF_LEN + AES_BLOCK_SIZE);

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
    memcpy(plaintext, plaintext_buffer, plaintext_len);
    plaintext[plaintext_len] = '\0';
}
