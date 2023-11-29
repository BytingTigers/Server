#ifndef SSL_H
#define SSL_H

void ssl_send(unsigned char *plaintext, int sockfd);
void ssl_recv(unsigned char *plaintext, int sockfd);

#endif