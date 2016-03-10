#pragma once

#include <openssl/ssl.h>

struct sock {
    int fd;
    SSL *ssl;
    int use_ssl;
};

int smtp_connect(const char *hostname, const char *service, struct sock *sock);
void sock_read(struct sock *sock);
int sock_write(struct sock *sock, const char *msg);
int sock_close(struct sock *sock);
void socket_perror(struct sock *sock, int ret);
