#pragma once

#include <openssl/ssl.h>

struct sock {
    int fd;
    SSL *ssl;
    int use_ssl;
};

int sock_connect(struct sock *sock, const char *hostname, const char *service);
ssize_t sock_read(struct sock *sock, char *buf, size_t bufsize);
void sock_dump(struct sock *sock);
int sock_write(struct sock *sock, const char *msg);
int sock_close(struct sock *sock);
void sock_err(struct sock *sock, int ret);
int sock_sendmsg(struct sock *sock, const char *fmt, ...);
int sock_vsendmsg(struct sock *sock, const char *fmt, va_list ap);
