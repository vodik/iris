#pragma once

#include <stdarg.h>
#include <openssl/ossl_typ.h>

#define SMTP_OK 250

struct sock;

int smtp_connect(struct sock *sock, const char *hostname,
		 const char *service, SSL_CTX *ctx);

int smtp_ehlo(struct sock *sock, const char *user);
int smtp_start_tls(struct sock *sock, SSL_CTX *ctx);
int smtp_auth_plain(struct sock *sock, const char *user, size_t user_size,
		    const char *passwd, size_t passwd_size);

int smtp_get_msg(struct sock *sock, int pipeline);
int smtp_sendmsg(struct sock *sock, int pipeline, const char *fmt, ...);
