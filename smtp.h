#pragma once

#include <stdarg.h>
#include <openssl/ossl_typ.h>

struct sock;

int start_tls(SSL_CTX *ctx, struct sock *sock);
int authenticate(struct sock *sock, const char *user, size_t user_size,
		 const char *passwd, size_t passwd_size);
