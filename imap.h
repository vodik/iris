#include <stdio.h>
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

struct sock;

int imap_connect(struct sock *sock, const char *hostname,
		 const char *service, SSL_CTX *ctx);
int imap_sendmsg(struct sock *sock, const char *fmt, ...);
