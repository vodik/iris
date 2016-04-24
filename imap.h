#include <stdio.h>
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
#include "socket.h"

struct imap {
    struct sock sock;
};

int imap_connect(struct imap *imap, const char *hostname,
		 const char *service, SSL_CTX *ctx);
int imap_sendmsg(struct imap *imap, const char *fmt, ...);
int imap_get_msg(struct imap *imap);
