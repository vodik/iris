#include <stdio.h>
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
#include "socket.h"

struct tag {
    int value;
    size_t len;
    char buf[8];  // irisXXX\0
};

struct imap {
    struct sock sock;
    struct tag tag;
};

int imap_connect(struct imap *imap, const char *hostname,
		 const char *service, SSL_CTX *ctx);
int imap_sendmsg(struct imap *imap, const char *fmt, ...);
int imap_getmsg(struct imap *imap, int unsolicited);
