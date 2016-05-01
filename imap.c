#include "imap.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdarg.h>
#include <err.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

#include "socket.h"

static size_t bump_tag(struct tag *tag)
{
    /* FIXME: super stupid */
    int ret = snprintf(tag->buf, sizeof(tag->buf), "iris%d ", ++tag->value);
    if (ret < 0)
	err(1, "failed to write tag");
    return ret;
}

int imap_get_msg(struct imap *imap)
{
    char buf[BUFSIZ];
    const ssize_t nbytes_r = sock_read(&imap->sock, buf, sizeof(buf));
    if (nbytes_r < 0)
	return -1;

    printf("\033[%dm%s\033[0m\n", 34, buf);

    /* if (strncmp(buf, tag, taglen) != 0) */
    /* 	return -1; */
    return 0;
}

int imap_sendmsg(struct imap *imap, const char *fmt, ...)
{
    va_list ap;
    char stupid_buf[4089];

    const size_t taglen = bump_tag(&imap->tag);
    va_start(ap, fmt);
    memcpy(stupid_buf, imap->tag.buf, taglen);
    size_t len = vsnprintf(stupid_buf + taglen, sizeof(stupid_buf) - taglen, fmt, ap);
    va_end(ap);

    len += taglen;
    stupid_buf[len++] = '\r';
    stupid_buf[len++] = '\n';
    stupid_buf[len] = '\0';

    sock_write(&imap->sock, stupid_buf);
    printf("\033[32m%s\033[0m", stupid_buf);
    return len;
}

int imap_connect(struct imap *imap, const char *hostname,
		 const char *service, SSL_CTX *ctx)
{
    sock_connect(&imap->sock, hostname, service);
    if (ctx)
	sock_starttls(&imap->sock, ctx);

    char buf[BUFSIZ];
    sock_read(&imap->sock, buf, sizeof(buf));
    printf("got: %s\n", buf);
    return 0;
}
