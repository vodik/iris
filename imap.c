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
    int ret = snprintf(tag->buf, sizeof(tag->buf), "iris%d", ++tag->value);
    if (ret < 0)
	err(1, "failed to write tag");
    tag->len = ret;
    return ret;
}

int imap_getmsg(struct imap *imap, int unsolicited)
{
    char buf[BUFSIZ];
    const ssize_t nbytes_r = sock_read(&imap->sock, buf, sizeof(buf));
    if (nbytes_r < 0)
	return -1;

    for (const char *it = buf; it != buf + nbytes_r;) {
	const size_t eol = strcspn(it, "\n");
	if (it[eol] != '\n')
	    /* TODO: MALFORMED LINE */
	    return -1;

	if (*it == '*') {
	    printf("\033[%dm%.*s\033[0m\n", 34, (int)eol, it);
	} else if (strncmp(it, imap->tag.buf, imap->tag.len) == 0) {
	    printf("\033[%d;1m%.*s\033[0m\n", 34, (int)eol, it);
	    return 0;
	}

	it += eol + 1;
    }

    return unsolicited ? 0 : -1;
}

int imap_sendmsg(struct imap *imap, const char *fmt, ...)
{
    va_list ap;
    char stupid_buf[4089];

    size_t taglen = bump_tag(&imap->tag);
    memcpy(stupid_buf, imap->tag.buf, taglen);
    stupid_buf[taglen++] = ' ';

    va_start(ap, fmt);
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

    return imap_getmsg(imap, 1);
}
