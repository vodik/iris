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
    ssize_t nbytes_r = sock_read(&imap->sock, buf, sizeof(buf));
    if (nbytes_r < 0)
	return -1;

    for (const char *it = buf; it != buf + nbytes_r;) {
	size_t eol = strcspn(it, "\n");
	if (it[eol] != '\n')
	    /* TODO: MALFORMED LINE */
	    return -1;

	const size_t lbracket = strcspn(it, "{");

	if (*it == '*') {
	    printf("\033[%dm%.*s\033[0m\n", 34, (int)eol, it);
	}

	if (it[lbracket] == '{') {
	    /* FIXME: undefined behaviour warning */
	    const size_t payload_size = atol(it + lbracket + 1);

	    it += eol + 1;

	    /* Deal with what's already present */
	    size_t acc = nbytes_r - (it - buf);
	    printf("\033[%dm%.*s\033[0m", 35, (int)acc, it);

	    /* Read more stuff */
	    for (;;) {
		nbytes_r = sock_read(&imap->sock, buf, sizeof(buf));
		acc += nbytes_r;

		size_t msglen;
		if (acc >= payload_size) {
		    msglen = nbytes_r - (acc - payload_size);
		} else {
		    msglen = nbytes_r;
		}

		printf("\033[%dm%.*s\033[0m", 35, (int)msglen, buf);

		/* If we're over the end, read again */
		if (acc >= payload_size) {
		    nbytes_r = sock_read(&imap->sock, buf, sizeof(buf));
		    it = buf;
		    eol = strcspn(it, "\n");
		    if (it[eol] != '\n')
			/* TODO: MALFORMED LINE */
			return -1;
		    break;
		}
	    }
	}

	if (imap->tag.len && strncmp(it, imap->tag.buf, imap->tag.len) == 0) {
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
