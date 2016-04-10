#include <stdio.h>
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

#include "socket.h"
#include "smtp.h"
#include "base64.h"

int smtp_get_msg(struct sock *sock, int pipeline)
{
    char buf[BUFSIZ];
    const ssize_t nbytes_r = sock_read(sock, buf, sizeof(buf));
    if (nbytes_r < 0)
	return -1;

    for (const char *it = buf; it != buf + nbytes_r;) {
	const size_t eol = strcspn(it, "\n");
	/* TODO: assert length of line >= 4 characters */
	if (it[eol] != '\n')
	    /* TODO: MALFORMED LINE */
	    return -1;

	const int status = (it[0] - '0') * 100 +
	                   (it[1] - '0') * 10 +
	                   (it[2] - '0');

	const int color = status >= 400 ? 31 : 34;
	printf("\033[%d;1m%d\033[0m\033[%dm%.*s\033[0m\n",
	       color, status, color, (int)eol - 3, it + 3);

	if (status >= 400)
	    return -1;
	else if (it[3] == ' ' && --pipeline == 0)
	    return SMTP_OK;

	it += eol + 1;
    }

    return -1;
}

int smtp_sendmsg(struct sock *sock, int pipeline, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    sock_vsendmsg(sock, fmt, ap);
    va_end(ap);

    return smtp_get_msg(sock, pipeline);
}

int smtp_connect(struct sock *sock, const char *hostname,
		 const char *service, SSL_CTX *ctx)
{
    sock_connect(sock, hostname, service);
    smtp_get_msg(sock, 1);

    if (ctx)
	smtp_starttls(sock, ctx);
    return smtp_ehlo(sock, hostname);
}

int smtp_ehlo(struct sock *sock, const char *user)
{
    sock_sendmsg(sock, "EHLO %s", user);
    return smtp_get_msg(sock, 1);
}

int smtp_starttls(struct sock *sock, SSL_CTX *ctx)
{
    sock_sendmsg(sock, "STARTTLS");
    smtp_get_msg(sock, 1);

    sock_starttls(sock, ctx);
    return 0;
}

int smtp_auth_plain(struct sock *sock, const char *user, size_t user_size,
		    const char *passwd, size_t passwd_size)
{
    const size_t total_size = user_size + passwd_size + 2;
    unsigned char buf[total_size + 1], *p = buf;

    *p++ = '\0';
    p = mempcpy(p, user, user_size);

    *p++ = '\0';
    p = mempcpy(p, passwd, passwd_size);

    char *encoded = base64_encode(buf, total_size, NULL);
    if (!encoded)
	exit(1);

    sock_sendmsg(sock, "AUTH PLAIN %s", encoded);
    free(encoded);

    return smtp_get_msg(sock, 1);
}
