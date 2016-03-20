#include <stdio.h>
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

#include "socket.h"
#include "smtp.h"
#include "base64.h"

int smtp_get_msg(struct sock *sock)
{
    char buf[BUFSIZ];
    const ssize_t nbytes_r = sock_read(sock, buf, sizeof(buf));
    if (nbytes_r < 0)
	return -1;

    for (const char *it = buf; it && it != buf + nbytes_r;) {
	const size_t eol = strcspn(it, "\n");
	if (it[eol] != '\n')
	    /* TODO: MALFORMED LINE */
	    return -1;

	printf("\033[31;1m%.*s\033[0m\033[31m%.*s\033[0m\n", 4, it, (int)eol - 4, it + 4);
	it += eol + 1;
    }

    return SMTP_OK;
}

int smtp_connect(struct sock *sock, const char *hostname,
		 const char *service, SSL_CTX *ctx)
{
    sock_connect(sock, hostname, service);
    smtp_get_msg(sock);

    if (ctx)
	smtp_start_tls(sock, ctx);
    return smtp_ehlo(sock, hostname);
}

int smtp_ehlo(struct sock *sock, const char *user)
{
    sock_sendmsg(sock, "EHLO %s", user);
    return smtp_get_msg(sock);
}

int smtp_start_tls(struct sock *sock, SSL_CTX *ctx)
{
    sock_sendmsg(sock, "STARTTLS");
    smtp_get_msg(sock);

    sock->ssl = SSL_new(ctx);
    SSL_set_fd(sock->ssl, sock->fd);

    int ret = SSL_connect(sock->ssl);
    if (ret <= 0)
        sock_err(sock, ret);

    sock->use_ssl = 1;
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

    return smtp_get_msg(sock);
}
