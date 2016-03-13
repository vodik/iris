#include <stdio.h>
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

#include "socket.h"
#include "smtp.h"
#include "base64.h"

int smtp_ehlo(struct sock *sock, const char *user)
{
    sock_sendmsg(sock, "EHLO %s", user);
    sock_read(sock);
    return 0;
}

int smtp_start_tls(struct sock *sock, SSL_CTX *ctx)
{
    sock_sendmsg(sock, "STARTTLS");
    sock_read(sock);

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

    sock_read(sock);
    return 0;
}
