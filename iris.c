#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

#include "socket.h"
#include "base64.h"
#include "config.h"

static int sock_sendmsg(struct sock *sock, const char *fmt, ...)
{
    va_list ap;
    char stupid_buf[4089];

    va_start(ap, fmt);
    size_t len = vsnprintf(stupid_buf, sizeof(stupid_buf), fmt, ap);
    va_end(ap);

    stupid_buf[len++] = '\r';
    stupid_buf[len++] = '\n';
    stupid_buf[len] = '\0';

    sock_write(sock, stupid_buf);
    printf("\033[32m%s\033[0m", stupid_buf);
    return len;
}

static int start_tls(SSL_CTX *ctx, struct sock *sock)
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

static int authenticate(struct sock *sock, const char *user, size_t user_size,
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

int main(int argc, char *argv[])
{
    SSL_CTX *context = SSL_CTX_new(TLSv1_method());
    SSL_CTX_set_options(context, 0);
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, 0);

    struct sock sock;
    if (sock_connect(&sock, HOST, "submission") < 0) {
        fprintf(stderr, "Fuck, it didn't work\n");
        fflush(stderr);
        return 1;
    }
    sock_read(&sock);

    start_tls(context, &sock);
    sock_sendmsg(&sock, "EHLO %s", USER);
    sock_read(&sock);

    authenticate(&sock, USER, strlen(USER), PASSWORD, strlen(PASSWORD));

    sock_sendmsg(&sock,
		 "MAIL FROM: <%s>\r\n"
		 "RCPT TO: <%s>\r\n"
		 "DATA",
		 MAIL_FROM, RCPT_TO);
    sock_read(&sock);

    sock_sendmsg(&sock,
		 "From: <%s>\r\n"
		 "To: <%s>\r\n"
		 "Subject: Test message!\r\n"
		 "This is a test message\r\n"
		 ".",
		 MAIL_FROM, RCPT_TO);
    sock_read(&sock);

    sock_close(&sock);
    SSL_CTX_free(context);
}
