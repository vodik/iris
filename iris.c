#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

#include "socket.h"
#include "base64.h"
#include "config.h"

static int start_tls(SSL_CTX *ctx, struct sock *sock)
{
    sock_write(sock, "STARTTLS\r\n");
    sock_read(sock);

    sock->ssl = SSL_new(ctx);
    SSL_set_fd(sock->ssl, sock->fd);

    int ret = SSL_connect(sock->ssl);
    if (ret <= 0)
        socket_perror(sock, ret);

    sock->use_ssl = 1;
    return 0;
}

static int authenticate(struct sock *sock)
{
    /* TODO: temp hack */
    const size_t user_size = sizeof(USER) - 1;
    const size_t password_size = sizeof(PASSWORD) - 1;
    const size_t total_size = user_size + password_size + 2;

    unsigned char buf[total_size + 1], *p = buf;

    p[0] = '\0';
    p = mempcpy(p + 1, USER, user_size);

    p[0] = '\0';
    p = mempcpy(p + 1, PASSWORD, password_size);

    char *encoded = base64_encode(buf, total_size, NULL);
    if (!encoded)
	exit(1);

    sock_write(sock, "AUTH PLAIN ");
    sock_write(sock, encoded);
    sock_write(sock, "\r\n");
    free(encoded);

    sock_read(sock);
    return 0;
}

int main(int argc, char *argv[])
{
    struct sock sock;
    if (smtp_connect(HOST, "submission", &sock) < 0) {
        fprintf(stderr, "Fuck, it didn't work\n");
        fflush(stderr);
        return 1;
    }

    sock_write(&sock, "EHLO " USER "\r\n");
    sock_read(&sock);

    SSL_CTX *context = SSL_CTX_new(TLSv1_method());
    SSL_CTX_set_options(context, 0);
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, 0);
    start_tls(context, &sock);

    sock_write(&sock, "EHLO " USER "\r\n");
    sock_read(&sock);

    authenticate(&sock);

    sock_write(&sock, "MAIL FROM: <" MAIL_FROM ">\r\n");
    sock_read(&sock);

    sock_write(&sock, "RCPT TO: <" RCPT_TO ">\r\n");
    sock_read(&sock);

    sock_write(&sock, "DATA\r\n");
    sock_read(&sock);

    sock_write(&sock,
    	 "From: <" MAIL_FROM ">\r\n"
    	 "To: <" RCPT_TO ">\r\n"
    	 "Subject: Test message!\r\n"
    	 "This is a test message\r\n"
    	 ".\r\n");
    sock_read(&sock);

    sock_close(&sock);
    SSL_CTX_free(context);
}
