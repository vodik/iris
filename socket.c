#include "socket.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


static void __attribute__((constructor)) init_openssl(void)
{
    SSL_library_init();
    SSL_load_error_strings();
}

static int sock_getaddrinfo(const char *hostname, const char *service)
{
    struct addrinfo *result, *iter;
    const struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE
    };

    int error = getaddrinfo(hostname, service, &hints, &result);
    if (error != 0) {
        if (error == EAI_SYSTEM) {
            perror("getaddrinfo");
        } else {
            fprintf(stderr, "error in getaddrinfo: %s\r\n", gai_strerror(error));
        }
        exit(EXIT_FAILURE);
    }

    int sock = -1;
    for (iter = result; iter != NULL; iter = iter->ai_next) {
        sock = socket(iter->ai_family, iter->ai_socktype, iter->ai_protocol);
        if (sock < 0)
            continue;

        if (connect(sock, iter->ai_addr, iter->ai_addrlen) == -1) {
            close(sock);
            continue;
        }

        break;
    }

    freeaddrinfo(result);
    return iter == NULL ? -1 : sock;
}

int sock_starttls(struct sock *sock, SSL_CTX *ctx)
{
    sock->ssl = SSL_new(ctx);
    SSL_set_fd(sock->ssl, sock->fd);

    int ret = SSL_connect(sock->ssl);
    if (ret <= 0)
        sock_err(sock, ret);

    sock->use_ssl = 1;
    return 0;
}

int sock_connect(struct sock *sock, const char *hostname, const char *service)
{
    int fd = sock_getaddrinfo(hostname, service);
    if (fd < 0) {
        perror("fd");
        return -1;
    }

    *sock = (struct sock){.fd = fd, .ssl = NULL, .use_ssl = 0};
    return 0;
}

ssize_t sock_read(struct sock *sock, char *buf, size_t bufsize)
{
    ssize_t nbytes_r;
    if (sock->use_ssl)
        nbytes_r = SSL_read(sock->ssl, buf, bufsize);
    else
        nbytes_r = read(sock->fd, buf, bufsize);

    if (nbytes_r >= 0)
	buf[nbytes_r] = 0;
    return nbytes_r;
}

void sock_dump(struct sock *sock)
{
    char buf[BUFSIZ];
    sock_read(sock, buf, sizeof(buf));
}

int sock_write(struct sock *sock, const char *msg)
{
    size_t len = strlen(msg);
    if (sock->use_ssl)
        return SSL_write(sock->ssl, msg, len);
    else
        return write(sock->fd, msg, len);
}

int sock_close(struct sock *sock)
{
    close(sock->fd);
    if (sock->use_ssl)
        SSL_free(sock->ssl);
    return 0;
}

void sock_err(struct sock *sock, int ret)
{
    if (sock->use_ssl) {
	int err = SSL_get_error(sock->ssl, ret);
	switch (err) {
	case SSL_ERROR_SYSCALL:
	case SSL_ERROR_SSL:
	    err = ERR_get_error();
	    if (err == 0) {
            if (ret == 0)
                printf("SSL: got EOF\r\n");
            else
                printf("SSL: %d: %s\r\n", errno, strerror(errno));
	    } else
            printf("SSL: %d: %s\r\n", err, ERR_error_string(err, 0));
	    break;
	default:
	    printf("SSL: %d: unhandled SSL error\r\n", err);
	    break;
	}
    } else {
        if (ret < 0)
            perror("shit");
        else
            printf("unexpeted EOF\r\n");
    }

    exit(ret);
}

int sock_vsendmsg(struct sock *sock, const char *fmt, va_list ap)
{
    char stupid_buf[4089];

    size_t len = vsnprintf(stupid_buf, sizeof(stupid_buf), fmt, ap);

    stupid_buf[len++] = '\r';
    stupid_buf[len++] = '\n';
    stupid_buf[len] = '\0';

    sock_write(sock, stupid_buf);
    printf("\033[32m%s\033[0m", stupid_buf);
    return len;
}

int sock_sendmsg(struct sock *sock, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    int ret = sock_vsendmsg(sock, fmt, ap);
    va_end(ap);
    return ret;
}
