#include "socket.h"
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

static int smtp_raw_socket(const char *hostname, const char *service)
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

int smtp_connect(const char *hostname, const char *service, struct sock *sock)
{
    int socket = smtp_raw_socket(hostname, service);
    if (socket < 0) {
        perror("socket");
	return -1;
    }

    *sock = (struct sock){.fd = socket, .ssl = NULL, .use_ssl = 0};
    sock_read(sock);
    return 0;
}

void sock_read(struct sock *sock)
{
    char buf[BUFSIZ];
    ssize_t nbytes_r;

    if (sock->use_ssl)
         nbytes_r = SSL_read(sock->ssl, buf, sizeof(buf));
    else
         nbytes_r = read(sock->fd, buf, sizeof(buf));

    printf("%.*s\r\n", (int)nbytes_r - 1, buf);
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

void socket_perror(struct sock *sock, int ret)
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
