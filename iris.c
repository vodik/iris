#include <stdio.h>
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

#include "socket.h"
#include "smtp.h"
#include "config.h"

static int smtp_demo(void)
{
    SSL_CTX *context = SSL_CTX_new(TLSv1_method());
    SSL_CTX_set_options(context, 0);
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, 0);

    struct sock sock;
    if (smtp_connect(&sock, HOST, "submission", context) != SMTP_OK) {
	fprintf(stderr, "Failed to connect\n");
	return 1;
    }

    if (smtp_auth_plain(&sock, USER, strlen(USER), PASSWORD, strlen(PASSWORD)) != SMTP_OK) {
	fprintf(stderr, "Failed to authenticate\n");
	return 1;
    }

    smtp_sendmsg(&sock, 3,
		 "MAIL FROM: <%s>\r\n"
		 "RCPT TO: <%s>\r\n"
		 "DATA",
		 MAIL_FROM, RCPT_TO);

    smtp_sendmsg(&sock, 1,
		 "From: <%s>\r\n"
		 "To: <%s>\r\n"
		 "Subject: Test message!\r\n"
		 "This is a test message\r\n"
		 ".",
		 MAIL_FROM, RCPT_TO);

    sock_close(&sock);
    SSL_CTX_free(context);
    return 0;
}

static int imap_demo(void)
{
    struct sock sock;

    SSL_CTX *context = SSL_CTX_new(TLSv1_method());
    SSL_CTX_set_options(context, 0);
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, 0);

    sock_connect(&sock, HOST, "imaps");
    sock_starttls(&sock, context);

    char buf[BUFSIZ];
    sock_read(&sock, buf, sizeof(buf));
    printf("got: %s\n", buf);

    /* if (imap_connect(&sock, HOST, "imaps", context) != 0) { */
    /* 	fprintf(stderr, "Failed to connect\n"); */
    /* 	return 1; */
    /* } */

    return 0;
}

int main(int argc, const char *argv[])
{
    if (argc != 2) {
	return 1;
    } else if (strcmp(argv[1], "submission") == 0) {
	return smtp_demo();
    } else if (strcmp(argv[1], "imap") == 0) {
	return imap_demo();
    }
}
