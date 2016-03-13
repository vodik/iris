#include <stdio.h>
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

#include "socket.h"
#include "smtp.h"
#include "config.h"

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

    smtp_start_tls(&sock, context);
    smtp_ehlo(&sock, USER);
    smtp_auth_plain(&sock, USER, strlen(USER), PASSWORD, strlen(PASSWORD));

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
