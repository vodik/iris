#include <stdio.h>
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

#include "socket.h"
#include "imap.h"
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

static int imap_demo(int uid)
{
    SSL_CTX *context = SSL_CTX_new(TLSv1_method());
    SSL_CTX_set_options(context, 0);
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, 0);

    struct imap imap = {0};
    imap_connect(&imap, HOST, "imaps", context);

    imap_sendmsg(&imap, "LOGIN %s %s", USER, PASSWORD);
    imap_getmsg(&imap, 0);

    imap_sendmsg(&imap, "LIST \"\" \"*\"");
    imap_getmsg(&imap, 0);

    imap_sendmsg(&imap, "SELECT INBOX");
    imap_getmsg(&imap, 0);

    imap_sendmsg(&imap, "FETCH %d BODY[]", uid);
    imap_getmsg(&imap, 0);

    imap_sendmsg(&imap, "LOGOUT");
    imap_getmsg(&imap, 0);

    return 0;
}

int main(int argc, const char *argv[])
{
    if (argc < 2) {
        return 1;
    } else if (strcmp(argv[1], "submission") == 0) {
        return smtp_demo();
    } else if (strcmp(argv[1], "imap") == 0) {
        const int uid = atoi(argv[2]);  // FIXME: Undefined behaviour
        return imap_demo(uid);
    }
}
