/*
 * main_epoll.c — SecureChat, variante epoll()
 *
 * Stesso protocollo e stessa logica applicativa di main_select.c
 * (registry.c e' condiviso), ma il multiplexing usa epoll() invece
 * di select(): niente FD_ZERO/FD_SET ad ogni ciclo, niente max_fd
 * da ricalcolare, epoll_wait() ritorna solo i fd davvero pronti.
 *
 * Come in main_select.c, l'handshake TLS (SSL_accept()) e' bloccante
 * e avviene subito dopo accept(), prima della epoll_ctl(ADD): stesso
 * trade-off, stessa motivazione (si veda main_select.c e la relazione).
 *
 * Compilazione: vedi Makefile (make chat_epoll)
 * Esecuzione:   ./chat_epoll   (richiede server.crt/server.key: make cert)
 * Test:         ./chat_client   (oppure openssl s_client -connect 127.0.0.1:8080)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "chat.h"
#include "tls.h"

#define MAX_EVENTS 64

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    registry_init();

    SSL_CTX *ctx = tls_server_context(TLS_CERT_FILE, TLS_KEY_FILE);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(1); }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }
    if (listen(server_fd, 16) < 0) { perror("listen"); exit(1); }

    int epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); exit(1); }

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = server_fd };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, server_fd, &ev) < 0) {
        perror("epoll_ctl ADD server_fd"); exit(1);
    }

    printf("=== SecureChat (epoll) su porta %d ===\n", PORT);

    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait"); break;
        }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == server_fd) {
                struct sockaddr_in caddr;
                socklen_t clen = sizeof(caddr);
                int client_fd = accept(server_fd, (struct sockaddr *)&caddr, &clen);
                if (client_fd < 0) { perror("accept"); continue; }

                if (client_fd >= MAX_CLIENTS) {
                    fprintf(stderr, "[!] troppi client, rifiuto fd=%d\n", client_fd);
                    close(client_fd);
                    continue;
                }

                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &caddr.sin_addr, ip, sizeof(ip));

                /* Handshake TLS bloccante, come in main_select.c: prima
                 * di questo punto client_fd non e' ancora nel set epoll,
                 * quindi non interferisce con epoll_wait(). */
                SSL *ssl = SSL_new(ctx);
                SSL_set_fd(ssl, client_fd);

                if (SSL_accept(ssl) <= 0) {
                    fprintf(stderr, "[!] handshake TLS fallito con %s:%d\n",
                            ip, ntohs(caddr.sin_port));
                    ERR_print_errors_fp(stderr);
                    SSL_free(ssl);
                    close(client_fd);
                    continue;
                }

                registry_add(client_fd, ssl);
                struct epoll_event cev = { .events = EPOLLIN, .data.fd = client_fd };
                if (epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &cev) < 0) {
                    perror("epoll_ctl ADD client");
                    registry_remove(client_fd);
                    close(client_fd);
                    continue;
                }

                printf("[+] client fd=%d connesso (TLS) da %s:%d\n",
                       client_fd, ip, ntohs(caddr.sin_port));
                continue;
            }

            ClientInfo *c = registry_find(fd);
            if (!c) continue;

            if (events[i].events & (EPOLLHUP | EPOLLERR)) {
                printf("[!] errore/hangup fd=%d\n", fd);
                epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
                registry_remove(fd);
                close(fd);
                continue;
            }

            char buf[BUFLEN];
            int r = SSL_read(c->ssl, buf, sizeof(buf));

            if (r <= 0) {
                printf("[-] client fd=%d disconnesso\n", fd);
                registry_remove(fd);
                epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
                close(fd);
                continue;
            }

            feed_bytes(c, buf, (size_t)r);

            /* Come in main_select.c: OpenSSL puo' aver gia' decifrato
             * piu' di un record TLS in questa singola lettura di
             * sistema. epoll_wait(), a livello di kernel, non
             * segnalerebbe di nuovo il fd finche' non arrivano byte
             * nuovi, quindi si continua a svuotare finche'
             * SSL_pending() promette dati gia' pronti. */
            while (SSL_pending(c->ssl) > 0) {
                r = SSL_read(c->ssl, buf, sizeof(buf));
                if (r <= 0) break;
                feed_bytes(c, buf, (size_t)r);
            }
        }
    }

    close(epfd);
    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}
