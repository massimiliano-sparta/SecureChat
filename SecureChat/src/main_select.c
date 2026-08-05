/*
 * main_select.c — SecureChat, variante select()
 *
 * Server TCP centrale, multiplexing con select(), singolo thread.
 * Nessun blocco su un singolo client per lo scambio applicativo:
 * select() ritorna solo quando almeno un fd (ascolto o client) ha dati
 * pronti.
 *
 * Il traffico e' cifrato con TLS (OpenSSL). L'handshake SSL_accept()
 * e' pero' BLOCCANTE e avviene subito dopo accept(), prima di
 * aggiungere il client al set monitorato: e' una scelta deliberata per
 * restare in un singolo thread senza dover scrivere una macchina a
 * stati per un handshake non bloccante. Il costo e' che, per la durata
 * di un handshake, il server non serve gli altri client gia' connessi
 * (si veda la discussione in relazione).
 *
 * Compilazione: vedi Makefile (make chat_select)
 * Esecuzione:   ./chat_select   (richiede server.crt/server.key: make cert)
 * Test:         ./chat_client   (oppure openssl s_client -connect 127.0.0.1:8080)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "chat.h"
#include "tls.h"

int main(void)
{
    /* SSL_write() non ha un equivalente di MSG_NOSIGNAL: senza questa
     * riga, scrivere verso un client appena disconnesso ucciderebbe
     * l'intero processo con SIGPIPE. */
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

    printf("=== SecureChat (select) su porta %d ===\n", PORT);

    fd_set master_set;
    FD_ZERO(&master_set);
    FD_SET(server_fd, &master_set);
    int max_fd = server_fd;

    while (1) {
        fd_set read_fds = master_set; /* select() la modifica: va ricopiata */

        int n = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("select"); break;
        }

        if (FD_ISSET(server_fd, &read_fds)) {
            struct sockaddr_in caddr;
            socklen_t clen = sizeof(caddr);
            int client_fd = accept(server_fd, (struct sockaddr *)&caddr, &clen);

            if (client_fd >= 0 && client_fd < MAX_CLIENTS) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &caddr.sin_addr, ip, sizeof(ip));

                /* Handshake TLS bloccante: fino a qui client_fd non e'
                 * ancora nel master_set, quindi non interferisce con
                 * select(); il resto del server resta pero' fermo per
                 * la durata dell'handshake (si veda il commento in
                 * testa al file). */
                SSL *ssl = SSL_new(ctx);
                SSL_set_fd(ssl, client_fd);

                if (SSL_accept(ssl) <= 0) {
                    fprintf(stderr, "[!] handshake TLS fallito con %s:%d\n",
                            ip, ntohs(caddr.sin_port));
                    ERR_print_errors_fp(stderr);
                    SSL_free(ssl);
                    close(client_fd);
                } else {
                    registry_add(client_fd, ssl);
                    FD_SET(client_fd, &master_set);
                    if (client_fd > max_fd) max_fd = client_fd;

                    printf("[+] client fd=%d connesso (TLS) da %s:%d\n",
                           client_fd, ip, ntohs(caddr.sin_port));
                }
            } else if (client_fd >= 0) {
                fprintf(stderr, "[!] troppi client, rifiuto fd=%d\n", client_fd);
                close(client_fd);
            }
        }

        for (int fd = 0; fd <= max_fd; fd++) {
            if (fd == server_fd) continue;
            if (!FD_ISSET(fd, &read_fds)) continue;

            ClientInfo *c = registry_find(fd);
            if (!c) continue;

            char buf[BUFLEN];
            int r = SSL_read(c->ssl, buf, sizeof(buf));

            if (r <= 0) {
                printf("[-] client fd=%d disconnesso\n", fd);
                registry_remove(fd);
                FD_CLR(fd, &master_set);
                close(fd);
                continue;
            }

            feed_bytes(c, buf, (size_t)r);

            /* OpenSSL puo' avere gia' decifrato piu' di un record TLS
             * nell'unica read() di sistema compiuta sopra: quei byte
             * restano nel buffer interno di OpenSSL, invisibili a
             * select(), che quindi non segnalerebbe di nuovo il fd
             * pronto finche' non arrivano byte NUOVI dal kernel --
             * esattamente lo stesso principio del disallineamento
             * fgets()/select() incontrato nel client (si veda
             * chat_client.c). Si continua a leggere finche'
             * SSL_pending() promette dati gia' disponibili, senza
             * tornare a select() nel frattempo. */
            while (SSL_pending(c->ssl) > 0) {
                r = SSL_read(c->ssl, buf, sizeof(buf));
                if (r <= 0) break;
                feed_bytes(c, buf, (size_t)r);
            }
        }
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}
