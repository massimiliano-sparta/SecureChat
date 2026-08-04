/*
 * chat_client.c — SecureChat, client interattivo
 *
 * Client TCP minimale per SecureChat: multiplexa con select() la
 * tastiera (STDIN_FILENO) e la socket verso il server, cosi' si puo'
 * scrivere un messaggio e ricevere quelli altrui senza bloccarsi
 * sull'uno o sull'altro.
 *
 * La connessione e' cifrata con TLS: subito dopo la connect() TCP si
 * esegue un handshake SSL_connect() bloccante (il socket e' comunque
 * bloccante per tutto il resto del programma, quindi non introduce
 * alcuna asimmetria rispetto al comportamento gia' esistente), poi il
 * ciclo select() procede come prima, con SSL_read()/SSL_write() al
 * posto di recv()/send().
 *
 * Ogni riga digitata viene inviata COMPLETA di '\n' finale: il server
 * la riconosce come messaggio concluso solo grazie a quel carattere
 * (si veda feed_bytes() in registry.c). Se il client non lo mandasse,
 * il messaggio resterebbe in sospeso nel buffer del server in attesa
 * di un futuro '\n'.
 *
 * Nota implementativa: la lettura da stdin NON usa fgets(). fgets()
 * bufferizza a livello di libreria C: se arrivano piu' righe insieme
 * in una singola read() sottostante (es. incollando/piping piu'
 * comandi di fila, come "/nick x" e "/join y" senza pausa), fgets() le
 * legge tutte ma ne restituisce una sola per chiamata. select(), pero',
 * ragiona sul file descriptor a livello di kernel: una volta che i
 * byte sono gia' stati "risucchiati" nel buffer interno di fgets(),
 * select() non segnala piu' STDIN come pronto finche' non arrivano
 * byte NUOVI, anche se una riga intera e' gia' li' in attesa. Risultato
 * pratico: la seconda riga resta bloccata fino al prossimo evento (o
 * alla EOF), invece di essere inviata subito. Per evitarlo si applica
 * qui lo stesso approccio usato dal server in feed_bytes(): read()
 * grezza su STDIN_FILENO e framing a riga fatto a mano.
 *
 * Compilazione: vedi Makefile (make chat_client)
 * Esecuzione:   ./chat_client [ip] [porta]
 *               (default: 127.0.0.1 e la porta definita in chat.h)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "chat.h"
#include "tls.h"

int main(int argc, char *argv[])
{
    const char *ip   = (argc > 1) ? argv[1] : "127.0.0.1";
    int         port = (argc > 2) ? atoi(argv[2]) : PORT;

    signal(SIGPIPE, SIG_IGN);

    /* Su terminale stdout e' gia' line-buffered di default, ma se
     * l'output viene rediretto o messo in pipe la libc passa a
     * fully-buffered: i messaggi resterebbero fermi nel buffer finche'
     * non si riempie o il programma non esce. Per un client interattivo
     * vogliamo vedere ogni riga subito, quindi lo forziamo esplicitamente. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) { perror("socket"); exit(1); }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
    };
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "indirizzo IP non valido: %s\n", ip);
        close(sock_fd);
        exit(1);
    }

    if (connect(sock_fd, (struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock_fd);
        exit(1);
    }

    SSL_CTX *ctx = tls_client_context();
    SSL     *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock_fd);

    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "handshake TLS fallito\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock_fd);
        exit(1);
    }

    printf("Connesso (TLS, %s) a SecureChat su %s:%d\n",
           SSL_get_version(ssl), ip, port);
    printf("Comandi: /nick <nome>   /join <stanza>   Ctrl-D per uscire\n");

    fd_set master_set;
    FD_ZERO(&master_set);
    FD_SET(STDIN_FILENO, &master_set);
    FD_SET(sock_fd, &master_set);
    int max_fd = (sock_fd > STDIN_FILENO) ? sock_fd : STDIN_FILENO;

    int stdin_open = 1;

    /* Buffer di accumulo per il framing manuale a riga sullo stdin,
     * stesso principio di inbuf/inlen in ClientInfo (chat.h). */
    char   in_acc[BUFLEN];
    size_t in_len = 0;

    while (1) {
        fd_set read_fds = master_set; /* select() la modifica: va ricopiata */

        int n = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        if (stdin_open && FD_ISSET(STDIN_FILENO, &read_fds)) {
            char chunk[BUFLEN];
            ssize_t r = read(STDIN_FILENO, chunk, sizeof(chunk));

            if (r < 0) {
                if (errno == EINTR) continue;
                perror("read");
                break;
            }

            if (r == 0) {
                /* EOF su stdin (es. Ctrl-D): da qui in poi select()
                 * segnalerebbe STDIN_FILENO pronto ad ogni ciclo (la
                 * condizione di EOF e' persistente), quindi lo togliamo
                 * dal master_set invece di ricontrollarlo. Chiudiamo
                 * solo il lato in scrittura della socket e restiamo in
                 * ascolto: cosi' non perdiamo eventuali risposte del
                 * server gia' in transito (es. l'ack a un /join appena
                 * inviato). Il client termina quando e' il server a
                 * chiudere la connessione. */
                FD_CLR(STDIN_FILENO, &master_set);
                stdin_open = 0;
                shutdown(sock_fd, SHUT_WR);
                continue;
            }

            /* Accoda i byte appena letti e invia al server ogni riga
             * completa ('\n'-terminata) trovata; un eventuale residuo
             * senza '\n' resta in in_acc in attesa dei prossimi byte. */
            for (ssize_t i = 0; i < r; i++) {
                if (in_len < sizeof(in_acc)) in_acc[in_len++] = chunk[i];

                if (chunk[i] == '\n') {
                    if (SSL_write(ssl, in_acc, in_len) < 0) {
                        fprintf(stderr, "errore di scrittura sulla connessione TLS\n");
                        in_len = 0;
                        goto fine;
                    }
                    in_len = 0;
                } else if (in_len == sizeof(in_acc)) {
                    /* riga troppo lunga per il buffer: la scarto invece
                     * di andare in overflow, in attesa del prossimo '\n' */
                    in_len = 0;
                }
            }
        }

        if (FD_ISSET(sock_fd, &read_fds)) {
            char buf[BUFLEN];
            int r = SSL_read(ssl, buf, sizeof(buf) - 1);

            if (r <= 0) {
                printf("Server disconnesso.\n");
                break;
            }

            buf[r] = '\0';
            printf(">> %s", buf);
            if (buf[r - 1] != '\n') printf("\n");

            /* Come lato server: eventuali record TLS ulteriori gia'
             * decifrati da OpenSSL in questa lettura non farebbero
             * scattare select() una seconda volta, quindi si continua
             * a svuotare finche' SSL_pending() promette dati pronti. */
            while (SSL_pending(ssl) > 0) {
                r = SSL_read(ssl, buf, sizeof(buf) - 1);
                if (r <= 0) { printf("Server disconnesso.\n"); goto fine; }
                buf[r] = '\0';
                printf(">> %s", buf);
                if (buf[r - 1] != '\n') printf("\n");
            }
        }
    }

fine:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock_fd);
    return 0;
}
