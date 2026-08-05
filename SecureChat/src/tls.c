/*
 * tls.c — SecureChat, configurazione OpenSSL
 *
 * Crea i contesti SSL lato server e lato client. Non contiene alcuna
 * logica di rete: l'handshake vero e proprio (SSL_accept()/SSL_connect())
 * resta nei main loop, perche' e' li' che si decide come intrecciarlo
 * con select()/epoll() (in questo progetto: in modo bloccante, subito
 * dopo accept()/connect(), prima di aggiungere il client al set
 * monitorato — si veda la relazione per la discussione del trade-off).
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls.h"

/* Controlla che il file esista e sia leggibile PRIMA di passarlo a
 * OpenSSL: se manca, il messaggio d'errore di OpenSSL da solo ("system
 * lib: No such file or directory") non dice nulla su una causa molto
 * comune in pratica: TLS_CERT_FILE/TLS_KEY_FILE sono percorsi relativi
 * (si veda chat.h), quindi si risolvono rispetto alla directory da cui
 * si lancia il programma, non rispetto a dove si trova l'eseguibile.
 * Lanciare "./chat_epoll" da dentro bin/ invece che dalla root del
 * progetto e' l'errore piu' frequente. */
static void check_file_or_die(const char *path, const char *what)
{
    if (access(path, R_OK) != 0) {
        fprintf(stderr,
            "[tls] %s '%s' non trovato o non leggibile.\n"
            "      Il percorso e' relativo alla directory da cui lanci\n"
            "      il programma: se hai fatto 'cd bin' prima di eseguirlo,\n"
            "      esegui invece dalla root del progetto (./bin/... invece\n"
            "      che ./...). Se il certificato non esiste ancora, genera\n"
            "      la coppia certificato/chiave con 'make cert'.\n",
            what, path);
        exit(1);
    }
}

SSL_CTX *tls_server_context(const char *cert_path, const char *key_path)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* Impone TLS 1.2 come versione minima: evita di negoziare per
     * errore protocolli obsoleti e insicuri (SSLv3, TLS 1.0/1.1). */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    /* In TLS 1.3 il server invia di default, subito dopo l'handshake e
     * senza che nessuno lo richieda, due messaggi NewSessionTicket (per
     * la ripresa di sessione). Un client che chiama SSL_read() una sola
     * volta per evento di select() li assorbe correttamente all'interno
     * di quell'unica chiamata (OpenSSL li processa in modo trasparente,
     * senza restituirli come dati applicativi) — ma se, dopo averli
     * consumati, non c'e' ancora nulla d'altro da leggere, quella stessa
     * chiamata resta bloccata in attesa di byte che non arriveranno
     * finche' non e' il client stesso a scrivere per primo: un vero e
     * proprio stallo, scoperto proprio testando due client in TLS 1.3.
     * Non essendo questo progetto interessato alla ripresa di sessione,
     * la soluzione piu' pulita e' non inviare affatto i ticket. */
    SSL_CTX_set_num_tickets(ctx, 0);

    check_file_or_die(cert_path, "certificato");

    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[tls] impossibile caricare il certificato '%s'\n",
                cert_path);
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    check_file_or_die(key_path, "chiave privata");

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[tls] impossibile caricare la chiave privata '%s'\n",
                key_path);
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr,
                "[tls] certificato e chiave privata non corrispondono\n");
        exit(1);
    }

    return ctx;
}

SSL_CTX *tls_client_context(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    /* SSL_VERIFY_NONE disabilita la verifica del certificato del server:
     * senza una CA che lo abbia firmato, un certificato autofirmato
     * generato localmente (vedi 'make cert') non supererebbe altrimenti
     * la verifica. Va bene per una demo in locale, ma espone a
     * man-in-the-middle in un contesto reale: in produzione si
     * caricherebbe la CA con SSL_CTX_load_verify_locations() e si
     * userebbe SSL_VERIFY_PEER, lasciando che sia OpenSSL a rifiutare
     * connessioni verso un server con identita' non verificabile. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}
