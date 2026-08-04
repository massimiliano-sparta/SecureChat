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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls.h"

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

    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[tls] impossibile caricare il certificato '%s'\n",
                cert_path);
        ERR_print_errors_fp(stderr);
        exit(1);
    }

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
