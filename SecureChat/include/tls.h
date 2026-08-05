#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>

/*
 * Incapsula la parte "amministrativa" di OpenSSL (creazione contesto,
 * caricamento certificato/chiave, opzioni di sicurezza) separata dalla
 * logica applicativa, sullo stesso principio con cui registry.c isola
 * la logica di chat dal meccanismo di multiplexing: main_select.c e
 * main_epoll.c usano queste funzioni senza doversi occupare dei
 * dettagli di configurazione di OpenSSL.
 */

/* Crea il contesto SSL lato server, caricando certificato e chiave
 * privata da file PEM. Termina il processo in caso di errore: senza un
 * contesto valido il server non ha alcun motivo di continuare. */
SSL_CTX *tls_server_context(const char *cert_path, const char *key_path);

/* Crea il contesto SSL lato client. Per una demo con certificato
 * autofirmato la verifica del certificato del server e' disabilitata
 * (si veda il commento in tls.c): adatto a un progetto didattico in
 * rete locale, non a un utilizzo in produzione. */
SSL_CTX *tls_client_context(void);

#endif /* TLS_H */
