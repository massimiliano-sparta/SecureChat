#ifndef CHAT_H
#define CHAT_H

#include <stddef.h>
#include <openssl/ssl.h>

#define PORT        8080
#define MAX_CLIENTS 64
#define BUFLEN      1024   /* buffer di lettura per singola recv()/SSL_read() */
#define MAX_NAME    32
#define MAX_ROOM    32
#define MAX_LINE    1024   /* buffer di accumulo per il framing a riga */
#define DEFAULT_ROOM "main"

#define TLS_CERT_FILE "server.crt"
#define TLS_KEY_FILE  "server.key"

/*
 * Un client TCP e' un flusso di byte, non di messaggi: una singola
 * recv() puo' restituire mezzo messaggio, un messaggio e mezzo, o
 * dieci messaggi insieme. Per questo ogni client ha un proprio
 * buffer di accumulo (inbuf/inlen): i byte vengono accodati finche'
 * non si trova un '\n', che segna la fine di un messaggio applicativo.
 *
 * Il campo ssl e' la sessione TLS associata al file descriptor fd:
 * ogni lettura/scrittura verso il client passa da SSL_read()/SSL_write()
 * invece che da recv()/send() direttamente sul socket.
 */
typedef struct {
    int    fd;
    SSL   *ssl;
    char   nickname[MAX_NAME];
    char   room[MAX_ROOM];
    int    active;
    char   inbuf[MAX_LINE];
    size_t inlen;
} ClientInfo;

extern ClientInfo clients[MAX_CLIENTS];

/* Gestione della rubrica client, indicizzata per fd */
void         registry_init(void);
int          registry_add(int fd, SSL *ssl);
void         registry_remove(int fd);
ClientInfo  *registry_find(int fd);

/* Logica applicativa: identica per la versione select() ed epoll() */
void handle_line(ClientInfo *c, char *line);
void feed_bytes(ClientInfo *c, const char *data, size_t n);
void broadcast_line(ClientInfo *sender, const char *line);

#endif /* CHAT_H */
