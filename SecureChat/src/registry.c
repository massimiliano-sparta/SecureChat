#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include "chat.h"

ClientInfo clients[MAX_CLIENTS];

void registry_init(void)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].fd     = -1;
        clients[i].ssl    = NULL;
        clients[i].active = 0;
        clients[i].inlen  = 0;
    }
}

int registry_add(int fd, SSL *ssl)
{
    if (fd < 0 || fd >= MAX_CLIENTS) return -1;
    ClientInfo *c = &clients[fd];
    c->fd     = fd;
    c->ssl    = ssl;   /* <-- INDISPENSABILE */
    c->active = 1;
    c->inlen  = 0;
    snprintf(c->nickname, MAX_NAME, "guest%d", fd);
    snprintf(c->room, MAX_ROOM, "%s", DEFAULT_ROOM);
    return 0;
}

void registry_remove(int fd)
{
    if (fd < 0 || fd >= MAX_CLIENTS) return;
    if (clients[fd].ssl) {
        SSL_shutdown(clients[fd].ssl);
        SSL_free(clients[fd].ssl);
    }
    clients[fd].fd     = -1;
    clients[fd].ssl    = NULL;
    clients[fd].active = 0;
    clients[fd].inlen  = 0;
}

ClientInfo *registry_find(int fd)
{
    if (fd < 0 || fd >= MAX_CLIENTS) return NULL;
    if (!clients[fd].active) return NULL;
    return &clients[fd];
}

void broadcast_line(ClientInfo *sender, const char *line)
{
    char out[MAX_LINE + MAX_NAME + 16];
    int n = snprintf(out, sizeof(out), "[%s][%s] %s\n",
                     sender->room, sender->nickname, line);
    if (n < 0 || n >= (int)sizeof(out)) return;

    for (int j = 0; j < MAX_CLIENTS; j++) {
        if (!clients[j].active) continue;
        if (clients[j].fd == sender->fd) continue;
        if (strcmp(clients[j].room, sender->room) != 0) continue;
        if (!clients[j].ssl) continue;

        SSL_write(clients[j].ssl, out, n);
    }
}

void handle_line(ClientInfo *c, char *line)
{
    if (!c || !c->ssl) return;

    if (strncmp(line, "/nick ", 6) == 0) {
        char *new_nick = line + 6;
        if (strlen(new_nick) == 0) return;
        strncpy(c->nickname, new_nick, MAX_NAME - 1);
        c->nickname[MAX_NAME - 1] = '\0';

        char notice[MAX_NAME + 64];
        int len = snprintf(notice, sizeof(notice),
                           "ora sei conosciuto come %s\n", c->nickname);
        if (len > 0) SSL_write(c->ssl, notice, len);
        return;
    }

    if (strncmp(line, "/join ", 6) == 0) {
        char *new_room = line + 6;
        if (strlen(new_room) == 0) return;
        strncpy(c->room, new_room, MAX_ROOM - 1);
        c->room[MAX_ROOM - 1] = '\0';

        char notice[MAX_ROOM + 64];
        int len = snprintf(notice, sizeof(notice),
                           "sei entrato nella stanza %s\n", c->room);
        if (len > 0) SSL_write(c->ssl, notice, len);
        return;
    }

    if (strlen(line) == 0) return;
    broadcast_line(c, line);
}

void feed_bytes(ClientInfo *c, const char *data, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char ch = data[i];
        if (ch == '\n') {
            c->inbuf[c->inlen] = '\0';
            if (c->inlen > 0 && c->inbuf[c->inlen - 1] == '\r')
                c->inbuf[c->inlen - 1] = '\0';
            handle_line(c, c->inbuf);
            c->inlen = 0;
            continue;
        }
        if (c->inlen < MAX_LINE - 1)
            c->inbuf[c->inlen++] = ch;
    }
}
