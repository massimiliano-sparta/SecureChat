#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/select.h>
 
#define MCAST_GROUP "239.1.2.3"
#define MCAST_PORT   5000
#define BUFLEN       1024
#define USERLEN      32

static int sockfd_global = -1;
static struct ip_mreq mreq_global;
 
static void sigint_handler(int sig)
{
    (void)sig;
    printf("\nUscita dal gruppo e chiusura...\n");
    setsockopt(sockfd_global, IPPROTO_IP, IP_DROP_MEMBERSHIP,
               &mreq_global, sizeof(mreq_global));
    close(sockfd_global);
    exit(0);
}
 
int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <nome utente>\n", argv[0]);
        return 1;
    }
    const char *username = argv[1];
 
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }
    sockfd_global = sockfd;
 
    int yes = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
 
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port   = htons(MCAST_PORT);
    inet_pton(AF_INET, MCAST_GROUP, &local.sin_addr);
 
    if (bind(sockfd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }
 
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    inet_pton(AF_INET, MCAST_GROUP, &mreq.imr_multiaddr);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    mreq_global = mreq;
 
    if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt IP_ADD_MEMBERSHIP");
        close(sockfd);
        return 1;
    }
 
    int ttl = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
 
    signal(SIGINT, sigint_handler);
 
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(MCAST_PORT);
    inet_pton(AF_INET, MCAST_GROUP, &dest.sin_addr);
 
    printf("Iscritto al gruppo %s porta %d come \"%s\"\n",
           MCAST_GROUP, MCAST_PORT, username);
    printf("Scrivi un messaggio e premi Invio per inviarlo (Ctrl+C per uscire)\n\n");
 
    char buf[BUFLEN];
    char out[BUFLEN + 128];
    struct sockaddr_in sender;
    socklen_t senderlen = sizeof(sender);
 
    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sockfd, &readfds);
 
        int maxfd = sockfd > STDIN_FILENO ? sockfd : STDIN_FILENO;
        if (select(maxfd + 1, &readfds, NULL, NULL, NULL) < 0) {
            perror("select");
            break;
        }
 
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (fgets(buf, sizeof(buf), stdin) == NULL) break;
            buf[strcspn(buf, "\n")] = '\0';
 
            if (strlen(buf) > 0) {
                snprintf(out, sizeof(out), "[%s] %s", username, buf);
                sendto(sockfd, out, strlen(out), 0,
                       (struct sockaddr *)&dest, sizeof(dest));
            }
        }
 
        if (FD_ISSET(sockfd, &readfds)) {
            ssize_t n = recvfrom(sockfd, buf, sizeof(buf) - 1, 0,
                                  (struct sockaddr *)&sender, &senderlen);
            if (n < 0) { perror("recvfrom"); break; }
            buf[n] = '\0';
 
            /* Filtra l'eco del proprio nome: il messaggio arriva
               comunque dal kernel (loopback attivo), ma non viene
               stampato se il mittente coincide con il proprio
               username */
            size_t namelen = strlen(username);
            if (n > (ssize_t)(namelen + 2) &&
                buf[0] == '[' &&
                strncmp(buf + 1, username, namelen) == 0 &&
                buf[1 + namelen] == ']') {
                continue;
            }
 
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sender.sin_addr, ip, sizeof(ip));
            printf("[%s] %s\n", ip, buf);
        }
    }
 
    setsockopt(sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
    close(sockfd);
    return 0;
 }
