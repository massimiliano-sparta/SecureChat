#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netinet/in.h>
 
#define MCAST_GROUP "239.1.2.3"
#define MCAST_PORT   5000
#define BUFLEN       1024
 
/* Variabile globale per il cleanup sul segnale SIGINT */
static int sockfd_global = -1;
static struct ip_mreq mreq_global;
 
static void sigint_handler(int sig){
    (void)sig;
    printf("\nUscita dal gruppo e chiusura...\n");
 
    /* IP_DROP_MEMBERSHIP: il kernel manda un IGMP Leave al router */
    setsockopt(sockfd_global, IPPROTO_IP, IP_DROP_MEMBERSHIP,
               &mreq_global, sizeof(mreq_global));
    close(sockfd_global);
    exit(0);
}
 
int main(void){
    /* 1. Crea socket UDP */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }
    sockfd_global = sockfd;
    int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
                   &yes, sizeof(yes)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(sockfd);
        return 1;
    }
 
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
 
    /* Installa il gestore per Ctrl+C: uscita pulita dal gruppo */
    signal(SIGINT, sigint_handler);
 
    printf("Iscritto al gruppo %s porta %d\n", MCAST_GROUP, MCAST_PORT);
    printf("In ascolto... (Ctrl+C per uscire)\n\n");
 
    /* 5. Loop di ricezione, con una sendto() di prova prima
          della recvfrom() per verificare il loopback locale.
          local ha gia' l'IP e la porta del gruppo, quindi puo'
          essere riusata anche come indirizzo di destinazione. */
    char buf[BUFLEN];
    struct sockaddr_in sender;
    socklen_t senderlen = sizeof(sender);
 
    while (1) {
        const char *test_msg = "ping";
        sendto(sockfd, test_msg, strlen(test_msg), 0,
               (struct sockaddr *)&local, sizeof(local));
 
        ssize_t n = recvfrom(sockfd, buf, sizeof(buf) - 1, 0,
                             (struct sockaddr *)&sender, &senderlen);
        if (n < 0) {
            perror("recvfrom");
            break;
        }
        buf[n] = '\0';
 
        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender.sin_addr, sender_ip, sizeof(sender_ip));
 
        printf("[%s:%d] %s\n",
               sender_ip,
               ntohs(sender.sin_port),
               buf);
    }
 
    /* Cleanup (raggiunto solo in caso di errore su recvfrom) */
    setsockopt(sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
               &mreq, sizeof(mreq));
    close(sockfd);
    return 0;
}
