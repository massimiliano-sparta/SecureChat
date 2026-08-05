# SecureChat

SecureChat è un'applicazione di chat multiutente in C, con connessioni TCP concorrenti gestite **in un singolo thread** tramite `select()` o `epoll()`, e canale cifrato con **TLS** (OpenSSL).

Nato come progetto per il corso di Laboratorio di Reti e Sistemi Distribuiti Mod. B della Università degli Studi di Messina, poi esteso oltre i requisiti della consegna: due implementazioni equivalenti del multiplexing, un client dedicato, e la cifratura TLS del canale.

---

## Funzionalità

- Server di chat centralizzato multi-client su TCP, cifrato con TLS
- **Due implementazioni equivalenti** dello stesso protocollo applicativo:
  - I/O multiplexing con `select()`
  - I/O multiplexing con `epoll()`
- Client interattivo dedicato (`chat_client`), che multiplexa tastiera e socket senza bloccarsi sull'una o sull'altra
- Nickname personalizzati (`/nick`) e stanze virtuali indipendenti (`/join`), con broadcast filtrato per stanza
- Framing robusto dei messaggi a tre livelli — protocollo, client, TLS — su un flusso di byte che non garantisce confini tra messaggi
- Gestione sicura della disconnessione (nessun crash da `SIGPIPE`)

---

## Struttura del progetto

```
SecureChat/
│
├── include/
│   ├── chat.h            # struttura ClientInfo, costanti, prototipi
│   └── tls.h             # contesti SSL lato server/client
│
├── src/
│   ├── registry.c        # rubrica client, framing, comandi, broadcast (condiviso)
│   ├── main_select.c     # main loop del server basato su select()
│   ├── main_epoll.c      # main loop del server basato su epoll()
│   ├── chat_client.c     # client interattivo dedicato
│   └── tls.c             # configurazione OpenSSL (contesti, certificato)
│
├── build/                # file oggetto (.o), generati dalla compilazione
├── bin/                  # eseguibili finali, generati dalla compilazione
├── Makefile
└── README.md
```

`registry.c` contiene l'intera logica applicativa (nickname, stanze, framing, broadcast) ed è identico per entrambe le varianti del server: cambia solo il meccanismo con cui il server scopre quali socket sono pronte. `tls.c` isola allo stesso modo la parte "amministrativa" di OpenSSL (creazione del contesto, caricamento di certificato e chiave) dai main loop, che si limitano a invocarla. `build/` e `bin/` non vanno versionati: li ricrea `make` ad ogni compilazione.

---

## Compilazione

```
make
```

Crea automaticamente `build/` e `bin/`, e produce tre eseguibili in `bin/`:

```
bin/chat_select
bin/chat_epoll
bin/chat_client
```

Per ripulire tutto:

```
make clean
```

### Certificato TLS

Il server ha bisogno di un certificato e di una chiave privata. Generateli in locale (autofirmati, validi per i test):

```
make cert
```

Questo crea `server.crt` e `server.key` nella root del progetto. 
---

## Avvio del server

```
./bin/chat_select
```

oppure

```
./bin/chat_epoll
```

(equivalenti dal punto di vista funzionale). Output atteso:

```
=== SecureChat (select) su porta 8080 ===
```

⚠️ **Nota:** questo terminale è il *server*, non un client — non è un posto dove scrivere messaggi di chat. Serve un client vero (vedi sotto).

---

## Avvio dei client

```
./bin/chat_client
```

Indirizzo e porta del server sono opzionali (default: `127.0.0.1` e la porta 8080 definita in `chat.h`):

```
./bin/chat_client <ip> <porta>
```

Aprire un **nuovo** terminale per ciascun utente. Un client generico come `netcat` **non funziona** contro questo server: la connessione richiede un handshake TLS, e `netcat` parla solo TCP in chiaro (la connessione viene respinta subito, senza bloccare né mandare in crash il server).

---

## Comandi disponibili

### Cambio nickname

```
/nick alice
```

### Cambio stanza

```
/join calcio
```

Solo gli utenti nella stessa stanza ricevono i messaggi degli altri.

---

## Esempio di utilizzo

Terminale 1 (server):
```
./bin/chat_select
```

Terminale 2 (client "alice"):
```
./bin/chat_client
/nick alice
/join calcio
ciao a tutti!
```

Terminale 3 (client "bob"):
```
./bin/chat_client
/nick bob
/join calcio
```

Output su bob:
```
>> [calcio][alice] ciao a tutti!
```

Un client in una stanza diversa (es. `/join tennis`) non riceve nulla. Premendo Ctrl-D il client chiude in modo pulito la connessione, senza perdere eventuali risposte del server già in transito.

---

## Concetti affrontati

- Comunicazione client-server su socket TCP, cifrata con TLS (OpenSSL)
- Problema C10K e approcci architetturali alla concorrenza di rete
- I/O multiplexing con `select()` ed `epoll()` a confronto
- Framing dei messaggi su un flusso di byte non delimitato, in tre manifestazioni dello stesso principio:
  - lato server (`feed_bytes()`, su `recv()`/`SSL_read()`)
  - lato client (`fgets()` contro `select()`: un buffer di libreria invisibile al kernel)
  - dentro OpenSSL (`SSL_read()` contro `select()`: i messaggi `NewSessionTicket` di TLS 1.3 possono bloccare l'unica lettura per evento se non gestiti)
- Handshake TLS bloccante come scelta di design: semplicità in cambio di una breve pausa del server durante la connessione di un nuovo client
- Bilancio tra ciò che TLS garantisce in questa implementazione (riservatezza e integrità del canale) e ciò che non garantisce (autenticità del server, senza una CA reale; autenticazione degli utenti)
- Gestione dello stato condiviso senza mutex, restando in un singolo thread
- Organizzazione di un progetto C in directory separate (sorgenti, header, oggetti, eseguibili) tramite Makefile

---

## Limiti noti

- Il certificato è autofirmato e la verifica è disabilitata lato client (`SSL_VERIFY_NONE`): il traffico è cifrato, ma un attaccante attivo che controlli il percorso di rete potrebbe impersonare il server (nessuna Certification Authority reale a garanzia). Adatto a una demo in rete locale, non a un uso in produzione.
- Nessuna autenticazione degli utenti oltre alla scelta libera di un nickname.
- L'handshake TLS bloccante mette in pausa l'intero server (single-thread) per la sua durata: accettabile alla scala di questo progetto, da riconsiderare per molte connessioni concorrenti o client volutamente lenti.

---

## Autori

Massimiliano Spartà (566093) e Simone Adamo (567317)
