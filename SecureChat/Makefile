CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LDLIBS  = -lssl -lcrypto
COMMON  = registry.c tls.c chat.h tls.h

all: chat_select chat_epoll chat_client

chat_select: main_select.c $(COMMON)
	$(CC) $(CFLAGS) -o chat_select main_select.c registry.c tls.c $(LDLIBS)

chat_epoll: main_epoll.c $(COMMON)
	$(CC) $(CFLAGS) -o chat_epoll main_epoll.c registry.c tls.c $(LDLIBS)

chat_client: chat_client.c chat.h tls.c tls.h
	$(CC) $(CFLAGS) -o chat_client chat_client.c tls.c $(LDLIBS)

# Certificato autofirmato per i test in locale. Va rigenerato da ognuno
# in locale (non e' portato nel repository: contiene una chiave privata).
cert:
	openssl req -x509 -newkey rsa:2048 -nodes \
	    -keyout server.key -out server.crt -days 365 \
	    -subj "/CN=localhost"

clean:
	rm -f chat_select chat_epoll chat_client

distclean: clean
	rm -f server.key server.crt

.PHONY: all clean distclean cert
