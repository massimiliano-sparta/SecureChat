# ============================================================
# SecureChat — Makefile con directory structure
# ============================================================

# Compilatore e flags
CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -Iinclude
LDLIBS  := -lssl -lcrypto

# Directory
SRCDIR  := src
INCDIR  := include
BUILDDIR:= build
BINDIR  := bin

# Sorgenti
SRC_TLS      := $(SRCDIR)/tls.c
SRC_REGISTRY := $(SRCDIR)/registry.c
SRC_SERVER_SELECT := $(SRCDIR)/main_select.c
SRC_SERVER_EPOLL  := $(SRCDIR)/main_epoll.c
SRC_CLIENT        := $(SRCDIR)/chat_client.c

# Oggetti
OBJ_TLS           := $(BUILDDIR)/tls.o
OBJ_REGISTRY      := $(BUILDDIR)/registry.o
OBJ_SERVER_SELECT := $(BUILDDIR)/main_select.o
OBJ_SERVER_EPOLL  := $(BUILDDIR)/main_epoll.o
OBJ_CLIENT        := $(BUILDDIR)/chat_client.o

# Eseguibili
TARGET_SELECT := $(BINDIR)/chat_select
TARGET_EPOLL  := $(BINDIR)/chat_epoll
TARGET_CLIENT := $(BINDIR)/chat_client

TARGETS := $(TARGET_SELECT) $(TARGET_EPOLL) $(TARGET_CLIENT)

# ============================================================
# Regole
# ============================================================

.PHONY: all clean dirs cert

all: dirs $(TARGETS)

# Crea le directory se non esistono
dirs:
	@mkdir -p $(BUILDDIR) $(BINDIR)

# --- Server select ---
# registry.c e tls.c sono comuni a entrambe le varianti di server
$(TARGET_SELECT): $(OBJ_SERVER_SELECT) $(OBJ_REGISTRY) $(OBJ_TLS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# --- Server epoll ---
$(TARGET_EPOLL): $(OBJ_SERVER_EPOLL) $(OBJ_REGISTRY) $(OBJ_TLS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# --- Client ---
# non usa registry.c (nessuna rubrica multi-client), ma serve comunque tls.c
$(TARGET_CLIENT): $(OBJ_CLIENT) $(OBJ_TLS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# Compilazione generica .c -> .o
$(BUILDDIR)/%.o: $(SRCDIR)/%.c $(INCDIR)/chat.h $(INCDIR)/tls.h | dirs
	$(CC) $(CFLAGS) -c $< -o $@

# Certificato autofirmato per i test in locale. Va rigenerato da ognuno
# in locale (non e' portato nel repository: contiene una chiave privata).
cert:
	openssl req -x509 -newkey rsa:2048 -nodes \
	    -keyout server.key -out server.crt -days 365 \
	    -subj "/CN=localhost"

# ============================================================
# Pulizia
# ============================================================

clean:
	rm -rf $(BUILDDIR) $(BINDIR)
