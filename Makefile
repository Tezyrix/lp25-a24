CC = gcc
CFLAGS = -Wall -Wextra -I./src
LDFLAGS = -lssl -lcrypto  # Ajout des flags pour lier OpenSSL

SRC = src/main.c src/file_handler.c src/deduplication.c src/backup_manager.c src/network.c
OBJ = $(SRC:.c=.o)

all: lp25_borgbackup

lp25_borgbackup: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)  # Ajout des LDFLAGS pour la liaison avec OpenSSL

clean:
	rm -f $(OBJ) lp25_borgbackup
