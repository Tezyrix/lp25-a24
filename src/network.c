#include "network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

// Fonction pour envoyer des données à un serveur
void send_data(const char *server_address, int port, const void *data, size_t size) {
    int sock;
    struct sockaddr_in server_addr;

    // Création du socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Erreur lors de la création de la socket");
        exit(EXIT_FAILURE);
    }

    // Configuration de l'adresse du serveur
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_address, &server_addr.sin_addr) <= 0) {
        perror("Adresse du serveur invalide");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Connexion au serveur
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Erreur lors de la connexion au serveur");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Envoi des données
    if (send(sock, data, size, 0) < 0) {
        perror("Erreur lors de l'envoi des données");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Données envoyées avec succès.\n");

    // Fermeture du socket
    close(sock);
}

// Fonction pour recevoir des données depuis un serveur
void receive_data(int port, void **data, size_t *size) {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[4096]; // Taille maximale de réception
    ssize_t received_size;

    // Création de la socket serveur
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Erreur lors de la création de la socket");
        exit(EXIT_FAILURE);
    }

    // Configuration de l'adresse du serveur
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // Liaison de la socket à l'adresse et au port
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Erreur lors du bind de la socket");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    // Mise en écoute
    if (listen(server_sock, 1) < 0) {
        perror("Erreur lors de la mise en écoute");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    printf("En attente de connexion sur le port %d...\n", port);

    // Acceptation d'une connexion
    client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
    if (client_sock < 0) {
        perror("Erreur lors de l'acceptation de la connexion");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    printf("Connexion acceptée.\n");

    // Réception des données
    received_size = recv(client_sock, buffer, sizeof(buffer), 0);
    if (received_size < 0) {
        perror("Erreur lors de la réception des données");
        close(client_sock);
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    // Allocation dynamique pour stocker les données reçues
    *data = malloc(received_size);
    if (*data == NULL) {
        perror("Erreur d'allocation mémoire");
        close(client_sock);
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    memcpy(*data, buffer, received_size);
    *size = (size_t)received_size;

    printf("Données reçues avec succès : %zu octets.\n", *size);

    // Fermeture des sockets
    close(client_sock);
    close(server_sock);
}
