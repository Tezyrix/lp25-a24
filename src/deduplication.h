#ifndef DEDUPLICATION_H
#define DEDUPLICATION_H

#include "file_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <dirent.h>

// Taille d'un chunk (4096 octets)
#define CHUNK_SIZE 4096

// Taille de la table de hachage qui contiendra les chunks
// dont on a déjà calculé le MD5 pour effectuer les comparaisons
#define HASH_TABLE_SIZE 1000

// Structure pour un chunk
typedef struct {
    unsigned char md5[MD5_DIGEST_LENGTH]; // MD5 du chunk
    void *data; // Données du chunk
} Chunk;

// Table de hachage pour stocker les MD5 et leurs index
typedef struct {
    unsigned char md5[MD5_DIGEST_LENGTH];
    int index;
} Md5Entry;

/**
 @brief Fonction de hachage MD5 pour l'indexation dans la table de hachage
 */
unsigned int hash_md5(unsigned char *md5);

/**
 @brief Fonction pour calculer le MD5 d'un chunk
 */
void compute_md5(void *data, size_t len, unsigned char *md5_out);

/**
 @brief Fonction permettant de chercher un MD5 dans la table de hachage
 @param hash_table Tableau de hachage qui contient les MD5 et l'index des chunks unique
 @param md5 MD5 du chunk dont on veut déterminer l'unicité
 @return Retourne l'index s'il trouve le md5 dans le tableau et -1 sinon
 */
int find_md5(Md5Entry *hash_table, unsigned char *md5);

/**
 @brief Fonction pour ajouter un MD5 dans la table de hachage
 @param hash_table
 @param md5
 @param index
 */
void add_md5(Md5Entry *hash_table, unsigned char *md5, int index);

/**
 @brief Fonction pour convertir un fichier non dédupliqué en tableau de chunks
 @param file Fichier qui sera dédupliqué
 @param chunks Tableau de chunks initialisés qui contiendra les chunks issu du fichier
 @param hash_table Tableau de hachage qui contient les MD5 et l'index des chunks unique
 */
void deduplicate_file(FILE *file, Chunk *chunks, Md5Entry *hash_table);

/**
 @brief Fonction permettant de charger un fichier dédupliqué en table de chunks
 en remplaçant les références par les données correspondantes
 @param file Nom du fichier dédupliqué présent dans le répertoire de sauvegarde
 @param chunks Représente le tableau de chunk qui contiendra les chunks restauré depuis filename
 @param chunk_count Compteur du nombre de chunk restauré depuis le fichier filename
 */
void undeduplicate_file(FILE *file, Chunk **chunks, int *chunk_count);

/**
 @brief Besoin d'une fonction pour calculer le md5 d'un fichier

 */
void find_file_MD5(FILE *file, unsigned char *md5);

#endif // DEDUPLICATION_H

