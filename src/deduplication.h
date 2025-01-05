#ifndef DEDUPLICATION_H
#define DEDUPLICATION_H

#include "file_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <regex.h>
#include <unistd.h>

// Taille d'un chunk (4096 octets)
#define CHUNK_SIZE 4096

// Taille de la table de hachage qui contiendra les chunks
// dont on a déjà calculé le MD5 pour effectuer les comparaisons
#define HASH_TABLE_SIZE 10000
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

Md5Entry *global_hash_table;
Chunk *global_chunks;
FILE *global_hash_file, *global_chunk_file;

/**
 @brief Fonction de hachage MD5 pour l'indexation dans la table de hachage
 */
unsigned int hash_md5(unsigned char *md5);

/**
 * @brief Initialise les tables globales utilisées tout au long du programme.
 *
 * Cette fonction vérifie si les fichiers contenant les tables globales existent. Si les fichiers sont trouvés,
 * elle charge les données dans les tables. Si les fichiers sont manquants, elle crée les fichiers et initialise
 * les tables à des valeurs par défaut (vides).
 *
 * Les tables globales sont utilisées pour stocker les données nécessaires à la gestion des sauvegardes et
 * de la déduplication des fichiers.
 */
void initialize_global_tables();

/**
 * @brief Ajoute un chunk dans les tables globales si ce dernier n'existe pas déjà.
 *
 * Cette fonction vérifie si le chunk (identifié par son hash MD5) existe déjà dans les tables globales.
 * Si ce n'est pas le cas, elle ajoute le chunk à la table, en s'assurant qu'il soit traité de manière unique.
 *
 * Les tables globales sont utilisées pour stocker des informations sur les chunks dédupliqués afin d'optimiser
 * l'espace de stockage lors des sauvegardes.
 *
 * @param data Données du chunk à ajouter dans les tables.
 * @param md5 Hash MD5 unique du chunk pour identifier sa présence dans les tables.
 */
void add_to_global_tables(void *data, unsigned char *md5);

/**
 * @brief Ferme les tables globales après leur utilisation.
 *
 * Cette fonction ferme les fichiers contenant les tables globales utilisées pour le stockage des chunks dédupliqués.
 * Elle est appelée lorsque les tables ne sont plus nécessaires, garantissant que toutes les données sont correctement
 * sauvegardées et que les ressources système sont libérées.
 *
 * @note Il est important d'appeler cette fonction à la fin de l'exécution du programme pour assurer la persistance
 * des modifications dans les fichiers et éviter les fuites de ressources.
 */
void close_global_tables();

/**
 * @brief Déduplique un fichier en générant un tableau d'indices non uniques pour ses chunks.
 *
 * Cette fonction lit le fichier spécifié et le découpe en plusieurs chunks. Chaque chunk est ensuite associé à un indice
 * qui correspond à un chunk spécifique dans les tables globales. Les indices générés peuvent être non uniques, car plusieurs
 * fichiers ou parties de fichiers peuvent partager les mêmes chunks.
 *
 * @param file_path Le chemin du fichier à dédupliquer.
 * @param chunk_indices Tableau d'entiers qui contiendra les indices des chunks du fichier.
 *                      Ces indices sont non uniques et peuvent être partagés entre différents fichiers.
 * @param chunk_count Le nombre total de chunks générés à partir du fichier.
 *
 * @note Cette fonction utilise les tables globales pour vérifier si les chunks existent déjà, et si ce n'est pas le cas,
 *       elle les ajoute.
 */
void deduplicate_file(const char *file_path, int *chunk_indices, int *chunk_count);

/**
 * @brief Calcule le MD5 d'un chunk de données.
 *
 * Cette fonction prend un bloc de données (chunk) en entrée et calcule son empreinte MD5.
 * Le résultat est stocké dans le tableau `md5` fourni en paramètre.
 *
 * @param data Le chunk de données dont on veut calculer le MD5.
 *             Il s'agit généralement d'un bloc de données de taille fixe.
 * @param md5 Tableau de 16 octets qui contiendra le résultat du calcul MD5.
 *            Le tableau doit être initialisé avant d'appeler la fonction.
 */
void compute_md5(unsigned char *data, unsigned char *md5);

/**
 * @brief Cherche l'indice d'un MD5 dans la table de hashage global.
 *
 * Cette fonction recherche l'indice du chunk correspondant au MD5 spécifié dans
 * la table de hashage globale. Si le MD5 est trouvé, elle renvoie l'indice
 * correspondant, sinon elle retourne -1 pour indiquer que le MD5 n'a pas été trouvé.
 *
 * @param hash_table La table de hashage globale dans laquelle chercher l'indice.
 *                   Elle contient des entrées de type `Md5Entry`, chaque entrée
 *                   correspondant à un chunk de données.
 * @param md5 Le MD5 du chunk à chercher dans la table de hashage. Il s'agit d'un tableau de 16 octets.
 *
 * @return L'indice du chunk trouvé dans la table de hashage, ou -1 si le MD5 n'est pas trouvé.
 */
int find_md5(Md5Entry *hash_table, unsigned char *md5);

/**
 * @brief Effectue la déduplication d'un fichier .
 *
 * Cette fonction prend un fichier backup en entrée, et écrit un fichier de sortie après
 * avoir effectué le chemin inverse à la déduplication.
 *
 * @param input_filename Nom du fichier d'entrée à restaurer. Le fichier sera lu
 *                       pour extraire ses chunks de données.
 * @param output_filename Nom du fichier de sortie dans lequel les données réels
 *                        seront écrites.
 */
void undeduplicate(const char *input_filename, const char *output_filename);

/**
 * @brief Récupère un chunk à partir de son index dans la table.
 *
 * Cette fonction récupère les données d'un chunk en fonction de son index dans
 * la table globale et les place dans un objet `Chunk` passé en sortie.
 * Elle permet d'extraire un chunk spécifique de la table de déduplication.
 *
 * @param index L'index du chunk à récupérer dans la table de hashage globale.
 * @param chunk_out Pointeur vers un objet `Chunk` où les données du chunk récupéré
 *                  seront stockées.
 */
void get_chunk_from_index(int index, Chunk *chunk_out);

/**
 * @brief Calcule le MD5 d'un fichier.
 *
 * Cette fonction lit un fichier, calcule son hash MD5 et stocke le résultat
 * dans le tableau de 16 octets fourni. Le MD5 permet d'identifier de manière unique
 * le contenu du fichier.
 *
 * @param file Le pointeur vers le fichier à analyser.
 * @param md5 Un tableau de 16 octets pour stocker le résultat du hash MD5.
 */
void find_file_MD5(FILE *file, unsigned char *md5);

#endif // DEDUPLICATION_H

