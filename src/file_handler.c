#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "file_handler.h"

/**
 * @brief Liste les fichiers et dossiers présents dans un répertoire.
 *
 * @param path Chemin du répertoire à explorer.
 */
void list_files(const char *path) {
    struct dirent *entry;
    DIR *dir = opendir(path);

    if (dir == NULL) {
        perror("Erreur lors de l'ouverture du répertoire");
        return;
    }

    printf("Contenu du répertoire %s :\n", path);
    while ((entry = readdir(dir)) != NULL) {
        printf("- %s\n", entry->d_name);
    }

    closedir(dir);
}

/**
 * @brief Lit le contenu d'un fichier.
 *
 * @param filepath Chemin du fichier à lire.
 * @param size Pointeur pour stocker la taille du fichier lu.
 * @return char* Contenu du fichier (à libérer après utilisation).
 */
char *read_file(const char *filepath, size_t *size) {
    FILE *file = fopen(filepath, "rb");
    if (file == NULL) {
        perror("Erreur lors de l'ouverture du fichier");
        return NULL;
    }

    // Se positionner à la fin du fichier pour obtenir sa taille
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    rewind(file);

    // Allouer de la mémoire pour lire le contenu du fichier
    char *buffer = malloc(*size);
    if (buffer == NULL) {
        perror("Erreur d'allocation de mémoire");
        fclose(file);
        return NULL;
    }

    // Lire le contenu du fichier
    size_t read_size = fread(buffer, 1, *size, file);
    if (read_size != *size) {
        perror("Erreur lors de la lecture du fichier");
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return buffer;
}

/**
 * @brief Écrit des données dans un fichier.
 *
 * @param filepath Chemin du fichier à écrire.
 * @param data Données à écrire.
 * @param size Taille des données à écrire.
 */
void write_file(const char *filepath, const void *data, size_t size) {
    FILE *file = fopen(filepath, "wb");
    if (file == NULL) {
        perror("Erreur lors de l'ouverture du fichier pour écriture");
        return;
    }

    // Écrire les données dans le fichier
    size_t written_size = fwrite(data, 1, size, file);
    if (written_size != size) {
        perror("Erreur lors de l'écriture des données dans le fichier");
    }

    fclose(file);
}
