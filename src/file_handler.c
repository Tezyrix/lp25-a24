#include "file_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <regex.h>
#include <unistd.h>
#include <openssl/md5.h>

// Fonction permettant de lire un fichier de log existant
log_t read_backup_log(const char *logfile) {
    log_t logs = {NULL, NULL};
    FILE *file = fopen(logfile, "r");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier log");
        return logs;
    }

    char path[256], date[64];
    unsigned char md5[MD5_DIGEST_LENGTH];
    while (fscanf(file, "%s;%s;%32s", path, date, md5) == 3) {
        log_element *new_element = malloc(sizeof(log_element));
        if (!new_element) {
            perror("Erreur d'allocation mémoire");
            fclose(file);
            return logs;
        }

        new_element->path = strdup(path);
        new_element->date = strdup(date);
        memcpy(new_element->md5, md5, MD5_DIGEST_LENGTH);
        new_element->next = NULL;

        if (!logs.head) {
            logs.head = logs.tail = new_element;
            new_element->prev = NULL;
        } else {
            logs.tail->next = new_element;
            new_element->prev = logs.tail;
            logs.tail = new_element;
        }
    }

    fclose(file);
    return logs;
}

// Fonction permettant de mettre à jour le fichier de log
void update_backup_log(const char *logfile, log_t *logs) {
    FILE *file = fopen(logfile, "w");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier log en écriture");
        return;
    }

    log_element *current = logs->head;
    while (current) {
        fprintf(file, "%s %s %32s\n", current->path, current->date, current->md5);
        current = current->next;
    }

    fclose(file);
}

// Fonction pour écrire un élément de log dans le fichier                       
void write_log_element(FILE *file, const char *path, const char *date, const unsigned char *md5) {
    if (!file || !path || !date ) {   // j'ai du modifié ici parce que j'envoie un MD5 NULL si c'est un directory
        fprintf(stderr, "Invalid parameter passed to write_log_element.\n");
        return;
    }
    
    fprintf(file, "%s %s %32s\n", path, date, md5);
}

// Fonction pour lister les fichiers dans un répertoire
void list_files(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) {
        perror("Erreur lors de l'ouverture du répertoire");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            printf("%s/%s\n", path, entry->d_name);
        }
    }

    closedir(dir);
}

// Fonction pour copier un fichier
void copy_file(const char *src, const char *dest) {
    FILE *src_file = fopen(src, "rb");
    FILE *dest_file = fopen(dest, "wb");
    if (!src_file || !dest_file) {
        perror("Erreur d'ouverture de fichier");
        if (src_file) fclose(src_file);
        if (dest_file) fclose(dest_file);
        return;
    }

    char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src_file)) > 0) {
        fwrite(buffer, 1, bytes, dest_file);
    }

    fclose(src_file);
    fclose(dest_file);
}

// Fonction pour comparer un fichier avec le contenu d'un backup_log
int compare_file_with_backup_log(const char *path, log_t *logs, const char *backup_name, const char *logfile) {
    struct stat file_stat;
    unsigned char file_md5[MD5_DIGEST_LENGTH];
    log_element *current = logs->head;

    // Vérifie si le chemin est valide
    if (stat(path, &file_stat) != 0) {
        fprintf(stderr, "Erreur : Impossible d'obtenir les informations du chemin %s\n", path);
        return 0; // Échec si le chemin n'existe pas
    }

    // Si c'est un dossier
    if (S_ISDIR(file_stat.st_mode)) {
        // Parcourt le log pour vérifier si le dossier existe déjà
        while (current) {
            if (strcmp(current->path, path) == 0) {
                return 0; // Le dossier existe déjà, aucun besoin de sauvegarde
            }
            current = current->next;
        }

        // Ajout du dossier au log
        log_element *new_entry = malloc(sizeof(log_element));
        if (!new_entry) {
            fprintf(stderr, "Erreur : Allocation mémoire échouée\n");
            return 0;
        }
        snprintf(new_entry->path, sizeof(new_entry->path), "%s/%s", backup_name, path);
        strcpy(new_entry->date, "0");  // Pas de date pour les dossiers
        memset(new_entry->md5, 0, MD5_DIGEST_LENGTH); // Pas de MD5 pour les dossiers
        new_entry->next = logs->head;
        logs->head = new_entry;

        // Mettre à jour le fichier log
        update_backup_log(logfile, logs);
        return 1; // Le dossier doit être sauvegardé
    }

    // Si c'est un fichier
    if (S_ISREG(file_stat.st_mode)) {
        // Calcul du MD5 du fichier
        if (!find_file_md5(path, file_md5)) {
            fprintf(stderr, "Erreur : Impossible de calculer le MD5 pour le fichier %s\n", path);
            return 0; // Échec si le MD5 ne peut pas être calculé
        }

        // Recherche du fichier dans le log
        while (current) {
            if (strcmp(current->path, path) == 0) {
                // Vérifie la date de modification et le contenu
                if (strcmp(current->date, ctime(&file_stat.st_mtime)) > 0 &&
                    memcmp(current->md5, file_md5, MD5_DIGEST_LENGTH) != 0) {
                    // Fichier à sauvegarder : date postérieure et contenu différent
                    break;
                }
                return 0; // Le fichier est déjà à jour
            }
            current = current->next;
        }

        // Ajout ou mise à jour du fichier dans le log
        log_element *new_entry = malloc(sizeof(log_element));
        if (!new_entry) {
            fprintf(stderr, "Erreur : Allocation mémoire échouée\n");
            return 0;
        }
        snprintf(new_entry->path, sizeof(new_entry->path), "%s/%s", backup_name, path);
        strncpy(new_entry->date, ctime(&file_stat.st_mtime), sizeof(new_entry->date) - 1);
        new_entry->date[sizeof(new_entry->date) - 1] = '\0'; // Assure la terminaison
        memcpy(new_entry->md5, file_md5, MD5_DIGEST_LENGTH);
        new_entry->next = logs->head;
        logs->head = new_entry;

        // Mettre à jour le fichier log
        update_backup_log(logfile, logs);
        return 1; // Le fichier doit être sauvegardé
    }

    return 0; // Ni fichier ni dossier à sauvegarder
}

void generate_backup_log(const char *source_dir, const char *backup_dir) {

    // Créer le nom du fichier log : backup_dir.backup_log
    char log_file[512];
    snprintf(log_file, sizeof(log_file), "%s.backup_log", backup_dir);

    // Ouvrir le fichier de log en mode ajout
    FILE *log = fopen(log_file, "a");
    if (!log) {
        perror("Erreur d'ouverture du fichier log");
        return;
    }
    // Ouvrir le répertoire source
    DIR *dir = opendir(source_dir);
    if (!dir) {
        perror("Erreur d'ouverture du répertoire");
        fclose(log);
        return;
    }

    struct dirent *entry;
    struct stat file_stat;

    // Parcourir chaque entrée du répertoire source
    while ((entry = readdir(dir)) != NULL) {
        // Ignorer les fichiers et répertoires cachés (commençant par ".")
        if (entry->d_name[0] == '.') {
            continue;
        }

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", source_dir, entry->d_name);
        stat(path, &file_stat);

        // Récupérer la date de dernière modification (mtime)
        struct tm *mtime_tm = localtime(&file_stat.st_mtime);
        char mtime_str[20];
        strftime(mtime_str, sizeof(mtime_str), "%Y-%m-%d %H:%M:%S", mtime_tm);

        // Si c'est un fichier, calculer le MD5 pour l'ajouter dans le log
        if (S_ISREG(file_stat.st_mode)) {
            unsigned char md5_str[MD5_DIGEST_LENGTH];
            find_file_MD5(path, md5_str);                     // Calculer le MD5 du fichier
            write_log_element(log, path, mtime_str, md5_str); // Ajouter les informations dans le log
        } else if (S_ISDIR(file_stat.st_mode)) {
            // Si c'est un répertoire, ajouter son info dans le log
            write_log_element(log, path, mtime_str, NULL); // Aucun MD5 pour les répertoires
            // Appel récursif pour traiter les sous-répertoires
            generate_backup_log(path, backup_dir);
        }
    }

    // Fermer le fichier log et le répertoire
    fclose(log);
    closedir(dir);
}
