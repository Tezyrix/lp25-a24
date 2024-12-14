#include "file_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>

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
    while (fscanf(file, "%s %s %32s", path, date, md5) == 3) {
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
        write_log_element(current, file);
        current = current->next;
    }

    fclose(file);
}

// Fonction pour écrire un élément de log dans le fichier                       ( tu pourrais modifier pour prendre en parametre le file, le chemin,la date et le md5 ?)
void write_log_element(log_element *elt, FILE *file) {                          //pour que j'ai pas a créer un element dans mes fonctions à moi + à gérer les free
    fprintf(file, "%s %s %32s\n", elt->path, elt->date, elt->md5);
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
