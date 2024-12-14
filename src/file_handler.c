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
        fprintf(file, "%s %s %32s\n", current->path, current->date, current->md5);
        current = current->next;
    }

    fclose(file);
}

// Fonction pour écrire un élément de log dans le fichier                       
void write_log_element(FILE *file, const char *path, const char *date, const unsigned char *md5) {
    if (!file || !path || !date || !md5) {
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
int compare_file_with_backup_log(const char *path, log_t *logs) {
    struct stat file_stat;
    unsigned char file_md5[MD5_DIGEST_LENGTH];
    log_element *current = logs->head;

    if (stat(path, &file_stat) != 0) {
        fprintf(stderr, "Erreur : Impossible d'obtenir les informations du fichier %s\n", path);
        return 0; // Échec si le fichier n'existe pas
    }

    if (!compute_md5(path, file_md5)) {
        fprintf(stderr, "Erreur : Impossible de calculer le MD5 pour le fichier %s\n", path);
        return 0; // Échec si le MD5 ne peut pas être calculé
    }

    while (current) {
        if (strcmp(current->path, path) == 0) {

            if (strcmp(current->date, ctime(&file_stat.st_mtime)) != 0) {
                return 1; // Succès : date de modification différente
            }

            if (memcmp(current->md5, file_md5, MD5_DIGEST_LENGTH) != 0) {
                return 1; // Succès : MD5 différent
            }

            return 0; // Échec : fichier identique
        }
        current = current->next;
    }

    return 1; // Succès : fichier n'existe pas dans le backup_log
}

//	- un fichier dans la source et dans la destination est copié si :
//-la date de modification est postérieure dans la source et le contenu est différent 
//- la taille est différente et le contenu est différent

// en gros ca serait bien si ta fonction : teste si c'est un fichier ou un dossier, 
// si c'est un dossier: tu regardes si il existe dans le log,
// si oui tu renvoie 0, si non tu l'ajoutes dans le log sous le format backup_name/path (backup_name que je te donne en parametre) et tu renvoie 1
// si c'est un fichier: tu regardes si il existe dans le log,
// si non, tu l'ajoutes dans le log sous le format backup_name/path/mtime/md5 (t'as un fonction pour calculer le md5 d'un fichier) et tu renvoie 1
// si oui tu regardes d'abord si on doit le sauvegarder selon les critères plus haut, si non tu renvoie 0, si oui tu l'ajoute au log selon le format et tu renvoie 1 (tu peux utiliser ta fonction plus haut)
// en gros tu renvoie 0 si je dois pas toucher au fichier, 1 si je dois le backup
