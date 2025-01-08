#include "file_handler.h"
#include "deduplication.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <regex.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <libgen.h>

// Fonction permettant de lire un fichier de log existant
log_t read_backup_log(const char *logfile) {
    log_t logs = {NULL, NULL};
    FILE *file = fopen(logfile, "r");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier log");
        return logs;
    }

    char path[256], date[64], md5_hex[33];
    unsigned char md5[MD5_DIGEST_LENGTH];
    while (fscanf(file, "%255[^;];%63[^;];%32s", path, date, md5_hex) == 3) {
        // Convertir le MD5 hexadécimal en binaire
        for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
            sscanf(&md5_hex[i * 2], "%2hhx", &md5[i]);
        }

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

// Fonction pour écrire un élément de log (pas de MD5 pour l'instant)
void write_log_element(FILE *log, const char *path, const char *mtime_str) {
    if (log && path && mtime_str) {
        fprintf(log, "%s;%s\n", path, mtime_str);
    }
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





int compare_file_with_backup_log(const char *path, log_t *logs, const char *backup_name, const char *logfile) {
    struct stat file_stat;
    char file_md5_str[MD5_DIGEST_LENGTH * 2 + 1]; // Pour stocker le MD5 sous forme hexadécimale
    log_element *current = logs->head;

    // Vérifie si le chemin est valide
    if (stat(path, &file_stat) != 0) {
        return 0; // Échec si le chemin n'existe pas
    }

    // Si c'est un fichier
    if (S_ISREG(file_stat.st_mode)) {
        calculate_md5(path, file_md5_str, sizeof(file_md5_str)); // MD5 calculé sous forme de chaîne hexadécimale

        // Extraire le basename du fichier path
        char *file_basename = basename(path);  // Donne juste le nom du fichier sans son chemin

        // Parcours des éléments de log pour comparer les basenames
        while (current) {
            // Extraire le basename du fichier dans le log
            char *log_basename = basename(current->path); // Basename du fichier dans les logs

            // Comparer les basenames
            if (strcmp(file_basename, log_basename) == 0) {
                // Conversion du MD5 du log en chaîne hexadécimale
                char log_md5_str[MD5_DIGEST_LENGTH * 2 + 1]; // Pour stocker le MD5 sous forme hexadécimale
                for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
                    snprintf(&log_md5_str[i * 2], 3, "%02x", current->md5[i]);
                }

                // Comparaison des MD5 sous forme de chaîne hexadécimale
                if (strcmp(log_md5_str, file_md5_str) != 0) { // Si les MD5 diffèrent
                    printf("Le fichier %s doit être sauvegardé (MD5 différent)\n", file_basename);
                    return 1; // Le fichier doit être sauvegardé (MD5 différent)
                }

                // Si les MD5 sont identiques, on vérifie la date
                if (strcmp(current->date, ctime(&file_stat.st_mtime)) > 0) {
                    // La date du log est plus ancienne que la date de modification du fichier
                    printf("Le fichier %s doit être sauvegardé (date différente)\n", file_basename);
                    return 1; // Le fichier doit être sauvegardé (date différente)
                }

                printf("Le fichier %s n'a pas besoin d'être sauvegardé (aucun changement)\n", file_basename);
                return 0; // Aucun changement détecté (MD5 et date identiques)
            }

            current = current->next;
        }

        // Si aucun fichier correspondant n'a été trouvé, il faut sauvegarder ce fichier
        printf("Le fichier %s doit être sauvegardé (pas de correspondance dans les logs)\n", file_basename);

        // Allocation de mémoire pour un nouvel élément de log
        log_element *new_entry = malloc(sizeof(log_element));
        if (!new_entry) {
            fprintf(stderr, "Erreur : Allocation mémoire échouée\n");
            return 0;
        }

        // Allocation de mémoire pour les champs path, date (md5 reste un tableau statique)
        new_entry->path = malloc(PATH_MAX * sizeof(char));  // Allocation mémoire pour path
        new_entry->date = malloc(20 * sizeof(char));  // Allocation mémoire pour date (taille suffisante pour une date)

        if (!new_entry->path || !new_entry->date) {
            fprintf(stderr, "Erreur : Allocation mémoire échouée pour path ou date\n");
            free(new_entry);  // Libération de la mémoire allouée avant de quitter
            return 0;
        }

        // Formater la date au format souhaité (YYYY-MM-DD:HH:MM:SS)
        char formatted_date[20];
        struct tm *tm_info = localtime(&file_stat.st_mtime);
        strftime(formatted_date, sizeof(formatted_date), "%Y-%m-%d:%H:%M:%S", tm_info);

        // Remplir les champs
        snprintf(new_entry->path, PATH_MAX, "%s/%s", basename(backup_name), file_basename); // Le chemin complet
        snprintf(new_entry->date, 20, "%s", formatted_date);  // Date de modification du fichier au format YYYY-MM-DD:HH:MM:SS

        // Copier le MD5 dans la structure (pas d'allocation dynamique, utilisation du tableau statique)
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            new_entry->md5[i] = file_md5_str[i * 2]; // Copie du MD5 calculé
        }

        new_entry->next = logs->head;  // Ajouter à la tête de la liste
        logs->head = new_entry;

        // Mettre à jour le fichier log
        
        // update_backup_log(logfile, logs);

        return 1; // Le fichier doit être sauvegardé (pas de correspondance dans les logs)

    }

    // Si c'est un dossier
    if (S_ISDIR(file_stat.st_mode)) {
        // Extraire le basename du dossier path
        char *dir_basename = basename(path);  // Donne juste le nom du dossier sans son chemin

        // Parcours des éléments de log pour vérifier si le dossier existe dans les logs
        while (current) {
            // Extraire le basename du fichier/dossier dans le log
            char *log_basename = basename(current->path); // Basename du fichier/dossier dans les logs

            // Comparer les basenames (uniquement pour les dossiers)
            if (strcmp(dir_basename, log_basename) == 0) {
                printf("Le dossier %s existe déjà dans les logs, aucune sauvegarde nécessaire.\n", dir_basename);
                return 0; // Le dossier est déjà sauvegardé, pas besoin de sauvegarder
            }

            current = current->next;
        }

        // Si le dossier n'est pas trouvé dans les logs, il faut le sauvegarder
        printf("Le dossier %s doit être sauvegardé (pas de correspondance dans les logs)\n", dir_basename);

        // Allocation de mémoire pour un nouvel élément de log
        log_element *new_entry = malloc(sizeof(log_element));
        if (!new_entry) {
            fprintf(stderr, "Erreur : Allocation mémoire échouée\n");
            return 0;
        }

        // Allocation de mémoire pour les champs path et date (pas besoin d'allocation pour md5)
        new_entry->path = malloc(PATH_MAX * sizeof(char));  // Allocation mémoire pour path
        new_entry->date = malloc(20 * sizeof(char));  // Allocation mémoire pour date (taille suffisante pour une date)
        
        if (!new_entry->path || !new_entry->date) {
            fprintf(stderr, "Erreur : Allocation mémoire échouée pour path ou date\n");
            free(new_entry);  // Libération de la mémoire allouée avant de quitter
            return 0;
        }

        // Formater la date au format souhaité (YYYY-MM-DD:HH:MM:SS)
        char formatted_date[20];
        struct tm *tm_info = localtime(&file_stat.st_mtime);
        strftime(formatted_date, sizeof(formatted_date), "%Y-%m-%d:%H:%M:%S", tm_info);

        // Remplir les champs
        snprintf(new_entry->path, PATH_MAX, "%s/%s", basename(backup_name), dir_basename); // Le chemin complet
        snprintf(new_entry->date, 20, "%s", formatted_date);  // Date de modification du dossier au format YYYY-MM-DD:HH:MM:SS
        memset(new_entry->md5, 0, MD5_DIGEST_LENGTH); // Pas de MD5 pour les dossiers, mettre à zéro
        new_entry->next = logs->head;  // Ajouter à la tête de la liste
        logs->head = new_entry;

        // Mettre à jour le fichier log
        
        // update_backup_log(logfile, logs);

        return 1; // Le dossier doit être sauvegardé (pas de correspondance dans les logs)
    }

    return 0; // Ni fichier ni dossier à sauvegarder

}




void calculate_md5(const char *filename, char *md5_str, size_t md5_str_size) {
    unsigned char c[MD5_DIGEST_LENGTH];
    unsigned char buf[1024];
    MD5_CTX mdContext;
    FILE *file = fopen(filename, "rb");

    if (!file) {
        perror("Erreur d'ouverture du fichier pour le calcul du MD5");
        snprintf(md5_str, md5_str_size, "N/A"); // Indiquer qu'il n'a pas été possible de calculer le MD5
        return;
    }

    MD5_Init(&mdContext);
    size_t bytes;
    while ((bytes = fread(buf, 1, sizeof(buf), file)) != 0) {
        MD5_Update(&mdContext, buf, bytes);
    }

    MD5_Final(c, &mdContext);
    fclose(file);

    // Convertir le hash en chaîne de caractères
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        snprintf(&md5_str[i * 2], 3, "%02x", c[i]);
    }
}


// Fonction principale pour générer le log
void generate_backup_log(const char *source_dir, const char *basename, FILE *log) {
    if (!source_dir) {
        fprintf(stderr, "Répertoire source invalide: %s\n", source_dir);
        return;
    }

    DIR *dir = opendir(source_dir);
    if (!dir) {
        perror("Erreur d'ouverture du répertoire");
        return;
    }

    struct dirent *entry;
    struct stat file_stat;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", source_dir, entry->d_name);

        if (strlen(path) >= sizeof(path)) {
            printf("Le chemin %s est trop long.\n", path);
            continue;
        }

        if (stat(path, &file_stat) == -1) {
            perror("Erreur d'obtention des informations sur le fichier");
            continue;
        }

        struct tm *mtime_tm = localtime(&file_stat.st_mtime);
        if (!mtime_tm) {
            perror("Erreur lors de la conversion de la date de modification");
            continue;
        }

        char mtime_str[20];
        strftime(mtime_str, sizeof(mtime_str), "%Y-%m-%d:%H:%M:%S", mtime_tm);

        char relative_path[1024];
        snprintf(relative_path, sizeof(relative_path), "%s/%s", basename, entry->d_name);

        if (S_ISREG(file_stat.st_mode)) {
            // Calculer le MD5 pour les fichiers
            char md5_hash[MD5_DIGEST_LENGTH * 2 + 1];
            calculate_md5(path, md5_hash, sizeof(md5_hash));

            // Ajouter le chemin relatif, la date de modification et le MD5 au log
            fprintf(log, "%s;%s;%s\n", relative_path, mtime_str, md5_hash);
        } else if (S_ISDIR(file_stat.st_mode)) {
        // Ajouter les répertoires au log (avec un MD5 fictif)
        unsigned char fake_md5[MD5_DIGEST_LENGTH] = {0}; // MD5 de 32 caractères '0'
        char fake_md5_str[MD5_DIGEST_LENGTH * 2 + 1]; // pour stocker le MD5 en hexadécimal

        // Convertir le fake_md5 en chaîne hexadécimale
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            sprintf(&fake_md5_str[i * 2], "%02x", fake_md5[i]);
        }

        // Ecrire le répertoire dans le log avec un MD5 fictif
        fprintf(log, "%s;%s;%s\n", relative_path, mtime_str, fake_md5_str);

        // Appel récursif pour traiter les sous-dossiers
        generate_backup_log(path, relative_path, log);
        }
    }

    closedir(dir);
}

void display_logs(const log_t *logs) {
    if (!logs || !logs->head) {
        printf("La liste des logs est vide.\n");
        return;
    }

    log_element *current = logs->head;
    printf("Contenu des logs :\n");
    printf("%-50s %-30s %-32s\n", "Chemin", "Date", "MD5");
    printf("----------------------------------------------------------------------------------------\n");

    while (current) {
        // Affiche un seul nœud
        printf("%-50s %-30s ", current->path, current->date);
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            printf("%02x", current->md5[i]); // Affiche le MD5 en hexadécimal
        }
        printf("\n");

        // Demande à l'utilisateur d'appuyer sur une touche pour continuer
        printf("Appuyez sur Entrée pour afficher le nœud suivant...\n");
        getchar(); // Attend que l'utilisateur appuie sur Entrée

        current = current->next;
    }

    printf("Fin des logs.\n");
}
