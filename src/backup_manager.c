#include "backup_manager.h"
#include "deduplication.h"
#include "file_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <regex.h>

//pas utiliser les hashages réellement

// Fonction pour créer une nouvelle sauvegarde complète puis incrémentale
void create_backup(const char *source_dir, const char *backup_dir){
    /**
     * @param source_dir est le chemin vers le répertoire à sauvegarder
     * @param backup_dir est le chemin vers le répertoire de sauvegarde
     */

    // Si aucune backup n'existe, faire une sauvegarde complète
    if (!check_if_backup_exist(backup_dir)) {
        printf("Pas de backup trouvé, sauvegarde complète...\n");
        full_backup(source_dir, backup_dir);
    } else {
        // Si une sauvegarde existe déjà, effectuer une sauvegarde incrémentale
        printf("Backup trouvé, on effectue une sauvegarde incrémentale\n", backup_dir);
        // Générer le nom du répertoire pour la sauvegarde incrémentale
        char incremental_backup_name[256];
        generate_backup_name(incremental_backup_name);

        // Créer un répertoire pour la sauvegarde incrémentale
        char incremental_backup_path[512];
        snprintf(incremental_backup_path, sizeof(incremental_backup_path), "%s/%s", backup_dir, incremental_backup_name);
        mkdir(incremental_backup_path, 0755);

        // Les logs sont déjà supposés être présents dans le répertoire de sauvegarde sous le nom backup_dir.backup_log on génere le path à celui ci
        char log_file[512];
        snprintf(log_file, sizeof(log_file), "%s.backup_log", backup_dir);
        log_t log_chain = read_backup_log(log_file);
        // Effectuer une sauvegarde incrémentale
        incremental_backup(source_dir, incremental_backup_path, log_chain, log_file);
        }
}

// Fonction permettant d'enregistrer dans fichier les indices des chunks dédupliqués
int write_backup_file(const char *output_filename, int *chunk_indices, int chunk_count){
    /**
     * @param output_filename est le fichier dans lequel on va sauvegarder
     * @param chunk_indices est un tableau d'indices des chunks dédupliqués
     * @param chunk_count est le nombre d'indices dans le tableau
     */

    // Ouvrir le fichier de sauvegarde en écriture binaire
    FILE *output_file = fopen(output_filename, "wb");

    if (!output_file) {
        return 1; 
    }
    // Parcourir chaque indice et l'écrire dans le fichier
    for (int i = 0; i < chunk_count; i++) {
        if (fprintf(output_file, "%d\n", chunk_indices[i]) < 0) {
            fclose(output_file);
            return 1; // Erreur lors de l'écriture de l'indice
        }
    }
    fclose(output_file); 
    return 0;            
}

void backup_file(const char *filename) {
    /**
     * @param filename est le nom du fichier à sauvegarder
     */

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Erreur");
        return;
    }

    // Initialisation d'un tableau d'indices dynamique pour deduplicate
    int *chunk_indices = malloc(sizeof(int) * HASH_TABLE_SIZE); 
    if (!chunk_indices) {
        perror("Erreur d'allocation mémoire");
        fclose(file);
        return;
    }
    int chunk_count = 0;
    // Remplir le tableau d'indices en utilisant la fonction deduplicate_file
    deduplicate_file(file, chunk_indices, &chunk_count);
    fclose(file);

    // Créer le nom du fichier de sauvegarde
    char backup_filename[512];
    snprintf(backup_filename, sizeof(backup_filename), "%s.backup", filename);

    // Écrire les indices dans le fichier de sauvegarde
    if (write_backup_file(backup_filename, chunk_indices, chunk_count) != 0) {
        fprintf(stderr, "Erreur dans la génération du fichier %s\n", backup_filename);
        free(chunk_indices);
        return;
    }

    // Obtenir les informations du fichier source
    struct stat file_stat;
    if (stat(filename, &file_stat) == 0) {
        // Modifier les permissions du fichier backup
        if (chmod(backup_filename, file_stat.st_mode) != 0) {
            perror("Erreur de permissions");
        }
        // Modifier les dates d'accès et de modification
        struct utimbuf new_times;
        new_times.actime = file_stat.st_atime;
        new_times.modtime = file_stat.st_mtime;
        utime(backup_filename, &new_times);
    } else {
        perror("Pas accès aux informations du fichier");
    }
    // Libérer la mémoire allouée pour les indices
    free(chunk_indices);

    printf("%s done\n", filename);
}

// Fonction permettant la restauration du fichier backup via le tableau de chunk
void write_restored_file(const char *output_filename, Chunk *chunks, int chunk_count) {
    /*
    */
}

// Fonction pour restaurer une sauvegarde
void restore_backup(const char *backup_id, const char *restore_dir) {
    /* @param: backup_id est le chemin vers le répertoire de la sauvegarde que l'on veut restaurer
    *          restore_dir est le répertoire de destination de la restauration
    */
}

// Fonction permettant de lister les différentes sauvegardes présentes dans la destination 
void list_backups(const char *backup_dir){
    /**
     * @param backup_dir dossier dans lequel on liste les backups
     */

    DIR *dir = opendir(backup_dir);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    regex_t regex;

    // Compile la regex au format pour qu'elle soit utilisable
    if ((regcomp(&regex, "^\\d{4}-\\d{2}-\\d{2}-\\d{2}:\\d{2}:\\d{2}\\.\\d{3}$", REG_EXTENDED)) != 0) {
        perror("La regex n'a pas pu être compilée");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        // Ignorer les directory spéciaux commençant par .
        if (entry->d_name[0] == '.') {
            continue;
        }    
        // On vérifie d'abord si c'est un directory 
        if (entry->d_type == DT_DIR) {
            // Puis on vérifie que son nom correspond au format de la backup
            if (regexec(&regex, entry->d_name, 0, NULL, 0) == 0) {
                printf("%s\n", entry->d_name);
            }
        }
    }
    regfree(&regex); // On libère la mémoire venant du regcomp
    closedir(dir);
}

// Fonction pour vérifier si une sauvegarde existe dans le répertoire donné            
int check_if_backup_exist(const char *backup_dir) {
    /**
     * @param backup_dir dossier dans lequel on cherche s'il existe une backup
     */

    DIR *dir = opendir(backup_dir);
    if (!dir) {
        perror("opendir");
        return 0;
    }
    struct dirent *entry;
    regex_t regex;

    // Compile la regex au format pour qu'elle soit utilisable
    if (regcomp(&regex, "^\\d{4}-\\d{2}-\\d{2}-\\d{2}:\\d{2}:\\d{2}\\.\\d{3}$", REG_EXTENDED) != 0) {
        perror("La regex n'a pas pu être compilée");
        closedir(dir);
        return 0;
    }

    // Parcours des fichiers dans le répertoire
    while ((entry = readdir(dir)) != NULL) {
        // Ignorer les fichiers commencant par . (sécurité)
        if (entry->d_name[0] == '.') {
            continue;
        }
        // Vérifier si c'est un répertoire et si son nom correspond à la regex
        if (entry->d_type == DT_DIR) {
            if (regexec(&regex, entry->d_name, 0, NULL, 0) == 0) {
                regfree(&regex); // Free la regex venant de regcomp
                closedir(dir);   
                return 1;        // Succès
            }
        }
    }
    regfree(&regex); // Libérer la mémoire de la regex
    closedir(dir);   // Fermer le répertoire
    return 0;        // Aucune sauvegarde trouvée, retour 0
}


// Fonction pour générer le nom du directory backup  
void generate_backup_name(char *backup_name) {
    /**
     * @param backup_name chaine de caractère vide dans lequel on va stocker le nom de la backup
     */

    struct timeval tv;
    gettimeofday(&tv, NULL);                    // Récupérer le temps actuel puis on le formate avec localtime
    struct tm *tm_info = localtime(&tv.tv_sec); // On traite les millisecondes à part en utilisant la structure tm

    // Formater le nom de la sauvegarde avec la date et l'heure
    strftime(backup_name, 20, "%Y-%m-%d-%H:%M:%S", tm_info);

    // Ajouter les millisecondes
    snprintf(backup_name + 19, 5, ".%03ld", tv.tv_usec / 1000); // tv_usec est en microsecondes, donc on divise par 1000 pour obtenir les millisecondes
}


// Fonction permettant de faire une copie complète par lien dur et génère le log
void full_backup(const char *source_dir, const char *backup_dir) {
    /**
     * @param source_dir source à copier
     * @param backup_dir dossier dans lequel on va copier
     */

    char backup_name[256];
    generate_backup_name(backup_name); // Générer le nom de la backup

    // Créer le répertoire de sauvegarde dans backup_dir
    char backup_path[512];
    snprintf(backup_path, sizeof(backup_path), "%s/%s", backup_dir, backup_name);
    mkdir(backup_path, 0755); // Umask classique   rwxr-xr-x

    DIR *source = opendir(source_dir);

    struct dirent *entry;
    while ((entry = readdir(source)) != NULL) {
        if (entry->d_name[0] == '.') { 
            continue;
        }
        char source_path[512], backup_file_path[512];
        snprintf(source_path, sizeof(source_path), "%s/%s", source_dir, entry->d_name);
        snprintf(backup_file_path, sizeof(backup_file_path), "%s/%s", backup_path, entry->d_name);

        // Vérification du type de fichier avec d_type
        if (entry->d_type == DT_DIR) {
            // Si c'est un répertoire, on crée un répertoire de sauvegarde
            mkdir(backup_file_path, 0755); 
            // Procédé de récursivité cas particulier 
            full_backup(source_path, backup_file_path);
        } else if (entry->d_type == DT_REG) {
            // Sinon cas général, c'est un fichier on fait un lien dur
            link(source_path, backup_file_path);
        }
    }
    closedir(source);
    // Générer le fichier de log après la sauvegarde
    generate_backup_log(source_dir, backup_dir);
}

// Fonction pour générer le fichier de log après une sauvegarde
void generate_backup_log(const char *source_dir, const char *backup_dir)
{
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

// Fonction effectuant une sauvegarde incrémentale d'un directory en mettant également à jour les logs
void incremental_backup(const char *source_dir, const char *incremental_backup_dir, log_t *logs, const char *logfile) {
    /**
     * @param source_dir source que l'on va sauvegarder
     * @param incremental_backup_dir directory dans lequel on va sauvegarder les fichiers modifiés ou ajoutés
     * @param logs liste chainée représentant les logs
     * @param logfile fichier log de toutes les sauvegardes
     */
    DIR *source = opendir(source_dir);
    if (!source) {
        perror("Erreur d'ouverture du répertoire source");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(source)) != NULL) {
        // Ignorer les fichiers et répertoires cachés
        if (entry->d_name[0] == '.') {
            continue;
        }

        char source_path[512], backup_file_path[512];
        snprintf(source_path, sizeof(source_path), "%s/%s", source_dir, entry->d_name);
        snprintf(backup_file_path, sizeof(backup_file_path), "%s/%s", incremental_backup_dir, entry->d_name);

        struct stat file_stat;
        stat(source_path, &file_stat);

        // Vérifier si c'est un fichier ou un répertoire
        if (S_ISDIR(file_stat.st_mode)) {
            // Si c'est un répertoire, on compare avec les logs
            if (compare_file_with_backup_log(source_path , logs, incremental_backup_dir, log_file)) {
                mkdir(backup_file_path, 0755); // Le répertoire est nouveau, on le crée
            }
            // Traiter récursivement le sous-répertoire
            incremental_backup(source_dir, backup_file_path, logs, log_file);
        } else if (S_ISREG(file_stat.st_mode)) {
            // Si c'est un fichier, on compare avec les logs
            if (compare_file_with_backup_log(source_path, logs, incremental_backup_dir, log_file)) {
                // Si le fichier a changé ou est nouveau, on le sauvegarde
                backup_file(source_path); // Sauvegarde le fichier en créant un fichier de backup

                // Construire le chemin du fichier de sauvegarde .backup dans le répertoire de sauvegarde incrémentale
                char backup_file_name[512];
                snprintf(backup_file_name, sizeof(backup_file_name), "%s/%s", incremental_backup_dir, entry->d_name);

                // Copier le fichier .backup dans le répertoire de sauvegarde incrémentale
                char backup_source_path[512];
                snprintf(backup_source_path, sizeof(backup_source_path), "%s.backup", source_path);
                copy_file(backup_source_path, backup_file_name); // Copier le fichier .backup dans la destination
                printf("Fichier .backup copié vers : %s\n", backup_file_name);

                // Supprimer le fichier .backup de la source après la copie
                remove(backup_source_path);
            }
        }
    }
    closedir(source);
    // Vérifier les fichiers supprimés dans la source et mettre à jour le log
    check_and_mark_deleted_files(source_dir, logs, logfile);
}

// Fonction vérifiant qu'il n'y a pas de fichier en trop dans la backup par rapport à la source et met à jour les logs 
void check_and_mark_deleted_files(const char *source_dir, log_t *logs, const char *logfile) {
    /**
     * @param source_dir source à laquelle on va comparer les logs
     * @param logs liste chainé représentant les logs
     * @param logfile fichier log
     */
    log_element *current = logs->head; // Parcours de la liste des logs

    while (current != NULL) {
        char file_path[512];
        snprintf(file_path, sizeof(file_path), "%s/%s", source_dir, current->path);

        struct stat file_stat;
        int exists = stat(file_path, &file_stat); // Vérifie si le fichier existe

        // Si le fichier n'existe pas on met l'entrée dans le log comme étant -1 à la date de modification
        if (exists != 0) {
            printf("Fichier supprimé détecté : %s\n", current->path);
            FILE *log_file = fopen(logfile, "a"); 
            if (!log_file) {
                perror("Erreur lors de l'ouverture du fichier log");
                return;
            }
            fprintf(log_file, "%s;-1\n", current->path);
            fclose(log_file); 
        }
        current = current->next;
    }
}