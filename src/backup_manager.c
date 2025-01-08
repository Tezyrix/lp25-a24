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
#include <unistd.h>
#include <openssl/md5.h>
#include <libgen.h>

/**
 * @brief Explication du système de sauvegarde et de restauration.
 *
 * Le répertoire de sauvegarde (`backup_dir`) contient :
 * - Un répertoire contenant la sauvegarde complète (full backup) par hard link.
 * - Un fichier de log retraçant toutes les sauvegardes.
 * - Les tables globales utilisées dans le programme principal.
 * - Des répertoires des sauvegardes incrémentales, chacun contenant des fichiers/dossiers modifiés ou ajoutés
 *   sous forme dédupliquée, permettant de prendre moins de place.
 *
 * La sauvegarde complète (full backup) ne prend aucun espace supplémentaire puisqu'elle est réalisée via des hard links.
 * Le log est un fichier texte léger qui enregistre les informations relatives aux sauvegardes.
 * Les répertoires des sauvegardes incrémentales contiennent uniquement des fichiers dédupliqués, qui sont très légers. Ces fichiers contiennent des indices de chunk.
 * Les tables globales sont les seuls éléments à contenir des données réelles. Elles stockent les informations de tous les chunks dédupliqués.
 *
 * Lors de la restauration, on récupère simplement les informations du log jusqu'à une date donnée, et on reconstruit progressivement le répertoire.
 * A noter qu'il n'y a pas de comparaison avec la source pendant la restauration. Ce système permet donc de maintenir plusieurs sauvegardes à différentes dates et de pouvoir restaurer à chacune de ces dates.
 *
 * Ce mécanisme est particulièrement adapté pour la sauvegarde et la restauration de répertoires légers qui sont fréquemment modifiés. Il permet également de restaurer à des dates antérieures.
 *
 * @note Points à améliorer :
 * - Bien qu'il y ait une table de hashage, on n'utilise pas réellement le hashage, cela pourrait permettre de parcourir les tables bien
 *   plus facilement.
 * - Dans le log on n'inscrit pas le md5 du fichier dédupliqué mais celui du fichier d'origine
 */

/**
    // Générer le fichier de log après la sauvegarde
    // Créer le nom du fichier log : backup_dir.backup_log

    // Créer le nom du fichier log basé sur le nom du répertoire de sauvegarde
    char log_file[512];
    
    // Utiliser basename pour obtenir uniquement le nom du répertoire, sans le chemin complet
    char backup_dir_name[512];
    strncpy(backup_dir_name, source_dir, sizeof(backup_dir_name));

    // Récupérer le nom du répertoire de sauvegarde (basename)
    char *dir_name = basename(backup_dir_name);  // dir_name contient le nom du dossier final
    
    // Créer le fichier log dans le répertoire de sauvegarde
    snprintf(log_file, sizeof(log_file), "%s%s.backup_log", backup_dir, dir_name);

    // Ouvrir le fichier log en mode append
    FILE *log = fopen(log_file, "a");
    if (!log) {
        perror("Erreur d'ouverture du fichier log");
        return;
    }

    // Générer le fichier de log après la sauvegarde
    generate_backup_log(source_dir, backup_path, log);
 */




void create_backup(const char *source_dir, const char *backup_dir) {

    // Si aucune backup n'existe, faire une sauvegarde complète
    if (!check_if_backup_exist(backup_dir)) {
        printf("Pas de backup trouvé, sauvegarde complète...\n");
        char backup_name[256];
        generate_backup_name(backup_name); // Générer le nom de la backup

        // Créer le répertoire de sauvegarde dans backup_dir
        char backup_path[512];
        snprintf(backup_path, sizeof(backup_path), "%s%s", backup_dir, backup_name);

        // Créer le répertoire de sauvegarde
        if (mkdir(backup_path, 0755) == -1) {
            perror("Erreur lors de la création du répertoire de sauvegarde");
            return;
        }
        // Effectuer la sauvegarde complète
        full_backup(source_dir, backup_path);

       
       char log_file[512];
        // Dupliquer source_dir pour éviter modification de l'original
        char *source_dir_copy = strdup(source_dir);
        if (!source_dir_copy) {
            perror("Erreur de duplication de source_dir");
            return;
        }

        // Utiliser basename sur la copie de source_dir
        char *source_name = basename(source_dir_copy);

        // Générer le chemin du fichier de log dans backup_dir
        snprintf(log_file, sizeof(log_file), "%s/%s.backup_log", backup_dir, source_name);

        // Libérer la mémoire allouée pour la copie
        free(source_dir_copy);

        // Ouvrir le fichier de log en mode ajout
        FILE *log = fopen(log_file, "a");
        if (!log) {
            perror("Erreur d'ouverture du fichier log");
            return;
        }
  
        // Générer le contenu du log après la sauvegarde

         char *base_name = basename(backup_path);
        generate_backup_log(backup_path,base_name, log); // Appeler la fonction pour générer le log

        // Fermer le fichier de log
        fclose(log);
    } else {
        // Si une sauvegarde existe déjà, effectuer une sauvegarde incrémentale
        printf("Backup trouvé, on effectue une sauvegarde incrémentale\n");
        // Générer le nom du répertoire pour la #include <libgen.h>sauvegarde incrémentale
        char incremental_backup_name[256];
        generate_backup_name(incremental_backup_name);

        // Créer un répertoire pour la sauvegarde incrémentale
        char incremental_backup_path[512];
        snprintf(incremental_backup_path, sizeof(incremental_backup_path), "%s%s", backup_dir, incremental_backup_name);
        mkdir(incremental_backup_path, 0755);

        // Les logs sont déjà supposés être présents dans le répertoire de sauvegarde sous le nom backup_dir.backup_log on génere le path à celui ci
        char log_file[512];
        snprintf(log_file, sizeof(log_file), "%s%s.backup_log", backup_dir,basename(source_dir));
        log_t log_chain = read_backup_log(log_file);
        
        // Effectuer une sauvegarde incrémentale
        incremental_backup(source_dir, incremental_backup_path, &log_chain, log_file);
        }
}


int check_if_backup_exist(const char *backup_dir) {

    DIR *dir = opendir(backup_dir);
    if (!dir) {
        perror("opendir");
        return 0;
    }
    struct dirent *entry;
    regex_t regex;

    // Compile la regex au format pour qu'elle soit utilisable
    if (regcomp(&regex, "^[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}$", REG_EXTENDED) != 0) {

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


        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", backup_dir, entry->d_name);
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) { // Vérifie si c'est un répertoire
            if (regexec(&regex, entry->d_name, 0, NULL, 0) == 0) {
                regfree(&regex);
                closedir(dir);
                return 1; // Succès
            }
        }
    }
    regfree(&regex); // Libérer la mémoire de la regex
    closedir(dir);   // Fermer le répertoire
    return 0;        // Aucune sauvegarde trouvée, retour 0
}


void full_backup(const char *source_dir, const char *backup_dir) {
    // Ouvrir le répertoire source
    DIR *source = opendir(source_dir);
    if (!source) {
        perror("Erreur d'ouverture du répertoire source");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(source)) != NULL) {
        // Ignorer les fichiers et répertoires cachés (commençant par ".")
        if (entry->d_name[0] == '.') {
            continue;
        }

        char source_path[512], backup_file_path[512];
        snprintf(source_path, sizeof(source_path), "%s/%s", source_dir, entry->d_name);
        snprintf(backup_file_path, sizeof(backup_file_path), "%s/%s", backup_dir, entry->d_name);

        struct stat file_stat;
        stat(source_path, &file_stat);

        // Vérification du type de fichier avec d_type
        if (S_ISDIR(file_stat.st_mode)) {
            // Si c'est un répertoire, on crée un répertoire de sauvegarde
            mkdir(backup_file_path, 0755);
            // Appel récursif pour traiter les sous-répertoires
            full_backup(source_path, backup_file_path);
        } else if (S_ISREG(file_stat.st_mode)) {
            // Sinon, c'est un fichier, on fait un lien dur
            link(source_path, backup_file_path);
        }
    }

    closedir(source);
}


void backup_file(const char *filename) {

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
    deduplicate_file(filename, chunk_indices, &chunk_count);
    fclose(file);

    // Obtenir les informations du fichier source pour les timestamps
    struct stat file_stat;
    if (stat(filename, &file_stat) != 0) {
        perror("Erreur lors de l'obtention des informations du fichier");
        free(chunk_indices);
        return;
    }

    // Créer le nom du fichier de sauvegarde
    char backup_filename[512];
    snprintf(backup_filename, sizeof(backup_filename), "%s.backup", filename);

    // Écrire les indices dans le fichier de sauvegarde
    if (write_backup_file(backup_filename, chunk_indices, chunk_count) != 0) {
        fprintf(stderr, "Erreur dans la génération du fichier %s\n", backup_filename);
        free(chunk_indices);
        return;
    }

    // Modifier les dates d'accès et de modification
    struct timespec new_times[2];
    new_times[0].tv_sec = file_stat.st_atime;  // Heure d'accès
    new_times[0].tv_nsec = 0;  // Nanosecondes (optionnel)
    new_times[1].tv_sec = file_stat.st_mtime;  // Heure de modification
    new_times[1].tv_nsec = 0;  // Nanosecondes (optionnel)

    // Appliquer les nouveaux temps à backup_filename
    if (utimensat(0, backup_filename, new_times, 0) != 0) {
        perror("Erreur lors de la mise à jour des timestamps");
    }

    // Libérer la mémoire allouée pour les indices
    free(chunk_indices);

    printf("%s done\n", filename);
}



int write_backup_file(const char *output_filename, int *chunk_indices, int chunk_count) {

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


void generate_backup_name(char *backup_name) {

    struct timeval tv;
    gettimeofday(&tv, NULL);                    // Récupérer le temps actuel puis on le formate avec localtime
    struct tm *tm_info = localtime(&tv.tv_sec); // On traite les millisecondes à part en utilisant la structure tm

    // Formater le nom de la sauvegarde avec la date et l'heure
    strftime(backup_name, 20, "%Y-%m-%d-%H:%M:%S", tm_info);

    // Ajouter les millisecondes
    snprintf(backup_name + 19, 5, ".%03ld", tv.tv_usec / 1000); // tv_usec est en microsecondes, donc on divise par 1000 pour obtenir les millisecondes
}


void incremental_backup(const char *source_dir, const char *incremental_backup_dir, log_t *logs, const char *logfile) {

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
        snprintf(backup_file_path, sizeof(backup_file_path), "%s%s", incremental_backup_dir, entry->d_name);
        

        struct stat file_stat;
        stat(source_path, &file_stat);

        if (S_ISREG(file_stat.st_mode)) {
        // Comparer le fichier avec le log
            
            if (compare_file_with_backup_log(source_path, logs, incremental_backup_dir, logfile)) {
                // Si le fichier est nouveau ou modifié, effectuer une sauvegarde
                printf("backup\n");

                
            }
        } else{
             if (S_ISDIR(file_stat.st_mode)) {
            // Si c'est un répertoire, on compare avec les logs
            if (compare_file_with_backup_log(source_path , logs, incremental_backup_dir, logfile)) {
                // Utiliser directement incremental_backup_dir pour créer le répertoire
                char backup_file_path[PATH_MAX];
              
                snprintf(backup_file_path, sizeof(backup_file_path), "%s/%s", incremental_backup_dir, basename(source_path));
                
                // Créer le répertoire dans le répertoire de sauvegarde incrémental
                if (mkdir(backup_file_path, 0755) == 0) {
                    printf("Le répertoire %s a été créé dans %s\n", basename(source_path), incremental_backup_dir);
                } else {
                    perror("Erreur lors de la création du répertoire");
                }
            }


            }
        }

    }
    closedir(source);
    // Vérifier les fichiers supprimés dans la source et mettre à jour le log
    //check_and_mark_deleted_files(source_dir, logs, logfile);
}


void check_and_mark_deleted_files(const char *source_dir, log_t *logs, const char *logfile) {

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
            fprintf(log_file, "%s;-1;0\n", current->path);   
            fclose(log_file); 
        }
        current = current->next;
    }
}


void restore_backup(const char *backup_dir, const char *destination_dir, const char *restore_date_str) {

    // Construire le chemin du fichier log
    char log_file_path[512];
    snprintf(log_file_path, sizeof(log_file_path), "%s/%s.backup_log", backup_dir, backup_dir);

    // Ouvrir le fichier log en mode lecture
    FILE *log_file = fopen(log_file_path, "r");
    if (!log_file) {
        perror("Erreur lors de l'ouverture du fichier log");
        return; // Si le fichier log ne peut pas être ouvert, on arrête la fonction.
    }

    // Convertir la date de restauration en struct tm
    struct tm restore_tm;
    memset(&restore_tm, 0, sizeof(struct tm));
    strptime(restore_date_str, "%Y-%m-%d-%H:%M:%S", &restore_tm);
    time_t restore_time = mktime(&restore_tm);

    // Lire chaque ligne du log
    char line[1024];
    while (fgets(line, sizeof(line), log_file)) {
        // Extraire la date de la ligne
        char date_str[24];              // Format YYYY-MM-DD-hh:mm:ss.sss
        sscanf(line, "%23s", date_str); // On prend seulement les premiers 23 caractères

        // Convertir la date de la ligne en struct tm
        struct tm log_tm;
        memset(&log_tm, 0, sizeof(struct tm));
        strptime(date_str, "%Y-%m-%d-%H:%M:%S", &log_tm);
        time_t log_time = mktime(&log_tm);

        // Comparer les dates
        if (log_time > restore_time) {
            // Si la date dans le log est supérieure à la date de restauration, on arrête
            break;
        }
        // Extraire les informations restantes de la ligne : path, mtime, md5
        char file_path[512];
        time_t mtime;
        unsigned char md5[MD5_DIGEST_LENGTH];
        int md5_found = sscanf(line + 24, "%511s;%ld;%32s", file_path, &mtime, md5);

        // Si md5_found == 3, on a bien récupéré le md5
        if (md5_found == 3) {
            // Restauration du fichier
            restore_file_from_backup(backup_dir, destination_dir, file_path, mtime, md5);
        }
    }

    // Fermer le fichier log
    fclose(log_file);
}


void restore_file_from_backup(const char *backup_dir, const char *destination_dir, const char *file_path, time_t mtime, unsigned char *md5) {

    // Si mtime == -1, il faut supprimer le fichier ou dossier
    if (mtime == -1) {
        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s/%s", destination_dir, file_path);
        struct stat statbuf;
        if (stat(full_path, &statbuf) == 0) {
            if (S_ISREG(statbuf.st_mode)) {
                remove(full_path);
            } else if (S_ISDIR(statbuf.st_mode)) {
                rmdir(full_path);
            }
        }
    } else if (mtime == 0) { // c'est un dossier à créer
        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s/%s", destination_dir, file_path);
        mkdir(full_path, 0755);
    } else if (mtime > 0 && md5 != NULL) { // Si mtime > 0, restaurer un fichier 
        // Construire le chemin complet du fichier .backup dans le backup_dir
        char backup_file_path[512];
        snprintf(backup_file_path, sizeof(backup_file_path), "%s/%s.backup", backup_dir, file_path);

        // Appeler la fonction write_restored_file pour générer le fichier restauré
        // Ce fichier sera écrit temporairement dans le répertoire de destination
        write_restored_file(backup_file_path);

        // Construire le chemin complet pour déplacer le fichier restauré
        char restored_file_path[512];
        snprintf(restored_file_path, sizeof(restored_file_path), "%s/%s", destination_dir, file_path);

        // Déplacer le fichier temporaire vers sa destination finale, écrasant si nécessaire
        if (rename(backup_file_path, restored_file_path) == 0) {
            printf("Fichier restauré depuis le backup : %s\n", restored_file_path);
            // On réapplique le mtime
            struct timespec new_times[2];  // Utiliser struct timespec
            new_times[0].tv_sec = mtime;
            new_times[0].tv_nsec = 0;
            new_times[1].tv_sec = mtime;
            new_times[1].tv_nsec = 0;

            // Appliquer les nouveaux timestamps au fichier restauré
            if (utimensat(0, restored_file_path, new_times, 0) != 0) {
                perror("Erreur lors de la mise à jour des timestamps");
            }
        } else {
            perror("Erreur lors du déplacement du fichier restauré");
        }
    }
}

void write_restored_file(const char *backup_filename) {

    // Construire le nom du fichier de sortie (enlever l'extension .backup)
    char output_filename[1024];
    strncpy(output_filename, backup_filename, strlen(backup_filename) - 7); // Enlever ".backup"
    output_filename[strlen(backup_filename) - 7] = '\0';                    // Terminer la chaîne de caractères

    // Utiliser la fonction undeduplicate pour restaurer le fichier
    undeduplicate(backup_filename, output_filename);
}


void list_backups(const char *backup_dir) {

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

