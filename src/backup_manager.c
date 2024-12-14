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

// global_hash_table HASH_TABLE_SIZE à faire get_md5      write_log_element(path, mtime_str, md5_str, log);

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
        // Appeler la fonction pour effectuer une sauvegarde incrémentale ici
        // incr_backup(source_dir, backup_dir);  // La fonction incrémentale sera implémentée plus tard
    }
}

// Fonction permettant d'enregistrer dans fichier le tableau de chunk dédupliqué  
int write_backup_file(const char *output_filename, Chunk *chunks, int chunk_count) {

    /**  
     * @param output_filename est le fichier dans lequel on va sauvegarder
     * @param chunks est le tableau de chunk issu de deduplicate
     * @param chunk_count est le nombre de chunk du fichier
     */


    // Ouvrir le fichier de sauvegarde en écriture binaire
    FILE *output_file = fopen(output_filename, "wb");

    if (!output_file) {
        return 1;
    }

    // Parcourir chaque chunk et écrire son index dans le fichier
    for (int i=0; i<chunk_count; i++) {
        unsigned char *md5=chunks[i].md5;

        // Chercher l'indice dans la table de hashage globale
        int index=find_md5(global_hash_table, md5);

        // Écrire l'indice dans le fichier, suivi d'un saut de ligne (plus facile pour le restore)
        if (fprintf(output_file, "%d\n", index) < 0) {
            fclose(output_file);
            return 1;
        }
    fclose(output_file);
    return 0;
    }
}


// Fonction implémentant la logique pour la sauvegarde d'un fichier         
void backup_file(const char *filename) {
    /**
     * @param filename est le nom du fichier à sauvegarder
     */

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file for reading");
        return;
    }

    // Initalisation du tableau de chunk
    Chunk *chunks = malloc(sizeof(Chunk) * HASH_TABLE_SIZE);
    if (!chunks) {
        perror("Erreur d'allocation mémoire");
        fclose(file);
        return;
    }

    int chunk_count = 0;
    deduplicate_file(file, chunks, &chunk_count); // Le tableau de chunk contiendra tous les chunks du fichier (tableau temporaire local)
    fclose(file);

    // Créer le nom du fichier de sauvegarde
    char backup_filename[512];
    snprintf(backup_filename, sizeof(backup_filename), "%s.backup", filename);

    // Écriture dans le fichier de sauvegarde des indices des chunks
    if (write_backup_file(backup_filename, chunks, chunk_count) != 0) {
        fprintf(stderr, "Erreur dans la génération du fichier %s\n", backup_filename);
        // Free chunks si erreur
        for (int i=0; i<chunk_count; i++) {
            free(chunks[i].data);
        }
        free(chunks);
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
        struct utimbuf new_times;               // Struct utimbuf utilisé pour les timestamps
        new_times.actime = file_stat.st_atime;  // Heure d'accès
        new_times.modtime = file_stat.st_mtime; // Heure de modification
        utime(backup_filename, &new_times);
    } else {
        perror("Pas accès aux informations du fichier");
    }

    // Free chunks
    for (int i=0; i<chunk_count; i++) {
        free(chunks[i].data); 
    }
    free(chunks);
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
        if (entry->d_name[0] == '.') { // Ignorer les 
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
    char log_file[512];
    snprintf(log_file, sizeof(log_file), "%s/%s.backup_log", backup_dir, backup_name);
    generate_backup_log(source_dir, backup_name); 
}

// Fonction pour parcourir récursivement les répertoires et générer le log
void generate_backup_log(const char *source_dir, const char *backup_name, const char *log_file) {
    DIR *dir = opendir(source_dir);
    if (!dir) {
        perror("Erreur d'ouverture du répertoire");
        return;
    }

    struct dirent *entry;
    struct stat file_stat;

    // Ouvrir le fichier log en mode ajout
    FILE *log = fopen(log_file, "a");
    if (!log) {
        perror("Erreur d'ouverture du fichier log");
        closedir(dir);
        return;
    }

    // On parcours chaque entrée du répertoire
    while ((entry = readdir(dir)) != NULL) {
        // Ignorer les fichiers et répertoires commençant par "." et ".."
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

        // Si c'est un fichier, calculer le MD5 pour le mettre dans le log
        if (S_ISREG(file_stat.st_mode)) {
            unsigned char md5_str[MD5_DIGEST_LENGTH]; 
            get_md5(path, md5_str);                          
            write_log_element(path, mtime_str, md5_str, log);
        } else if (S_ISDIR(file_stat.st_mode)) {
            write_log_element(path, mtime_str, NULL, log);
            generate_backup_log(path, backup_name); // Appel récursif pour traiter les sous-répertoires
        }
    }
    // Fermer le fichier log et le répertoire
    fclose(log);
    closedir(dir);
}