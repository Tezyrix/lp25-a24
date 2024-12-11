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

// Fonction pour créer une nouvelle sauvegarde complète puis incrémentale
void create_backup(const char *source_dir, const char *backup_dir) {
    /* @param: source_dir est le chemin vers le répertoire à sauvegarder
    *          backup_dir est le chemin vers le répertoire de sauvegarde
    */
}

// Fonction permettant d'enregistrer dans fichier le tableau de chunk dédupliqué
void write_backup_file(const char *output_filename, Chunk *chunks, int chunk_count) {

}


// Fonction implémentant la logique pour la sauvegarde d'un fichier
void backup_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file for reading");
        return;
    }

    // Initialisation du tableau de chunk propre à chaque fichier
    Chunk *chunks = malloc(sizeof(Chunk) * HASH_TABLE_SIZE);
    if (!chunks) {
        perror("Erreur d'allocation mémoire");
        fclose(file);
        return;
    }

    // Initialiser une table de hachage pour stocker les MD5 des chunks uniques
    Md5Entry hash_table[HASH_TABLE_SIZE] = {0};

    // Dédupliquer le fichier
    int chunk_count = 0;
    deduplicate_file(file, chunks, hash_table, &chunk_count);

    fclose(file);

    // Générer un nom de fichier de sauvegarde avec snprintf en .backup
    char backup_filename[512];
    snprintf(backup_filename, sizeof(backup_filename), "%s.backup", filename);

    // Écrire le fichier de sauvegarde
    write_backup_file(backup_filename, chunks, chunk_count);

    // Récupérer la date et les droits du file avec stat
    struct stat file_stat;
    if (stat(filename, &file_stat) == 0) {
        // Modifier les droits d'accès du fichier de sauvegarde
        chmod(backup_filename, file_stat.st_mode);

        // Récupérer les dates d'accès et de modif du file et les stocker dans une nouvelle struct
        struct utimbuf new_times;
        new_times.actime = file_stat.st_atime;  // heure d'accès
        new_times.modtime = file_stat.st_mtime; // heure de modification
        utime(backup_filename, &new_times); // utime pour modifier ces dates
    } else {
        perror("Erreur dans la récupération des informations du fichier");
    }

    // free chaque data dans le tableau de chunk
    for (int i = 0; i < chunk_count; i++) {
        free(chunks[i].data); // Libérer les données de chaque chunk
    }
    free(chunks);

    printf("Backup faite pour: %s\n", filename);
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