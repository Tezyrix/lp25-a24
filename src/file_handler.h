
#ifndef FILE_HANDLER_H
#define FILE_HANDLER_H

#include <stdio.h>
#include <openssl/md5.h>

// Structure pour une ligne du fichier log
typedef struct log_element{
    const char *path; // Chemin du fichier/dossier
    unsigned char md5[MD5_DIGEST_LENGTH]; // MD5 du fichier dédupliqué
    char *date; // Date de dernière modification
    struct log_element *next;
    struct log_element *prev;
} log_element;

// Structure pour une liste de log représentant le contenu du fichier backup_log
typedef struct {
    log_element *head; // Début de la liste de log
    log_element *tail; // Fin de la liste de log
} log_t;


log_t read_backup_log(const char *logfile);
void update_backup_log(const char *logfile, log_t *logs);
void write_log_element(FILE *log, const char *basename, const char *mtime_str);
void list_files(const char *path);
void copy_file(const char *src, const char *dest);
int compare_file_with_backup_log(const char *path, log_t *logs, const char *backup_name, const char *logfile);

/**
 * @brief Génère un fichier de log après une sauvegarde.
 *
 * Cette fonction crée un fichier de log retraçant les informations de la sauvegarde réalisée.
 * Elle enregistre les détails concernant le répertoire source et la destination de la sauvegarde.
 *
 * @param source_dir Le répertoire source de la sauvegarde.
 * @param backup_dir Le répertoire de destination où la sauvegarde a été effectuée.
 */
void generate_backup_log(const char *source_dir, const char *basename, FILE *log);
void display_logs(const log_t *logs);

#endif // FILE_HANDLER_H
