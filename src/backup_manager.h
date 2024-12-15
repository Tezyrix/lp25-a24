#ifndef BACKUP_MANAGER_H
#define BACKUP_MANAGER_H

#include "deduplication.h"
#include "file_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <regex.h>

// Fonction pour créer un nouveau backup incrémental
void create_backup(const char *source_dir, const char *backup_dir);
// Fonction permettant d'enregistrer dans fichier le tableau de chunk dédupliqué
void write_backup_file(const char *output_filename, Chunk *chunks, int chunk_count);
// Fonction pour la sauvegarde de fichier dédupliqué
void backup_file(const char *filename);
// Fonction pour restaurer une sauvegarde
void restore_backup(const char *backup_id, const char *restore_dir);
// Fonction permettant la restauration du fichier backup via le tableau de chunk
void write_restored_file(const char *output_filename, Chunk *chunks, int chunk_count);
// Fonction permettant de lister les différentes sauvegardes présentes dans la destination
void list_backups(const char *backup_dir);
// Fonction pour vérifier si une sauvegarde existe dans le répertoire donné
int check_if_backup_exist(const char *backup_dir);
// Fonction pour générer le nom du directory backup
void generate_backup_name(char *backup_name);
// Fonction permettant de faire une copie complète par lien dur et génère le log
void full_backup(const char *source_dir, const char *backup_dir);
// Fonction pour parcourir récursivement les répertoires et générer le log
void generate_backup_log(const char *source_dir, const char *backup_name, const char *log_file);
// Fonction effectuant une sauvegarde incrémentale d'un directory en mettant également à jour les logs
void incremental_backup(const char *source_dir, const char *incremental_backup_dir, log_t *logs, const char *logfile);
// Fonction vérifiant qu'il n'y a pas de fichier en trop dans la backup par rapport à la source et met à jour les logs
void check_and_mark_deleted_files(const char *source_dir, log_t *logs, const char *logfile);

#endif // BACKUP_MANAGER_H


