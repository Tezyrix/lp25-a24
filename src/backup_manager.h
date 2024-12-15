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
#include <unistd.h>
#include <openssl/md5.h>

/**
 * @brief Crée une sauvegarde complète puis incrémentale.
 *
 * Sauvegarde le répertoire source dans le répertoire de sauvegarde, en effectuant une première sauvegarde complète,
 * suivie d'une sauvegarde incrémentale pour les modifications.
 *
 * @param source_dir Le chemin vers le répertoire à sauvegarder.
 * @param backup_dir Le chemin vers le répertoire de sauvegarde.
 */
void create_backup(const char *source_dir, const char *backup_dir);

/**
 * @brief Vérifie si une sauvegarde existe dans le répertoire spécifié.
 *
 * Vérifie la présence d'une sauvegarde dans le répertoire `backup_dir`.
 * La fonction renvoie 1 si une sauvegarde existe, sinon 0.
 *
 * @param backup_dir Le chemin vers le répertoire de sauvegarde à vérifier.
 * @return 1 si une sauvegarde existe, 0 sinon.
 */
int check_if_backup_exist(const char *backup_dir);

/**
 * @brief Effectue une copie complète d'un répertoire par lien dur et génère le log.
 *
 * Cette fonction copie tous les fichiers du répertoire `source_dir` vers `backup_dir` en utilisant des liens durs
 * pour ne pas dupliquer l'espace disque. Elle génère également un log des fichiers copiés.
 *
 * @param source_dir Le chemin du répertoire source à copier.
 * @param backup_dir Le chemin du répertoire de destination pour la sauvegarde.
 */
void full_backup(const char *source_dir, const char *backup_dir);

/**
 * @brief Crée une sauvegarde d'un fichier en le renommant avec l'extension `.backup` et en le dédupliquant.
 *
 * Cette fonction prend un fichier spécifié par `filename` et crée une copie de celui-ci
 * en lui ajoutant l'extension `.backup` dans le même répertoire.
 *
 * @param filename Le nom du fichier à sauvegarder.
 */
void backup_file(const char *filename);

/**
 * @brief Enregistre les indices des chunks dédupliqués dans un fichier.
 *
 * Cette fonction écrit dans le fichier spécifié par `output_filename` les indices des chunks
 * dédupliqués (représentés par `chunk_indices`), ainsi que leur nombre `chunk_count`.
 *
 * @param output_filename Le fichier dans lequel les indices des chunks seront sauvegardés.
 * @param chunk_indices Un tableau contenant les indices des chunks dédupliqués.
 * @param chunk_count Le nombre d'indices présents dans le tableau `chunk_indices`.
 * @return Retourne 0 si l'enregistrement est réussi, sinon une valeur non nulle en cas d'erreur.
 */
int write_backup_file(const char *output_filename, int *chunk_indices, int chunk_count);

/**
 * @brief Génère un nom de répertoire pour la sauvegarde.
 *
 * Cette fonction crée un nom unique pour le répertoire de sauvegarde basé sur la date et l'heure actuelles.
 * Le nom est enregistré dans le paramètre `backup_name`.
 *
 * @param backup_name Le tableau de caractères où le nom du répertoire de sauvegarde sera écrit.
 */
void generate_backup_name(char *backup_name);

/**
 * @brief Effectue une sauvegarde incrémentale d'un répertoire en enregistrant les fichiers modifiés ou ajoutés,
 *        et en mettant à jour les logs de sauvegarde.
 *
 * @param source_dir Le répertoire source à sauvegarder.
 * @param incremental_backup_dir Le répertoire dans lequel les fichiers modifiés ou ajoutés seront sauvegardés.
 * @param logs La liste chainée représentant les logs des sauvegardes.
 * @param logfile Le fichier log où seront enregistrées les entrées de la sauvegarde.
 */
void incremental_backup(const char *source_dir, const char *incremental_backup_dir, log_t *logs, const char *logfile);

/**
 * @brief Vérifie qu'il n'y a pas de fichier en trop dans la sauvegarde par rapport à la source et met à jour les logs.
 *
 * @param source_dir Le répertoire source à laquelle on va comparer les fichiers présents dans les logs.
 * @param logs La liste chainée représentant les logs des sauvegardes effectuées.
 * @param logfile Le fichier log où seront enregistrées les modifications effectuées lors de la vérification.
 */
void check_and_mark_deleted_files(const char *source_dir, log_t *logs, const char *logfile);

/**
 * @brief Restaure une sauvegarde à une date donnée en reconstruisant petit à petit le dossier à partir du log.
 *
 * Cette fonction permet de restaurer un répertoire en utilisant les logs de sauvegarde et les différentes sauvegardes incrémentales.
 * Elle reconstruit l'état du répertoire à la date spécifiée dans le paramètre `restore_date_str`.
 *
 * @param backup_dir Le répertoire contenant la sauvegarde complète, le fichier log et les sauvegardes incrémentales.
 * @param destination_dir Le répertoire où la sauvegarde restaurée sera placée.
 * @param restore_date_str La date à laquelle la restauration doit être effectuée, sous forme de chaîne de caractères.
 */
void restore_backup(const char *backup_dir, const char *destination_dir, const char *restore_date_str);

/**
 * @brief Restaure un fichier depuis la sauvegarde en fonction des informations du log.
 *
 * Cette fonction décide de la façon de restaurer un fichier spécifique à partir du log,
 * en se basant sur son chemin, sa date de modification et son hash MD5 pour vérifier
 * si le fichier/dossier doit être supprimé/modifié/ajouté
 *
 * @param backup_dir Le répertoire contenant la sauvegarde complète, le fichier log complet de toutes les sauvegardes,
 *                   ainsi que les sauvegardes incrémentales.
 * @param destination_dir Le répertoire où le fichier restauré sera placé.
 * @param file_path Le chemin du fichier à restaurer.
 * @param mtime La date de modification du fichier à appliquer lors de la restauration.
 * @param md5 Le hash MD5 du fichier d'origine.
 */
void restore_file_from_backup(const char *backup_dir, const char *destination_dir, const char *file_path, time_t mtime, unsigned char *md5);

/**
 * @brief Génère un fichier restauré à partir d'une sauvegarde.
 *
 * Cette fonction prend en entrée le nom d'un fichier de sauvegarde et génère le fichier restauré dans le répertoire de destination.
 *
 * @param backup_filename Le chemin du fichier de sauvegarde à partir duquel le fichier restauré sera généré.
 */
void write_restored_file(const char *backup_filename);

/**
 * @brief Liste les différentes sauvegardes présentes dans un répertoire.
 *
 * Cette fonction permet de parcourir le répertoire spécifié pour lister toutes les sauvegardes disponibles.
 * Elle affiche les répertoires et fichiers de sauvegarde (complètes et incrémentales) afin de fournir un aperçu
 * des données disponibles pour la restauration.
 *
 * @param backup_dir Le répertoire contenant les sauvegardes à lister.
 */
void list_backups(const char *backup_dir);


#endif // BACKUP_MANAGER_H


