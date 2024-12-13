#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include "file_handler.h"
#include "deduplication.h"
#include "backup_manager.h"
#include "network.h"

void print_usage() {
    printf("Usage: backup_tool [options]\n");
    printf("Options:\n");
    printf("--backup       : Effectue une sauvegarde incrémentale\n");
    printf("--restore      : Restaure une sauvegarde\n");
    printf("--list-backups : Liste les sauvegardes existantes\n");
    printf("--dry-run      : Test la sauvegarde ou la restauration sans modifications réelles\n");
    printf("--s-server     : Adresse IP du serveur source\n");
    printf("--d-server     : Adresse IP du serveur de destination\n");
    printf("--source       : Chemin du répertoire source\n");
    printf("--dest         : Chemin du répertoire de destination\n");
    printf("--verbose      : Affiche des informations détaillées\n");
}

int main(int argc, char *argv[]) {
    int option_index = 0;
    int backup_flag = 0, restore_flag = 0, list_flag = 0;
    char *source_dir = NULL, *dest_dir = NULL;
    char *s_server = NULL, *d_server = NULL;
    int dry_run = 0, verbose = 0;

    struct option long_options[] = {
        {"backup", no_argument, &backup_flag, 1},
        {"restore", no_argument, &restore_flag, 1},
        {"list-backups", no_argument, &list_flag, 1},
        {"dry-run", no_argument, &dry_run, 1},
        {"s-server", required_argument, NULL, 's'},
        {"d-server", required_argument, NULL, 'd'},
        {"source", required_argument, NULL, 'r'},
        {"dest", required_argument, NULL, 't'},
        {"verbose", no_argument, &verbose, 1},
        {0, 0, 0, 0}
    };

    // Parsing des arguments
    int opt;
    while ((opt = getopt_long(argc, argv, "s:d:r:t:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 's':
                s_server = optarg;
                break;
            case 'd':
                d_server = optarg;
                break;
            case 'r':
                source_dir = optarg;
                break;
            case 't':
                dest_dir = optarg;
                break;
            case '?':
                print_usage();
                return EXIT_FAILURE;
        }
    }

    // Vérification des options
    if (backup_flag && (restore_flag || list_flag)) {
        fprintf(stderr, "Erreur: --backup ne peut pas être utilisé avec --restore ou --list-backups\n");
        return EXIT_FAILURE;
    }

    if (restore_flag && (backup_flag || list_flag)) {
        fprintf(stderr, "Erreur: --restore ne peut pas être utilisé avec --backup ou --list-backups\n");
        return EXIT_FAILURE;
    }

    if (list_flag && (backup_flag || restore_flag)) {
        fprintf(stderr, "Erreur: --list-backups ne peut pas être utilisé avec --backup ou --restore\n");
        return EXIT_FAILURE;
    }

    /* Suggestion pour remplacer les 3 'if' ci-dessus:
    if ((restore_flag || list_flag) || (backup_flag || list_flag) || (backup_flag && restore_flag)) {
        fprintf(stderr, "Erreur: --list-backups, --backup et --restore ne peuvent pas être utilisés ensembles\n");
        return EXIT_FAILURE;
    }
    */

    if (!source_dir || !dest_dir) {
        fprintf(stderr, "Erreur: Les options --source et --dest sont obligatoires\n");
        return EXIT_FAILURE;
    }

    // Gestion des options
    if (backup_flag) {
        if (verbose) {
            printf("Démarrage de la sauvegarde incrémentale...\n");
        }

        if (dry_run) {
            printf("Mode dry-run: aucune sauvegarde réelle effectuée.\n");
        } else {
            create_backup(source_dir, dest_dir);
        }

    } else if (restore_flag) {
        if (verbose) {
            printf("Démarrage de la restauration...\n");
        }

        if (dry_run) {
            printf("Mode dry-run: aucune restauration réelle effectuée.\n");
        } else {
            restore_backup(source_dir, dest_dir);
        }

    } else if (list_flag) {
        if (verbose) {
            printf("Liste des sauvegardes...\n");
        }

        list_backups(dest_dir);

    } else {
        fprintf(stderr, "Erreur: Aucune option valide spécifiée. Utilisez --backup, --restore, ou --list-backups.\n");
        print_usage();
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
