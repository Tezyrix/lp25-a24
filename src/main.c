#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "file_handler.h"
#include "deduplication.h"
#include "backup_manager.h"
#include "network.h"

void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("Options:\n");
    printf("  --backup <source> <destination>    Create a backup\n");
    printf("  --restore <backup_id> <destination> Restore a backup\n");
    printf("  --list <backup_directory>         List available backups\n");
    printf("  --send <server> <port> <file>     Send backup to server\n");
    printf("  --receive <port>                  Receive backup from server\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    static struct option long_options[] = {
        {"backup", required_argument, 0, 'b'},
        {"restore", required_argument, 0, 'r'},
        {"list", required_argument, 0, 'l'},
        {"send", required_argument, 0, 's'},
        {"receive", required_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;
    while ((c = getopt_long(argc, argv, "b:r:l:s:v:", long_options, &option_index)) != -1) {
        switch (c) {
            case 'b': {
                if (optind + 1 >= argc) {
                    fprintf(stderr, "Error: Missing arguments for --backup\n");
                    return EXIT_FAILURE;
                }
                create_backup(optarg, argv[optind]);
                break;
            }
            case 'r': {
                if (optind >= argc) {
                    fprintf(stderr, "Error: Missing arguments for --restore\n");
                    return EXIT_FAILURE;
                }
                restore_backup(optarg, argv[optind]);
                break;
            }
            case 'l': {
                list_backups(optarg);
                break;
            }
            case 's': {
                if (optind + 1 >= argc) {
                    fprintf(stderr, "Error: Missing arguments for --send\n");
                    return EXIT_FAILURE;
                }
                send_data(optarg, atoi(argv[optind]), argv[optind + 1], strlen(argv[optind + 1]));
                break;
            }
            case 'v': {
                receive_data(atoi(optarg), NULL, NULL);
                break;
            }
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
