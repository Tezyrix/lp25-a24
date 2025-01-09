#include "deduplication.h"



// deduplication.c
Md5Entry *global_hash_table = NULL;
Chunk *global_chunks = NULL;
FILE *global_hash_file = NULL, *global_chunk_file = NULL;


unsigned int hash_md5(unsigned char *md5) {
    unsigned int hash = 0;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        hash = (hash << 5) + hash + md5[i];
    }
    return hash % HASH_TABLE_SIZE;
}

/**
 * @brief Système de déduplication.
 *
 * - **Tables Globales** : Stocke les chunks dédupliqués uniques (identifiés par MD5). Elles sont initialisées au début et fermées à la fin.
 * - **Déduplication** : Les fichiers sont découpés en chunks, et seuls les chunks uniques sont ajoutés aux tables globales.
 * - **Calcul MD5** : Chaque chunk et fichier ont un hash MD5 unique permettant de vérifier les doublons.
 * - **Restauration** : Les fichiers peuvent être reconstruits à partir des indices en effectuant l'inverse de la déduplication.
 * 
 * Ce système permet de sauvegarder efficacement, tout en réduisant l'espace utilisé grâce à la gestion des chunks.
 */

void initialize_global_tables() {
    // Allocation de mémoire pour les tables globales
    global_hash_table = malloc(sizeof(Md5Entry) * HASH_TABLE_SIZE);
    global_chunks = malloc(sizeof(Chunk) * HASH_TABLE_SIZE);

    if (!global_hash_table || !global_chunks) {
        perror("Erreur d'allocation de mémoire pour les tables globales");
        exit(1);
    }

    // Essayer d'ouvrir les fichiers en mode lecture/écriture
    FILE *hash_file = fopen("hash_table.dat", "r+b");
    FILE *chunk_file = fopen("chunk_table.dat", "r+b");

    if (hash_file && chunk_file) {
        // Les fichiers existent : charger les données
        size_t hash_read = fread(global_hash_table, sizeof(Md5Entry), HASH_TABLE_SIZE, hash_file);
        size_t chunk_read = fread(global_chunks, sizeof(Chunk), HASH_TABLE_SIZE, chunk_file);

        // Vérification si la lecture a échoué
        if (hash_read != HASH_TABLE_SIZE || chunk_read != HASH_TABLE_SIZE) {
            printf("Erreur de lecture des fichiers de tables. Certaines données peuvent être manquantes.\n");
        }

        printf("Tables globales chargées depuis les fichiers existants.\n");
    } else {
        // Les fichiers n'existent pas : les créer et initialiser à vide
        printf("Fichiers de tables non trouvés. Réinitialisation...\n");

        // Si les fichiers sont manquants, les ouvrir en mode écriture pour les créer
        if (!hash_file)
            hash_file = fopen("hash_table.dat", "w+b");
        if (!chunk_file)
            chunk_file = fopen("chunk_table.dat", "w+b");

        if (!hash_file || !chunk_file) {
            perror("Erreur : Impossible de créer les fichiers de tables globales");
            exit(1);
        }

        // Initialiser les tables globales à -1 pour chaque index
        for (int i = 0; i < HASH_TABLE_SIZE; i++) {
            global_hash_table[i].index = -1;  // Initialisation à -1 pour indiquer un slot libre
            global_chunks[i].data = NULL;     // Pas de chunk de données pour commencer
        }

        // Écrire les tables initialisées dans les fichiers
        fwrite(global_hash_table, sizeof(Md5Entry), HASH_TABLE_SIZE, hash_file);
        fwrite(global_chunks, sizeof(Chunk), HASH_TABLE_SIZE, chunk_file);
        printf("Tables globales initialisées et écrites dans les fichiers.\n");
    }

    // Garder les fichiers ouverts dans des pointeurs globaux
    global_hash_file = hash_file;
    global_chunk_file = chunk_file;
}


void save_global_tables_to_files() {
    if (global_hash_file && global_chunk_file) {
        // Sauvegarder global_hash_table dans le fichier
        fseek(global_hash_file, 0, SEEK_SET);  // Remettre le curseur au début du fichier
        fwrite(global_hash_table, sizeof(Md5Entry), HASH_TABLE_SIZE, global_hash_file);

        // Sauvegarder global_chunks dans le fichier
        fseek(global_chunk_file, 0, SEEK_SET);  // Remettre le curseur au début du fichier
        fwrite(global_chunks, sizeof(Chunk), HASH_TABLE_SIZE, global_chunk_file);
    } else {
        printf("Erreur: Les fichiers ne sont pas ouverts.\n");
    }
}


void add_to_global_tables(void *data, unsigned char *md5) {
    int chunk_index = -1;
    int last_index = -1;

    // Vérifier si le MD5 est déjà présent dans la table de hachage
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        // Si le MD5 existe déjà dans la table, ne rien faire
        if (global_hash_table[i].index != -1 && memcmp(global_hash_table[i].md5, md5, MD5_DIGEST_LENGTH) == 0) {
            return;
        }

        // Trouver le dernier indice utilisé (non -1)
        if (global_hash_table[i].index != -1) {
            last_index = i;
        }
    }

    // Calculer le nouvel index
    chunk_index = (last_index == -1) ? 0 : last_index + 1;

    // Ajouter le MD5 dans la table de hachage avec le nouvel index
    global_hash_table[chunk_index].index = chunk_index;
    memcpy(global_hash_table[chunk_index].md5, md5, MD5_DIGEST_LENGTH);

    // Ajouter le chunk dans la table des chunks avec le même indice
    global_chunks[chunk_index].data = malloc(CHUNK_SIZE);
    if (global_chunks[chunk_index].data == NULL) {
        perror("Erreur d'allocation mémoire pour le chunk");
        return;
    }
    memcpy(global_chunks[chunk_index].data, data, CHUNK_SIZE);
    memcpy(global_chunks[chunk_index].md5, md5, MD5_DIGEST_LENGTH*2+1);

    // Sauvegarder les tables dans les fichiers après l'ajout
    save_global_tables_to_files();
}


void close_global_tables() {
    if (global_hash_file) {
        fclose(global_hash_file);
        global_hash_file = NULL;
    }
    if (global_chunk_file) {
        fclose(global_chunk_file);
        global_chunk_file = NULL;
    }
}

void deduplicate_file(const char *file_path, int *chunk_indices, int *chunk_count) {
    FILE *file = fopen(file_path, "rb");
    if (file == NULL) {
        return; // Si le fichier n'est pas ouvert, on ne fait rien
    }

    unsigned char buffer[CHUNK_SIZE];     // Buffer pour stocker un chunk
    unsigned char md5[MD5_DIGEST_LENGTH]; // MD5 du chunk

    while (1) {
        // Lire un chunk du fichier
        size_t bytes_read = fread(buffer, 1, CHUNK_SIZE, file);
        if (bytes_read == 0) {
            break; // Fin du fichier
        }

        // Calculer le MD5 du chunk lu
        compute_md5(buffer, md5);

        // Ajouter le chunk dans la table globale (il ne sera ajouté que si c'est un nouveau chunk)
        add_to_global_tables(buffer, md5);

        // Trouver l'indice du chunk dans la table globale
        int index = find_md5(global_hash_table, md5);

        // Ajouter l'indice du chunk au tableau
        chunk_indices[*chunk_count] = index;
        (*chunk_count)++;
    }

    fclose(file);
}



// Fonction pour calculer le MD5 d'un chunk et le convertir en chaîne hexadécimale
void compute_md5(unsigned char *data, char *md5_hex) {
    MD5_CTX context;          // Structure pour l'état de calcul du MD5
    MD5_Init(&context);       // Initialiser le contexte
    
    // Calculer le MD5 du chunk
    MD5_Update(&context, data, CHUNK_SIZE);
    
    unsigned char md5[MD5_DIGEST_LENGTH];    // Tableau pour stocker le résultat MD5 binaire
    MD5_Final(md5, &context); // Finaliser le calcul MD5
    
    // Convertir le résultat binaire en chaîne hexadécimale
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        // Format hexadécimal à deux chiffres, puis copie dans md5_hex
        sprintf(&md5_hex[i * 2], "%02x", md5[i]);
    }
}



int find_md5(Md5Entry *hash_table, unsigned char *md5) {
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        if (memcmp(hash_table[i].md5, md5, MD5_DIGEST_LENGTH) == 0) {
            return hash_table[i].index;
        }
    }
    return -1;
}



void undeduplicate(const char *input_filename, const char *output_filename) {

    FILE *input_file = fopen(input_filename, "r");
    FILE *output_file = fopen(output_filename, "wb");

    if (!input_file) {
        perror("Erreur lors de l'ouverture du fichier d'entrée");
        return;
    }
    if (!output_file) {
        perror("Erreur lors de l'ouverture du fichier de sortie");
        fclose(input_file);
        return;
    }

    char line[1024]; // Pour lire chaque ligne du fichier d'entrée

    // Récuperer l'index à chaque ligne
    while (fgets(line, sizeof(line), input_file)) {
        int index;
        sscanf(line, "%d", &index); 

        // Récuperer le chunk associé
        Chunk chunk_out;
        get_chunk_from_index(index, &chunk_out);

        fwrite(chunk_out.data, 1, CHUNK_SIZE, output_file); // Écrire le chunk dans le fichier
    }

    // Fermer les fichiers après traitement
    fclose(input_file);
    fclose(output_file);
}


void get_chunk_from_index(int index, Chunk *chunk_out) { 
    unsigned char md5[MD5_DIGEST_LENGTH];

    // Première boucle : Chercher le md5 dans la table de hachage avec l'index
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        Md5Entry *entry = &global_hash_table[i];  // On accède directement à l'élément
        if (entry && entry->index == index) {
            // Si l'index correspond, on récupère le md5 associé
            memcpy(md5, entry->md5, MD5_DIGEST_LENGTH);
            break;
        }
    }

    // Deuxième boucle : Chercher le chunk correspondant au md5 dans la table de chunks
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        Chunk *chunk = &global_chunks[i];  // On accède directement à l'élément
        if (chunk && memcmp(chunk->md5, md5, MD5_DIGEST_LENGTH) == 0) {
            // Si les md5 correspondent, on copie le chunk dans chunk_out
            memcpy(chunk_out, chunk, sizeof(Chunk));
            return; // Chunk trouvé, on quitte la fonction
        }
    }
}


void find_file_MD5(FILE *file, unsigned char *md5) {

    if (!file || !md5) {
        fprintf(stderr, "Paramètres invalides pour find_file_MD5.\n");
        return;
    }

    MD5_CTX ctx;
    unsigned char buffer[CHUNK_SIZE];
    size_t bytes_read;

    // Initialisation du contexte MD5
    MD5_Init(&ctx);

    // Lire le fichier par blocs et mettre à jour le hash
    while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, file)) > 0) {
        MD5_Update(&ctx, buffer, bytes_read);
    }
    // Finalisation : calculer le hash final
    MD5_Final(md5, &ctx);
}