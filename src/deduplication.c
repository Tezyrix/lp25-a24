#include "deduplication.h"

unsigned int hash_md5(unsigned char *md5) {
    unsigned int hash = 0;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        hash = (hash << 5) + hash + md5[i];
    }
    return hash % HASH_TABLE_SIZE;
}

// Fonction qui calcule le MD5 d'un chunk de données
void compute_md5(unsigned char *data, unsigned char *md5) {
    /**
     * @param data donnée du chunk
     * @param md5 md5 du chunk
     */
    MD5_CTX context;    // Structure pour l'état de calcul du MD5
    MD5_Init(&context); // Initialiser le contexte
    // Calculer le MD5 du chunk
    MD5_Update(&context, data, CHUNK_SIZE);
    // Obtenir le résultat du calcul MD5 dans le tableau md5
    MD5_Final(md5, &context);
}

// Fonction qui chercher l'indice d'un md5 d'un chunk dans la table de hashage global
int find_md5(Md5Entry *hash_table, unsigned char *md5) {
    /**
     * @param hash_table table de hashage global
     * @param md5 md5 du chunk à chercher
     */
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        if (memcmp(hash_table[i].md5, md5, MD5_DIGEST_LENGTH) == 0) {
            return hash_table[i].index;
        }
    }
    return -1;
}


// Fonction permettant la déduplication d'un fichier régulier en un tableau d'indice non unique
void deduplicate_file(const char *file_path, int *chunk_indices, int *chunk_count) {
    /**
     * @param file_path nom du fichier à dédupliquer
     * @param chunk_indices tableau d'int contenant la liste des indices des chunks du fichier (non unique)
     * @param chunk_count nombre de chunk du fichier
     */
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
        // Check si le chunk est déja connu
        add_to_global_tables(buffer, md5);
        // Chercher l'indice du chunk dans la table de hachage
        int index = find_md5(global_hash_table, md5);
        chunk_indices[*chunk_count] = index;
        (*chunk_count)++;
    }
    fclose(file);
}

void undeduplicate_file(FILE *file, Chunk **chunks, int *chunk_count) {
}

// Fonction permettant d'initialiser les deux tables globales qu'on utilise tout au long du programme
void initialize_global_tables() {
    /**
     * @param
     */

    // Essayer d'ouvrir les fichiers en mode lecture/écriture
    FILE *hash_file = fopen("hash_table.dat", "r+b");
    FILE *chunk_file = fopen("chunk_table.dat", "r+b");

    if (hash_file && chunk_file) {
        // Les fichiers existent : charger les données
        fread(global_hash_table, sizeof(Md5Entry), HASH_TABLE_SIZE, hash_file);
        fread(global_chunks, sizeof(Chunk), HASH_TABLE_SIZE, chunk_file);
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

        // Initialiser les tables globales
        memset(global_hash_table, 0, sizeof(global_hash_table));
        memset(global_chunks, 0, sizeof(global_chunks));

        // Écrire les tables initialisées dans les fichiers
        fwrite(global_hash_table, sizeof(Md5Entry), HASH_TABLE_SIZE, hash_file);
        fwrite(global_chunks, sizeof(Chunk), HASH_TABLE_SIZE, chunk_file);
    }

    // Garder les fichiers ouverts dans des pointeurs globaux
    global_hash_file = hash_file;
    global_chunk_file = chunk_file;
}

// Fonction permettant pour un chunk donné de l'ajouter dans les tables globales si il n'existe pas déja de manière unique
void add_to_global_tables(void *data, unsigned char *md5) {
    /**
     * @param data donnée du chunk
     * @param md5 md5 du chunk
     */
    int chunk_index = -1;
    int last_index = -1;

    // Vérifier si le MD5 est déjà présent dans la table de hachage
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        if (global_hash_table[i].index != 0 && memcmp(global_hash_table[i].md5, md5, MD5_DIGEST_LENGTH) == 0) {
            // Si le MD5 existe déjà, ne rien faire
            return;
        }
        // Trouver le dernier indice utilisé (pour ajouter un nouveau chunk)
        if (global_hash_table[i].index != 0) {
            last_index = i;
        }
    }

    // Si on a trouvé un dernier index utilisé, l'index du prochain chunk sera last_index + 1 sinon cela veut dire que la table est vide donc 0
    chunk_index = (last_index == -1) ? 0 : last_index + 1;

    // Ajouter le MD5 dans la table de hachage avec un nouvel indice
    global_hash_table[chunk_index].index = chunk_index;
    memcpy(global_hash_table[chunk_index].md5, md5, MD5_DIGEST_LENGTH);

    // Ajouter le chunk dans la table des chunks avec le même indice
    global_chunks[chunk_index].data = malloc(CHUNK_SIZE);
    if (global_chunks[chunk_index].data == NULL) {
        perror("Erreur d'allocation mémoire pour le chunk");
        return;
    }
    memcpy(global_chunks[chunk_index].data, data, CHUNK_SIZE);
    memcpy(global_chunks[chunk_index].md5, md5, MD5_DIGEST_LENGTH);
}

// Fonction permettant de fermer les tables globales quand on ne les utilise plus
void close_global_tables() {
    if (global_hash_file) {
        fclose(global_hash_file);
        global_hash_file = NULL; 
    }
    if (global_chunk_file){
        fclose(global_chunk_file);
        global_chunk_file = NULL;
    }
}

/**
 * @brief Calcule le MD5 d'un fichier.
 * @param file Le pointeur vers le fichier à analyser.
 * @param md5 Un tableau de 16 octets pour stocker le résultat du hash MD5.
 */
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