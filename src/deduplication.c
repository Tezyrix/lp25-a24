#include "deduplication.h"

unsigned int hash_md5(unsigned char *md5) {
    unsigned int hash = 0;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        hash = (hash << 5) + hash + md5[i];
    }
    return hash % HASH_TABLE_SIZE;
}

void compute_md5(void *data, size_t len, unsigned char *md5_out) {
    MD5((unsigned char *)data, len, md5_out);
}

int find_md5(Md5Entry *hash_table, unsigned char *md5) {
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        if (memcmp(hash_table[i].md5, md5, MD5_DIGEST_LENGTH) == 0) {
            return hash_table[i].index;
        }
    }
    return -1;
}

void add_md5(Md5Entry *hash_table, unsigned char *md5, int index) {
    unsigned int hash_index = hash_md5(md5);
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        int current_index = (hash_index + i) % HASH_TABLE_SIZE;

        if (hash_table[current_index].index == -1) {
            memcpy(hash_table[current_index].md5, md5, MD5_DIGEST_LENGTH);
            hash_table[current_index].index = index;
            return;
        }

        if (memcmp(hash_table[current_index].md5, md5, MD5_DIGEST_LENGTH) == 0) {
            return;
        }
    }
    printf("Table de hachage pleine. Impossible d'ajouter une nouvelle entrée.\n");
}

void deduplicate_file(FILE *file, Chunk *chunks, Md5Entry *hash_table) {

}

void undeduplicate_file(FILE *file, Chunk **chunks, int *chunk_count) {
    fread(chunk_count, sizeof(int), 1, file);
    *chunks = (Chunk *)malloc(sizeof(Chunk) * (*chunk_count));

    for (int i = 0; i < *chunk_count; i++) {
        fread((*chunks)[i].md5, MD5_DIGEST_LENGTH, 1, file);

        size_t data_size;
        fread(&data_size, sizeof(size_t), 1, file);

        if (data_size > 0) {
            (*chunks)[i].data = malloc(data_size);
            fread((*chunks)[i].data, data_size, 1, file);
        } else {
            (*chunks)[i].data = NULL; // Chunk référencé uniquement par MD5
        }
    }
}