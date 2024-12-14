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
    printf("Table de hachage pleine. Impossible d'ajouter l'élément.\n");
}

void deduplicate_file(FILE *file, Chunk *chunks, Md5Entry *hash_table) {
    unsigned char buffer[CHUNK_SIZE];
    size_t bytes_read;
    int chunk_index = 0;

    while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, file)) > 0) {
        unsigned char md5[MD5_DIGEST_LENGTH];
        compute_md5(buffer, bytes_read, md5);

        if (find_md5(hash_table, md5) == -1) {
            // Nouveau chunk
            chunks[chunk_index].data = malloc(bytes_read);
            memcpy(chunks[chunk_index].data, buffer, bytes_read);
            memcpy(chunks[chunk_index].md5, md5, MD5_DIGEST_LENGTH);
            add_md5(hash_table, md5, chunk_index);
            chunk_index++;
        }
    }
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