#pragma once
#include <stddef.h>
#include <stdbool.h>
#include <sys/mman.h>

#include "elf_definitions.h"

typedef struct ElfHashTable {
    uint32_t nbucket;
    uint32_t nchain;
    uint32_t *bucket;
    uint32_t *chain;

} ElfHashTable;

typedef struct GnuHashTable {
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t bloom_shift;
    uint64_t *bloom;
    uint32_t *buckets;
    uint32_t *chain;
} GnuHashTable;


// Dynamic shared object
typedef struct dso
{
    // a refrence to the original buffer
    char *buffer;
    size_t buffer_size;

    Elf64_Ehdr *elf_header;
    
    // program header info these point into the copy
    Elf64_Phdr *program_headers;
    Elf64_Half program_header_length;
    Elf64_Half program_header_count;

    // base address/ header and mmaped size
    Elf64_Ehdr *header;
    char *base;
    size_t total_memory;


    // dynamic array
    Elf64_Dyn *dynamic_array;

    // tables
    char *string_table;
    Elf64_Sym *symbol_table;

    // hash tables for symbol resulotion
    char *elf_hash_table;
    char *gnu_hash_table;

    // finalization function information
    size_t fini_function_offset;
    size_t fini_function_array_offset;
    size_t fini_function_array_size;
    
    
} dso;

bool load_dso(void *buffer, size_t buffer_size, dso **out);
void *gnu_lookup(dso *d, const char* symbol_name);
void *elf_lookup(dso *d, const char *symbol_name);
