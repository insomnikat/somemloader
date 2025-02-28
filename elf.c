#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <unistd.h>
#include <string.h>

#include "elf_definitions.h"
#include "elf.h"
#include "options.h"

#define PAGE_SIZE 4096


inline static uint64_t size_in_pages(size_t size)
{
    return (size/PAGE_SIZE) + ((size % PAGE_SIZE) != 0);
}

inline static size_t ceiling_to_next_page(size_t number)
{
    size_t ceiling = number;
    if ((number % PAGE_SIZE) != 0) 
    {
        ceiling += PAGE_SIZE - 1;
        ceiling &= -PAGE_SIZE;
    }
    return ceiling;
}

inline static size_t floor_to_previous_page(size_t number)
{
    size_t floor = number;
    floor &= -PAGE_SIZE;
    return floor;
}

static uint32_t elf_hash(const char* name) 
{
    uint32_t h = 0, g;
    for (; *name; name++) 
    {
        h = (h << 4) + *name;
        // added parens or the lsp will kill me
        if ((g = h & 0xf0000000))
        {
            h ^= g >> 24;
        }
        h &= ~g;
    }
    return h;
}

// yoinked from https://flapenguin.me/elf-dt-hash
// thank you very much

void *elf_lookup(dso *d, const char *symbol_name)
{
    uint32_t hash = elf_hash(symbol_name);

    uint32_t *table_entries = (uint32_t *) d->elf_hash_table;
    const uint32_t nbucket = table_entries[0];
    const uint32_t nchain = table_entries[1];
    const uint32_t* bucket = &table_entries[2];
    const uint32_t* chain = &bucket[nbucket];


    for (uint32_t i = bucket[hash % nbucket]; i; i = chain[i]) {
        if (strcmp(symbol_name, d->string_table + d->symbol_table[i].st_name) == 0) {
            return (d->base + d->symbol_table[i].st_value);
        }
    }

    return NULL;
}

static uint32_t gnu_hash(const char* name) {
    uint32_t h = 5381;

    for (; *name; name++) {
        h = (h << 5) + h + *name;
    }

    return h;
}
// yoinked from https://flapenguin.me/elf-dt-gnu-hash
// thanks :p

void* gnu_lookup(dso *d, const char* symbol_name) 
{

    const uint64_t elfclass_bits = 64;
    const uint32_t namehash = gnu_hash(symbol_name);

    uint32_t *elements = (uint32_t *) d->gnu_hash_table;

    const uint32_t nbuckets = elements[0];
    const uint32_t symoffset = elements[1];
    const uint32_t bloom_size = elements[2];
    const uint32_t bloom_shift = elements[3];
    const uint64_t* bloom = (uint64_t *) &elements[4];
    const uint32_t* buckets = (uint32_t *) &bloom[bloom_size];
    const uint32_t* chain = &buckets[nbuckets];

    uint64_t word = bloom[(namehash / elfclass_bits) % bloom_size];
    uint64_t mask = 0
        | (uint64_t)1 << (namehash % elfclass_bits)
        | (uint64_t)1 << ((namehash >> bloom_shift) % elfclass_bits);

    if ((word & mask) != mask) 
    {
        return NULL;
    }

    uint32_t symix = buckets[namehash % nbuckets];
    if (symix < symoffset) 
    {
        return NULL;
    }

    /* Loop through the chain. */
    while (true) 
    {
        const char* symname = d->string_table + d->symbol_table[symix].st_name;
        const uint32_t hash = chain[symix - symoffset];

        if ((namehash|1) == (hash|1) && strcmp(symbol_name, symname) == 0) 
        {
            return d->base + d->symbol_table[symix].st_value;
        }

        /* Chain ends with an element with the lowest bit set to 1. */
        if (hash & 1) 
        {
            break;
        }

        symix++;
    }

    return NULL;
}

static bool is_valid_elf_library(void *buffer, size_t buffer_size)
{
    if (buffer_size < sizeof(Elf64_Ehdr)) 
    {
        return NULL;
    }

    Elf64_Ehdr *header = buffer;
    bool valid_magic_number =
           (header->e_ident[EI_MAG0] == ELFMAG0) 
        && (header->e_ident[EI_MAG1] == ELFMAG1) 
        && (header->e_ident[EI_MAG2] == ELFMAG2)
        && (header->e_ident[EI_MAG3] == ELFMAG3);

    if (!valid_magic_number) 
    {
        return false;
    } 

    bool compatible_with_os = 
           (header->e_ident[EI_CLASS] == ELFCLASS64) 
        && (header->e_ident[EI_DATA] == ELFDATA2LSB)
        && (header->e_ident[EI_VERSION] == EV_CURRENT)
        && ((header->e_ident[EI_OSABI] == ELFOSABI_SYSV) || (header->e_ident[EI_OSABI] == ELFOSABI_LINUX))
        && (header->e_ident[EI_ABIVERSION] == 0)
    ;

    if (!compatible_with_os) 
    {
        return false;
    } 

    bool compatible_with_hardware = 
           (header->e_machine == EM_X86_64) 
    ;

    if (!compatible_with_hardware) 
    {
        return false;
    } 

    bool is_library = 
        (header->e_type == ET_DYN);

    // could just skip this if statement and return is_library but this looks better, scew performance ig :p
    if (!is_library) 
    {
        return false;
    } 

    return true;
}

static bool relocate(Elf64_Sym *symbol_table, Elf64_Rela *rela_table, size_t rela_table_size, char *base)
{
    for (size_t i = 0; i < rela_table_size; i++) 
    {

        const Elf64_Rela *cur = &rela_table[i];

        size_t symbol_index = ELF64_R_SYM(cur->r_info);
        size_t relocation_type = ELF64_R_TYPE(cur->r_info);

        if (symbol_index == STN_UNDEF) 
        {
            return false;
        }

        Elf64_Sym *refrenced_symbol = &symbol_table[symbol_index];
        size_t symbol_value = 0;

        // modified version of loader.c from 
        // https://github.com/Ferdi265/dynamic-loader
        // one case where index is stn_undef is when we are using R_X86_64_RELATIVE so it isn't a problem to have it
        if (symbol_index != STN_UNDEF) {
            // do not resolve symbols, the library should be its own unit without need for external linking
            if (refrenced_symbol->st_shndx == SHN_UNDEF) {
                return false;
            } else {
                symbol_value = (size_t)base + refrenced_symbol->st_value;
            }
        }

        size_t target = (size_t)base + cur->r_offset;

        switch (relocation_type) {
            case R_X86_64_NONE:
                // docs say none
                return false;
            case R_X86_64_64:
                *(uint64_t *)target = symbol_value + cur->r_addend;
                break;
            case R_X86_64_PC32:
                *(uint32_t *)target = symbol_value + cur->r_addend - target;
                break;
            case R_X86_64_COPY:
                // docs say none
            return false;
            case R_X86_64_GLOB_DAT:
                *(uint64_t *)target = symbol_value;
                break;
            case R_X86_64_JUMP_SLOT:
                *(uint64_t *)target = symbol_value;
                break;
            case R_X86_64_RELATIVE:
                *(uint64_t *)target = (size_t)base + cur->r_addend;
                break;
            case R_X86_64_GOTPCREL:
                // https://refspecs.linuxfoundation.org/elf/elf.pdf 
                // page 80
                // needs the address of the got, can use DT_PLTGOT to get the address of the PLT
                // and then do some silly arithmatic by looking at the first PLT entry stub and 
                // then finding the address of the runtime resolve function which should be index 3 in the GOT
                // and then subtract by 2 indicies (i think (?)). I haven't been 
                // able to reproduce it nor can I find good enough documentation to know where it is even used.
                // but even then if written correctly there shouldnt be a plt... soooooo......
                return false;
            case R_X86_64_32:
            case R_X86_64_32S:
                *(uint32_t *)target = symbol_value + cur->r_addend;
                break;
            // these aren't conformant to the System V AMD64 ABI as per
            // https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.95.pdf
            // page 69 but this will stay
            case R_X86_64_16:
                *(uint16_t *)target = symbol_value + cur->r_addend;
                break;
            case R_X86_64_8:
                *(uint8_t *)target = symbol_value + cur->r_addend;
                break;
            default:
                return false;
        }
    }
    return true;
}



bool load_dso(void *input_buffer, size_t buffer_size, dso **out)
{
    if (!is_valid_elf_library(input_buffer, buffer_size)) 
    {
        return false;
    }

    dso *dso_entry = malloc(sizeof(dso));
    void *buffer = malloc(buffer_size);

    memcpy(buffer, input_buffer, buffer_size);
    if (dso_entry == NULL) 
    {
        return false;
    }

    dso_entry->buffer = buffer;
    dso_entry->buffer_size = buffer_size;

    dso_entry->elf_header = buffer;

    dso_entry->program_headers = (Elf64_Phdr *) (dso_entry->buffer + dso_entry->elf_header->e_phoff);
    dso_entry->program_header_length = dso_entry->elf_header->e_phentsize;
    dso_entry->program_header_count = dso_entry->elf_header->e_phnum;


    Elf64_Dyn *dynamic_array = NULL;
    // this can be uncommented in order to force libraries to be mapped to random addresses. this isn't really needed
    // and can be dangerous due to the unchecked usage of MAP_FIXED which might straight up nuke the page at the hint address
    // but the odds are pretty low. but since we are the attacker, we don't care about address randomization

    // buffer is less that 256 and no flags are passed, should be guarneteed to work or block
    /*size_t random_address = 0;*/
    /*getrandom(&random_address, sizeof(random_address), NULL);*/
    /**/
    /*uint8_t *base = (uint8_t *) (random_address & 0x00007FFFFFFFFFFF);*/

    // get the ammount of memory needed to load the image and mmap it at once with no protections.

    // make the addresss point to the page that is at either end of the allocated memory space.
    // so for min_address that would be the a bitwise and 0xfff...000
    // and for max_address that would be address + page and then bitwise and 0xfff...000

    size_t min_address = SIZE_MAX;
    size_t max_address = 0;
    for (size_t i = 0; i < dso_entry->program_header_count; i++) 
    {
        Elf64_Phdr *ph = &dso_entry->program_headers[i];
        if (ph->p_type == PT_LOAD) 
        {
            if (min_address > ph->p_vaddr) 
            {
                min_address = floor_to_previous_page(ph->p_vaddr);
            }

            if (max_address < ph->p_vaddr + ph->p_memsz) 
            {
                max_address = ceiling_to_next_page(ph->p_vaddr + ph->p_memsz);
            }

        }
        if (ph->p_type == PT_DYNAMIC) 
        {
            dynamic_array = (Elf64_Dyn *) ((unsigned long)dso_entry->buffer + ph->p_offset);
        }
    }

    size_t total_memory = max_address - min_address;

    /*printf("%lu\n", total_memory);*/

    char * base = (char *)mmap(NULL, total_memory, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

    if (base == MAP_FAILED) 
    {
        goto failure_before_mmap;
    }


    for (size_t i = 0; i < dso_entry->program_header_count; i++) 
    {
        Elf64_Phdr *ph = &dso_entry->program_headers[i];
        if (ph->p_type == PT_LOAD) {

            /*char *cpydest = base + ph->p_vaddr;*/
            /*char *cpyeaddr = cpydest + ph->p_filesz;*/
            /*char array[4096] = {0};*/
            /*snprintf(buffer, sizeof(array), "range: %p - %p\n", cpydest, cpyeaddr);*/
            /*write(4, buffer, strlen(buffer));*/

            // copy everything from file size
            memcpy((base + ph->p_vaddr), (char*)buffer + ph->p_offset, ph->p_filesz);
        }
    }


    size_t elf_hash_table_offset = 0;
    size_t gnu_hash_table_offset = 0;
    size_t string_table_offset = 0;
    size_t symbol_table_offset = 0;

    size_t rela_table_offset = 0;
    size_t rela_table_size = 0;

    size_t plt_relocation_type = 0;
    size_t plt_rela_offset = 0;
    size_t plt_rela_size = 0;

    size_t init_function_offset = 0;
    size_t init_function_array_offset = 0;
    size_t fini_function_offset = 0;
    size_t fini_function_array_offset = 0;

    size_t init_function_array_size = 0;
    size_t fini_function_array_size = 0;
    // extract information from the dynamic array
    // yes i could use a switch statement but it looks ugly
    for (size_t i = 0; dynamic_array[i].d_tag != DT_NULL; i++) 
    {
        // check the dynamic array for any DT_NEEDED entries, if they exist then the library isn't statically linked and thus refuse to load it.
        // this check is not the most accurate as even listing a shared library during compilation will result in it having a needed entry even if it is never used.
        if (dynamic_array[i].d_tag == DT_NEEDED) 
        {
            goto failure_after_mmap;
        }
        // hash table
        else if (dynamic_array[i].d_tag == DT_HASH) 
        {
            elf_hash_table_offset = dynamic_array[i].d_un.d_ptr;
        }
        // gnu hash table
        else if (dynamic_array[i].d_tag == DT_GNU_HASH) 
        {
            gnu_hash_table_offset = dynamic_array[i].d_un.d_ptr;
        }
        // string table
        if (dynamic_array[i].d_tag == DT_STRTAB) 
        {
            string_table_offset = dynamic_array[i].d_un.d_ptr;
        }
        // symbol table
        if (dynamic_array[i].d_tag == DT_SYMTAB) 
        {
            symbol_table_offset = dynamic_array[i].d_un.d_ptr;
        }
        // rela entry, x64 only supports rela not rel, check page 67 of the x64 system v suplement
        else if (dynamic_array[i].d_tag == DT_RELA) 
        {
            rela_table_offset = dynamic_array[i].d_un.d_ptr;
        }
        // rela entry size, x64 only supports rela not rel, check page 67 of the x64 system v suplement
        else if (dynamic_array[i].d_tag == DT_RELASZ) 
        {
            rela_table_size = dynamic_array[i].d_un.d_val;
        }
        // init function
        else if (dynamic_array[i].d_tag == DT_INIT) 
        {
            init_function_offset = dynamic_array[i].d_un.d_ptr;
        }
        // init function array
        else if (dynamic_array[i].d_tag == DT_INIT_ARRAY) 
        {
            init_function_array_offset = dynamic_array[i].d_un.d_ptr;
        }
        // init function array size
        else if (dynamic_array[i].d_tag == DT_INIT_ARRAYSZ) 
        {
            init_function_array_size = dynamic_array[i].d_un.d_val;
        }
        // fini function
        else if (dynamic_array[i].d_tag == DT_FINI) 
        {
            fini_function_offset = dynamic_array[i].d_un.d_ptr;
        }
        // fini function array 
        else if (dynamic_array[i].d_tag == DT_FINI_ARRAY) 
        {
            fini_function_array_offset = dynamic_array[i].d_un.d_ptr;
        }
        // fini function array size
        else if (dynamic_array[i].d_tag == DT_FINI_ARRAYSZ) 
        {
            fini_function_array_size = dynamic_array[i].d_un.d_val;
        }
        else if (dynamic_array[i].d_tag == DT_PLTREL) 
        {
            plt_relocation_type = dynamic_array[i].d_un.d_val;
        }
        else if (dynamic_array[i].d_tag == DT_JMPREL) 
        {
            plt_rela_offset = dynamic_array[i].d_un.d_ptr;
        }
        else if (dynamic_array[i].d_tag == DT_PLTRELSZ) 
        {
            plt_rela_size = dynamic_array[i].d_un.d_val;
        }
    }


    // Note: mprotect calls may be detected as suspicious

#ifdef ENABLE_MPROTECT

    for (uint16_t i = 0; i < dso_entry->program_header_count; i++) {
        Elf64_Phdr *ph = &dso_entry->program_headers[i];
        if (ph->p_type == PT_LOAD) {


            char *vaddr_page = base + floor_to_previous_page(ph->p_vaddr);
            char *max_page = (char *) ceiling_to_next_page((size_t) vaddr_page + ph->p_memsz);

            int segment_flags = dso_entry->program_headers[i].p_flags;

            int memflags = 0;

            if (segment_flags & PF_R) 
            {
                memflags |= PROT_READ;
            }

            if (segment_flags & PF_W) 
            {
                memflags |= PROT_WRITE;
            }

            if (segment_flags & PF_X) 
            {
                memflags |= PROT_EXEC;
            }

            int result = mprotect(vaddr_page, max_page - vaddr_page, memflags);

            if (result == -1) 
            {
                goto failure_after_mmap;
            }
        }
    }

#endif 

     char *string_table = base + string_table_offset;
     Elf64_Sym *symbol_table = (Elf64_Sym *) (base + symbol_table_offset);

    if (rela_table_size != 0) 
    {
        Elf64_Rela *rela_table = (Elf64_Rela *) (base + rela_table_offset);
        size_t rela_table_entry_count = plt_rela_size / sizeof(Elf64_Rela);
        relocate(symbol_table, rela_table, rela_table_entry_count, base);
    }
    if (plt_rela_size != 0)
    {
        Elf64_Rela *rela_table = (Elf64_Rela *) (base + plt_rela_offset);
        // this isn't portable, as depending on the arch the type of DT_PLTREL will change but since x86_64 only uses rela then 
        // it is redundunt a better check would be 
        // size_t entry_count = 0;
        // if (plt_relocation_type == DT_REL) 
        // {
        //     entry_count = plt_table_size / sizeof(ELF64_REL)
        // }
        // etc etc

        size_t rela_table_entry_count = plt_rela_size / sizeof(Elf64_Rela);
        relocate(symbol_table, rela_table, rela_table_entry_count, base);
    }

    if (init_function_offset) 
    {
        size_t (*init_function)() = (size_t (*)()) base + init_function_offset;
        init_function();
    }

    if (init_function_array_size) 
    {

        size_t (**init_functions)() = (size_t (**)()) base + init_function_offset;
        for (size_t i = 0; i < init_function_array_size; i++) 
        {
            init_functions[i]();
        }
    }


    dso_entry->base = base;
    dso_entry->header = (Elf64_Ehdr *) base;
    dso_entry->dynamic_array = dynamic_array;
    dso_entry->string_table = string_table;
    dso_entry->symbol_table = symbol_table;
    dso_entry->elf_hash_table = (elf_hash_table_offset ? (base + elf_hash_table_offset) : NULL);
    dso_entry->gnu_hash_table = (gnu_hash_table_offset ? (base + gnu_hash_table_offset) : NULL);
    dso_entry->fini_function_offset = fini_function_offset;
    dso_entry->fini_function_array_offset = fini_function_array_offset;
    dso_entry->fini_function_array_size = fini_function_array_size;

    dso_entry->total_memory = total_memory;
    *out = dso_entry;



    return true;


failure_after_mmap:
    munmap(base, total_memory);

failure_before_mmap:
    free(dso_entry);
    return false;
}

