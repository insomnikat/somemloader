#include "mydlfcn.h"
#include "elf.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void *dlopen_buffer(void* buffer, size_t buffer_size)
{
    dso *out = NULL;
    if (!load_dso(buffer, buffer_size, &out)) 
    {
        return NULL;
    }
    return out;
}

int dlclose_buffer(void *handle)
{
    dso *d = handle;

    char *base = d->base;
    size_t mmaped_memory_size = d->total_memory;

    if (d->fini_function_offset) 
    {
        size_t (*fini_function)() = (size_t (*)()) d->base + d->fini_function_offset;
        fini_function();
    }

    if (d->fini_function_array_size) 
    {

        size_t (**fini_functions)() = (size_t (**)()) d->base + d->fini_function_offset;
        for (size_t i = 0; i < d->fini_function_array_size; i++) 
        {
            fini_functions[i]();
        }
    }

    // free internal buffer
    free(d->buffer);
    free(handle);

    // unmap memory
    return munmap(base, mmaped_memory_size);
}

void *dlsym_buffer(void *handle, char *name)
{
    dso *d = handle;
    void *symbol = NULL;
    if (d->elf_hash_table) 
    {
        symbol = elf_lookup(d, name);
    }
    
    if (symbol != NULL) 
    {
        return symbol;
    }

    if (d->gnu_hash_table) 
    {
        symbol = gnu_lookup(d, name);
    }

    if (symbol != NULL) 
    {
        return symbol;
    }

    return NULL;
}


