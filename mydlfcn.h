#pragma once
#include <stddef.h>

// The user should provide the buffer containing the library as well as its size, there will be no 
// dlopen flags implementation as only the the main library/ should be able to access dlopen as to 
// simplify the operations.
void *dlopen_buffer(void* buffer, size_t buffer_size);

int dlclose_buffer(void *handle);

void *dlsym_buffer(void *handle, char *name);
