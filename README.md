# x86_64 Library Loader

A simple library for loading -nostdlib shared objects directly from memory for x86_64.

## Why
When writing a piece of malware sometimes, it is preferable to keep it fileless, in order 
to avoid any disk scanning tools from detecting it, if the payload is in the form of a shared
object the usual process for loading from memory is by combining a memfd_create/memfd_secret 
system call and then combine it with a call to dlopen, using the file path argument of 
"/proc/self/fd/<fd returned from system call>", this can be detected by either monitoring 
the calls to dlfcn.h functions using system tap for example or by a kernel based anti-malware
tools detecting suspicious memfd system calls, this bypasses this by providing a very simple 
loader for shared objects. 

This library was made in mind with loading from statically linked binaries which is usually very
hacky or even impossible depending on your libc implementation. Don't get me wrong this is still 
a hack job.

## Limitations
As mentioned before this targets -nostdlib shared objects for the x86_64 architecture only.
RELRO and shared object dependencies support isn't provided.

## Usage
Drop the C files into your project and include mydlfcn.h and use the functions provided by it. :D

One important thing to note, options.h has the preprocessor option to enable or disable mprotect 
calls used to fix the memory protections in accordance with the library but some systems detect
the change as suspecious so that can be disabled.
