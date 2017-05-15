/*
The MIT License (MIT)

Copyright (c) 2017 MH Lim

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef MEMORY_POOL_H
#define MEMORY_POOL_H

#include <stddef.h>

#ifndef MEMORY_POOL_EXPORT
#define MEMORY_POOL_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*pool_exception_handler_s)(const char *name, void *starting_addr, void *last_addr, void *error_location);

MEMORY_POOL_EXPORT void *pool_create(size_t size);
MEMORY_POOL_EXPORT void pool_destroy(void *pool);

MEMORY_POOL_EXPORT pool_exception_handler_s pool_set_heap_corruption_handler(void *pool, pool_exception_handler_s handler);
MEMORY_POOL_EXPORT pool_exception_handler_s pool_set_memory_leak_handler(void *pool, pool_exception_handler_s handler);
MEMORY_POOL_EXPORT pool_exception_handler_s pool_set_dangling_pointer_handler(void *pool, pool_exception_handler_s handler);

MEMORY_POOL_EXPORT void pool_set_name(void *pool, const char *name);
MEMORY_POOL_EXPORT const char *pool_get_name(void *pool);

MEMORY_POOL_EXPORT void *pool_malloc(void *pool, size_t size);
MEMORY_POOL_EXPORT void *pool_calloc(void *pool, size_t count, size_t element_size);
MEMORY_POOL_EXPORT void *pool_realloc(void *pool, void *memory, size_t new_size);

MEMORY_POOL_EXPORT void pool_free(void *pool, void *memory);
MEMORY_POOL_EXPORT void pool_defragment(void *pool);

#ifdef __cplusplus
}
#endif

#endif
