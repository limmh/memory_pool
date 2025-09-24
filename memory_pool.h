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
