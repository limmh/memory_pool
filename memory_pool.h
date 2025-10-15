#ifndef MEMORY_POOL_H
#define MEMORY_POOL_H

#include <stddef.h>
#include <stdio.h>

#ifndef MEMORY_POOL_EXPORT
#define MEMORY_POOL_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*pool_exception_handler_s)(const char *name, const void *starting_addr, const void *last_addr, const void *error_location);
typedef pool_exception_handler_s pool_exception_handler_type;

typedef struct pool_allocator_type {
	void *(*alloc)(size_t number_of_bytes);
	void (*dealloc)(void *memory);
} pool_allocator_type;

typedef struct pool_mutex_type {
	void *mutex;
	void (*mutex_lock)(void *mutex);
	void (*mutex_unlock)(void *mutex);
} pool_mutex_type;

typedef struct pool_result_type {
	void *pool;
	size_t actual_size; /* actual size including overhead in bytes */ 
} pool_result_type;

MEMORY_POOL_EXPORT size_t pool_minimum_overhead_size(void);

MEMORY_POOL_EXPORT void *pool_create(size_t size); /* uses OS heap and uses no mutex */

MEMORY_POOL_EXPORT
pool_result_type pool_create_with_allocator_or_mutex_support(
	size_t size, /* minimum number of bytes */
	pool_allocator_type *allocator, /* allocator: optional, can be NULL (uses OS heap) */
	pool_mutex_type *pool_mutex /* mutex: optional, can be NULL (no thread safety) */
);

MEMORY_POOL_EXPORT void pool_destroy(void *pool);

MEMORY_POOL_EXPORT pool_exception_handler_type pool_set_heap_corruption_handler(void *pool, pool_exception_handler_type handler);
MEMORY_POOL_EXPORT pool_exception_handler_type pool_set_memory_leak_handler(void *pool, pool_exception_handler_type handler);
MEMORY_POOL_EXPORT pool_exception_handler_type pool_set_dangling_pointer_handler(void *pool, pool_exception_handler_type handler);

MEMORY_POOL_EXPORT void pool_set_name(void *pool, const char *name);
MEMORY_POOL_EXPORT const char *pool_get_name(void *pool);

MEMORY_POOL_EXPORT FILE *pool_set_log_file(void *pool, FILE *log_file); /* returns the previous FILE pointer */
MEMORY_POOL_EXPORT FILE *pool_get_log_file(void *pool);

MEMORY_POOL_EXPORT void *pool_malloc(void *pool, size_t size);
MEMORY_POOL_EXPORT void *pool_calloc(void *pool, size_t count, size_t element_size);
MEMORY_POOL_EXPORT void *pool_realloc(void *pool, void *memory, size_t new_size);

MEMORY_POOL_EXPORT void pool_free(void *pool, void *memory);
MEMORY_POOL_EXPORT void pool_defragment(void *pool);

#ifdef __cplusplus
}
#endif

#endif
