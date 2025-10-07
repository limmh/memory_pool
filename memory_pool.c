#include "memory_pool.h"
#ifdef MEMORY_POOL_WITH_ERROR_LOGGING
#include "logging.h"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t)0U - 1U)
#endif

typedef struct block_info_type
{
	unsigned char pattern[sizeof(size_t)];
	size_t size;
} block_info_type;

typedef struct pool_info_type
{
	const char *name;
	size_t size;
	size_t allocated_blocks;
	block_info_type *first_free_block;
	void *mutex;
	void (*mutex_lock)(void *);
	void (*mutex_unlock)(void *);
	void (*dealloc)(void *);
	pool_exception_handler_type dangling_pointer_handler;
	pool_exception_handler_type heap_corruption_handler;
	pool_exception_handler_type memory_leak_handler;
	FILE *log_file;
} pool_info_type;

static const size_t mask = (sizeof(size_t) - 1U);

static void *pool_get_first_valid_address(const pool_info_type *pool)
{
	return ((unsigned char*) pool) + sizeof *pool + sizeof(block_info_type);
}

static void *pool_get_last_valid_address(const pool_info_type *pool)
{
	unsigned char *start = ((unsigned char*) pool) + sizeof *pool + sizeof(block_info_type);
	return (start + pool->size - 1U); /* last usable byte, not including trailing block info */
}

static void *pool_get_last_block(void *pool) /* trailing block (not usable) */
{
	return (unsigned char*) pool_get_last_valid_address((pool_info_type*) pool) + 1U;
}

static int pool_memory_address_is_valid(void *pool, void *memory)
{
	void *start = NULL, *last = NULL;
	start = pool_get_first_valid_address((pool_info_type*) pool);
	last = pool_get_last_valid_address((pool_info_type*) pool);
	assert(memory >= start);
	assert(memory < last);
	assert(((size_t) memory & mask) == 0U);
	return (memory >= start && memory < last && ((size_t) memory & mask) == 0);
}

static size_t pool_calculate_block_size(size_t minimum_size)
{
	return ((minimum_size != 0U) && (minimum_size & mask) == 0U) ?
		minimum_size : ((minimum_size / sizeof(minimum_size) + 1U) * sizeof(minimum_size));
}

static size_t pool_get_block_size(const block_info_type *block)
{
	return (block->size & ~mask);
}

static block_info_type *pool_get_next_block(const block_info_type *block)
{
	return (block_info_type*) (((unsigned char*) (block + 1U)) + pool_get_block_size(block));
}

static void pool_set_block_as_occupied(block_info_type *block)
{
	block->size |= mask;
}

static void pool_set_block_as_free(block_info_type *block)
{
	block->size &= ~mask;
}

static void pool_set_block_size(block_info_type *block, size_t size)
{
	assert((size & mask) == 0U);
	size &= ~mask;
	block->size &= mask;
	block->size |= size;
}

static int pool_block_is_available(const block_info_type *block)
{
	return ((block->size & mask) == 0);
}

static void pool_activate_check(block_info_type *block)
{
	memset(block->pattern, 0xCC, sizeof block->pattern);
}

static void pool_deactivate_check(block_info_type *block)
{
	memset(block->pattern, 0x0, sizeof block->pattern);
}

static const void *pool_block_head_is_corrupted(const block_info_type *block)
{
	size_t i = 0U;
	for (; i < sizeof block->pattern; i++) {
		if (block->pattern[i] != 0xCCU)
			return &(block->pattern[i]);
	}
	return NULL;
}

static const void *pool_block_tail_is_corrupted(const block_info_type *block)
{
	size_t i = 0U;
	block_info_type *next = pool_get_next_block(block);
	for (; i < sizeof block->pattern; i++)
		if (next->pattern[i] != 0xCCU)
			return &(next->pattern[i]);
	return NULL;
}

static int pool_detect_heap_corruption(const pool_info_type *pool, const block_info_type *block)
{
	const void *start = NULL, *last = NULL, *error_location = NULL;
	if ((error_location = pool_block_head_is_corrupted(block)) != NULL) {
		size_t block_size = pool_get_block_size(block);
		if (block_size > pool->size) { /* avoid accessing memory region outside of the pool */
			block_size = pool->size;
		}
		start = pool;
		last = ((const unsigned char *) (block + 1U)) + block_size - 1U;
		if (pool->heap_corruption_handler != NULL) {
			pool->heap_corruption_handler(pool->name, start, last, error_location);
		}
		if (pool->log_file != NULL) {
			if (pool->name != NULL && pool->name[0] != '\0') {
				fprintf(pool->log_file, "%s: ", pool->name);
			}
			fprintf(pool->log_file, "Heap corruption occurred at location %p.\n", error_location);
#ifdef MEMORY_POOL_WITH_ERROR_LOGGING
			logging_display_memory_contents(start, last, pool->log_file);
#endif
		}
		return 1;
	}

	if ((error_location = pool_block_tail_is_corrupted(block)) != NULL) {
		start = block;
		last = ((const unsigned char*) error_location) + sizeof(size_t) - 1U;

		if (pool->heap_corruption_handler != NULL) {
			pool->heap_corruption_handler(pool->name, start, last, error_location);
		}
		if (pool->log_file != NULL) {
			if (pool->name != NULL && pool->name[0] != '\0') {
				fprintf(pool->log_file, "%s: ", pool->name);
			}
			fprintf(pool->log_file, "Heap corruption occurred at location %p.\n", error_location);
#ifdef MEMORY_POOL_WITH_ERROR_LOGGING
			logging_display_memory_contents(start, last, pool->log_file);
#endif
		}
		return 1;
	}
	return 0;
}

static int pool_detect_repeated_free(const pool_info_type *pool, const block_info_type *block)
{
	if (pool_block_is_available(block)) {
		const void *start = NULL, *last = NULL, *error_location = NULL;
		start = block;
		error_location = block;
		last = (const unsigned char*) (block + 1U) + pool_get_block_size(block) - 1U;
		if (pool->dangling_pointer_handler != NULL) {
			pool->dangling_pointer_handler(pool->name, start, last, error_location);
		}
		if (pool->log_file != NULL) {
			if (pool->name != NULL && pool->name[0] != '\0') {
				fprintf(pool->log_file, "%s: ", pool->name);
			}
			fprintf(pool->log_file, "Memory at %p has already been released to the pool.\n", error_location);
#ifdef MEMORY_POOL_WITH_ERROR_LOGGING
			logging_display_memory_contents(start, last, pool->log_file);
#endif
		}
		return 1;
	}
	return 0;
}

static int pool_check_block_size(const pool_info_type *pool, const block_info_type *block)
{
	const void *start = NULL, *last = NULL, *error_location = NULL;
	size_t block_size = pool_get_block_size(block);
	if (block_size <= pool->size) {
		return 1; /* OK */
	}
	start = block;
	last = (const unsigned char*) (block + 1U) + block_size;
	error_location = &(block->size);
	if (pool->heap_corruption_handler != NULL) {
		pool->heap_corruption_handler(pool->name, start, last, error_location);
	}
	if (pool->log_file != NULL) {
		if (pool->name != NULL && pool->name[0] != '\0') {
			fprintf(pool->log_file, "%s: ", pool->name);
		}
		fprintf(pool->log_file, "The block size at %p (%lu) is more than the pool size (%lu).\n",
			error_location, (unsigned long) block_size, (unsigned long) pool->size);
#ifdef MEMORY_POOL_WITH_ERROR_LOGGING
		logging_display_memory_contents(start, last, pool->log_file);
#endif
	}
	return 0; /* NOT OK */
}

size_t pool_minimum_overhead_size(void)
{
	return sizeof(pool_info_type) + 2U * sizeof(block_info_type);
}

pool_result_type pool_create_with_allocator_or_mutex_support(size_t size, pool_allocator_type *pool_allocator, pool_mutex_type *pool_mutex)
{
	void *pool = NULL;
	size_t actual_size = 0U;
	void *(*alloc_fptr)(size_t) = NULL;
	int allocator_available = 0;
	pool_result_type pool_result = {NULL, 0U};
	size = pool_calculate_block_size(size);
	/*
	Initial state:
	+--------------------+---------------------+----------------------------------------+---------------------+
	| pool_info (header) | starting block_info |          usable memory region          | trailing block info |
	+--------------------+---------------------+----------------------------------------+---------------------+
	*/
	actual_size = pool_minimum_overhead_size() + size;
	allocator_available = (pool_allocator != NULL && pool_allocator->alloc != NULL && pool_allocator->dealloc != NULL);

	alloc_fptr = (allocator_available) ? pool_allocator->alloc : &malloc;
	pool = (*alloc_fptr)(actual_size);
	if (pool != NULL) {
		block_info_type *block = NULL;
		pool_info_type *pool_info = (pool_info_type*) pool;

		memset(pool, 0, actual_size);
		pool_info->name = "";
		pool_info->size = size;
		pool_info->allocated_blocks = 0U;
		pool_info->first_free_block = NULL;
		pool_info->dealloc = (allocator_available) ? pool_allocator->dealloc : &free;
		pool_info->dangling_pointer_handler = NULL;
		pool_info->heap_corruption_handler = NULL;
		pool_info->memory_leak_handler = NULL;
		pool_info->log_file = stdout;

		if (pool_mutex != NULL) {
			pool_info->mutex = pool_mutex->mutex;
			pool_info->mutex_lock = pool_mutex->mutex_lock;
			pool_info->mutex_unlock = pool_mutex->mutex_unlock;
		} else {
			pool_info->mutex = NULL;
			pool_info->mutex_lock = NULL;
			pool_info->mutex_unlock = NULL;
		}

		/* starting block info */
		block = (block_info_type*) (pool_info + 1U);
		pool_set_block_size(block, size);
		pool_activate_check(block);
		/* trailing block info (does not contain any usable memory, marked as occupied) */
		block = (block_info_type*) ((unsigned char*) (block + 1U) + block->size);
		pool_set_block_size(block, 0U);
		pool_set_block_as_occupied(block);
		pool_activate_check(block);

		pool_result.pool = pool;
		pool_result.actual_size = actual_size;
	}	

	return pool_result;
}

void *pool_create(size_t size)
{
	pool_result_type pool_result = pool_create_with_allocator_or_mutex_support(size, NULL, NULL);
	return pool_result.pool;
}

void pool_destroy(void *pool)
{
	pool_info_type *pool_info = NULL;
	block_info_type *block_info = NULL;
	void *last_block = NULL;
	void (*dealloc)(void*) = NULL;

	if (pool == NULL)
		return;

	pool_info = (pool_info_type*) pool;
	block_info = (block_info_type*) (pool_info + 1U);
	last_block = pool_get_last_block(pool);
	dealloc = pool_info->dealloc;

	if (pool_info->allocated_blocks > 0) {
		int more_than_1_block = (pool_info->allocated_blocks > 1);
		if (pool_info->log_file != NULL) {
			if (pool_info->name != NULL && pool_info->name[0] != '\0') {
				fprintf(pool_info->log_file, "%s: ", pool_info->name);
			}
			fprintf(pool_info->log_file, "%lu allocated block%s not released.\n", (unsigned long) pool_info->allocated_blocks, (more_than_1_block ? "s were" : " was"));
		}
	}

	while ((unsigned char*) block_info <= (unsigned char*) last_block - sizeof(block_info_type)) {
		if (pool_detect_heap_corruption(pool_info, block_info))
			break;
		if (!pool_block_is_available(block_info)) {
			void *start = (void*) (block_info + 1);
			void *last = (void*) (((unsigned char*) start) + pool_get_block_size(block_info) - 1U);
			if (pool_info->memory_leak_handler != NULL) {
				pool_info->memory_leak_handler(pool_info->name, start, last, start);
			}
#ifdef MEMORY_POOL_WITH_ERROR_LOGGING
			if (pool_info->log_file != NULL) {
				logging_display_memory_contents(start, last, pool_info->log_file);
			}
#endif
		}
		block_info = pool_get_next_block(block_info);
	}

	if (dealloc != NULL) {
		(*dealloc)(pool);
	}	
}

static void pool_defragment_internal(void *pool)
{
	pool_info_type *pool_info = (pool_info_type*) pool;
	block_info_type *block_info = (block_info_type*) (pool_info + 1U);
	void *last_block = pool_get_last_block(pool);

	while ((unsigned char*) block_info <= (unsigned char*) last_block - sizeof(block_info_type)) {
		if (pool_detect_heap_corruption(pool_info, block_info))
			break;
		if (pool_block_is_available(block_info)) {
			block_info_type *next = pool_get_next_block(block_info);
			if (((unsigned char*) next <= (unsigned char*) last_block - sizeof(block_info_type)) && pool_block_is_available(next)) {
				size_t current_block_size = 0U, next_block_size = 0U, new_block_size = 0U;
				current_block_size = pool_get_block_size(block_info);
				next_block_size = pool_get_block_size(next);
				new_block_size = current_block_size + next_block_size + sizeof *next;
				pool_set_block_size(block_info, new_block_size);
				pool_deactivate_check(next);
				pool_set_block_size(next, 0U);
				continue;
			}
		}
		block_info = pool_get_next_block(block_info);
	}
}

static void *pool_malloc_internal(void *pool, size_t size)
{
	unsigned char *ptr = NULL;
	pool_info_type *pool_info = (pool_info_type*) pool;
	block_info_type *block_info = (pool_info->first_free_block != NULL) ? pool_info->first_free_block : (block_info_type*) (pool_info + 1U);
	void *last_block = pool_get_last_block(pool);
	size = pool_calculate_block_size(size);
	pool_info->first_free_block = NULL;

	while ((unsigned char*) block_info <= (unsigned char*) last_block - sizeof(block_info_type)) {
		size_t block_size = 0U;

		if (pool_detect_heap_corruption(pool_info, block_info)) {
			ptr = NULL;
			break;
		}

		if (!pool_block_is_available(block_info)) {
			block_info = pool_get_next_block(block_info);
			continue;
		}

		block_size = pool_get_block_size(block_info);
		if (block_size < size) {
			block_info = pool_get_next_block(block_info);
			continue;
		} else if (block_size == size) {
			pool_activate_check(block_info);
			pool_set_block_as_occupied(block_info);	
			ptr = ((unsigned char*) (block_info + 1U));
			pool_info->allocated_blocks++;
			break;
		} else {
			const size_t adjusted_block_size = (block_size > size + sizeof(block_info_type)) ? size : block_size; 
			pool_activate_check(block_info);
			pool_set_block_as_occupied(block_info);
			pool_set_block_size(block_info, adjusted_block_size);
			ptr = (unsigned char*) (block_info + 1U);
			pool_info->allocated_blocks++;

			if (block_size > size + sizeof(block_info_type)) {
				block_info_type *next = pool_get_next_block(block_info);
				if ((unsigned char*) next <= (unsigned char*) last_block - sizeof(block_info_type)) {
					const size_t next_block_size = block_size - (size + sizeof(block_info_type));
					pool_activate_check(next);
					pool_set_block_size(next, next_block_size);
					pool_set_block_as_free(next);
					pool_info->first_free_block = next;
				}
			}
			break;
		}
	}

	if (pool_info->first_free_block == NULL && (void*) block_info < last_block) {
		block_info_type* next_block = pool_get_next_block(block_info);
		while ((unsigned char*) next_block <= (unsigned char*) last_block - sizeof(block_info_type)) {
			if (pool_block_is_available(next_block)) {
				pool_info->first_free_block = next_block;
				break;
			}
			next_block = pool_get_next_block(next_block);
		}
	}

	return ptr;
}

static void *pool_calloc_internal(void *pool, size_t count, size_t element_size)
{
	size_t size = 0U;
	void *memory = NULL;
	if (count > 0U && element_size > 0U) {
		const size_t max_count = SIZE_MAX / element_size;
		const size_t remainder = SIZE_MAX % element_size;
		const int size_is_OK = (max_count > count) || ((max_count == count) && (remainder == 0U));
		assert(size_is_OK);
		if (!size_is_OK)
			return NULL;
	}
	size = count * element_size;
	memory = pool_malloc_internal(pool, size);
	if (memory != NULL)
		memset(memory, 0, size);
	return memory;
}

static void pool_free_internal(void *pool, void *memory)
{
	pool_info_type *pool_info = NULL;
	block_info_type *block_info = NULL, *next = NULL;
	void *last_block = NULL;
	int heap_corruption_detected = 0, repeated_free_detected = 0, block_size_is_correct = 0;

	if (memory == NULL || !pool_memory_address_is_valid(pool, memory))
		return;

	pool_info = (pool_info_type*) pool;
	block_info = ((block_info_type*) memory) - 1U;
	heap_corruption_detected = pool_detect_heap_corruption(pool_info, block_info);
	repeated_free_detected = pool_detect_repeated_free(pool_info, block_info);
	block_size_is_correct = pool_check_block_size(pool_info, block_info);
	if (heap_corruption_detected || repeated_free_detected || !block_size_is_correct)
		return;

	pool_set_block_as_free(block_info);
	pool_info->allocated_blocks--;
	last_block = pool_get_last_block(pool);
	next = pool_get_next_block(block_info);

	if (pool_info->first_free_block == NULL || (void*) block_info < (void*) pool_info->first_free_block) {
		pool_info->first_free_block = block_info;
	}

	if (((unsigned char*) next <= (unsigned char*) last_block - sizeof(block_info_type)) && pool_block_is_available(next)) {
		size_t current_block_size = 0U, next_block_size = 0U, new_block_size = 0U;
		current_block_size = pool_get_block_size(block_info);
		next_block_size = pool_get_block_size(next);
		new_block_size = current_block_size + next_block_size + sizeof *next;
		pool_set_block_size(block_info, new_block_size);
		pool_deactivate_check(next);
		pool_set_block_size(next, 0U);
	}
}

static void *pool_realloc_internal(void *pool, void *memory, size_t new_size)
{
	block_info_type *block_info = NULL;
	size_t size = 0U;
	void *new_memory = NULL;

	if (memory == NULL)
		return pool_malloc_internal(pool, new_size);

	if (!pool_memory_address_is_valid(pool, memory))
		return NULL;

	block_info = ((block_info_type*) memory) - 1U;
	size = pool_get_block_size(block_info);
	if (new_size <= size)
		return memory;

	new_memory = pool_malloc_internal(pool, new_size);
	if (new_memory != NULL) {
		memcpy(new_memory, memory, size);
		pool_free_internal(pool, memory);
	}

	return new_memory;
}

pool_exception_handler_type pool_set_heap_corruption_handler(void *pool, pool_exception_handler_type handler)
{
	pool_exception_handler_type prev_handler = NULL;
	pool_info_type *pool_info = (pool_info_type*) pool;
	if (pool_info) {
		pool_info_type *pool_info = (pool_info_type*) pool;
		const int mutex_is_available = (pool_info->mutex != NULL) && (pool_info->mutex_lock != NULL) && (pool_info->mutex_unlock != NULL);
		if (mutex_is_available) {
			pool_info->mutex_lock(pool_info->mutex);
		}
		prev_handler = pool_info->heap_corruption_handler;
		pool_info->heap_corruption_handler = handler;
		if (mutex_is_available) {
			pool_info->mutex_unlock(pool_info->mutex);
		}
	}
	return prev_handler;
}

pool_exception_handler_type pool_set_memory_leak_handler(void *pool, pool_exception_handler_type handler)
{
	pool_exception_handler_type prev_handler = NULL;
	pool_info_type *pool_info = (pool_info_type*) pool;
	if (pool_info) {
		pool_info_type *pool_info = (pool_info_type*) pool;
		const int mutex_is_available = (pool_info->mutex != NULL) && (pool_info->mutex_lock != NULL) && (pool_info->mutex_unlock != NULL);
		if (mutex_is_available) {
			pool_info->mutex_lock(pool_info->mutex);
		}
		prev_handler = pool_info->memory_leak_handler;
		pool_info->memory_leak_handler = handler;
		if (mutex_is_available) {
			pool_info->mutex_unlock(pool_info->mutex);
		}
	}
	return prev_handler;
}

pool_exception_handler_type pool_set_dangling_pointer_handler(void *pool, pool_exception_handler_type handler)
{
	pool_exception_handler_type prev_handler = NULL;
	pool_info_type *pool_info = (pool_info_type*) pool;
	if (pool_info) {
		pool_info_type *pool_info = (pool_info_type*) pool;
		const int mutex_is_available = (pool_info->mutex != NULL) && (pool_info->mutex_lock != NULL) && (pool_info->mutex_unlock != NULL);
		if (mutex_is_available) {
			pool_info->mutex_lock(pool_info->mutex);
		}
		prev_handler = pool_info->dangling_pointer_handler;
		pool_info->dangling_pointer_handler = handler;
		if (mutex_is_available) {
			pool_info->mutex_unlock(pool_info->mutex);
		}
	}
	return prev_handler;
}

void pool_set_name(void *pool, const char *name)
{
	assert(pool != NULL);
	if (pool != NULL) {
		pool_info_type *pool_info = (pool_info_type*) pool;
		const int mutex_is_available = (pool_info->mutex != NULL) && (pool_info->mutex_lock != NULL) && (pool_info->mutex_unlock != NULL);
		assert(name != NULL);
		if (mutex_is_available) {
			pool_info->mutex_lock(pool_info->mutex);
		}
		if (name != NULL) {
			((pool_info_type*) pool)->name = name;
		} else {
			((pool_info_type*) pool)->name = "";
		}
		if (mutex_is_available) {
			pool_info->mutex_unlock(pool_info->mutex);
		}
	}
}

const char *pool_get_name(void *pool)
{
	const char* name = "";
	assert(pool != NULL);
	if (pool != NULL) {
		pool_info_type *pool_info = (pool_info_type*) pool;
		const int mutex_is_available = (pool_info->mutex != NULL) && (pool_info->mutex_lock != NULL) && (pool_info->mutex_unlock != NULL);
		if (mutex_is_available) {
			pool_info->mutex_lock(pool_info->mutex);
		}
		name = pool_info->name;
		if (mutex_is_available) {
			pool_info->mutex_unlock(pool_info->mutex);
		}
	}
	return name;
}

FILE* pool_set_log_file(void* pool, FILE* log_file)
{
	FILE *previous_log_file = stdout;
	assert(pool != NULL);
	if (pool != NULL) {
		pool_info_type *pool_info = (pool_info_type*) pool;
		const int mutex_is_available = (pool_info->mutex != NULL) && (pool_info->mutex_lock != NULL) && (pool_info->mutex_unlock != NULL);
		if (mutex_is_available) {
			pool_info->mutex_lock(pool_info->mutex);
		}
		previous_log_file = pool_info->log_file;
		pool_info->log_file = (log_file != NULL) ? log_file : stdout;
		if (mutex_is_available) {
			pool_info->mutex_unlock(pool_info->mutex);
		}
	}
	return previous_log_file;
}

FILE* pool_get_log_file(void* pool)
{
	FILE* log_file = stdout;
	assert(pool != NULL);
	if (pool != NULL) {
		pool_info_type *pool_info = (pool_info_type*) pool;
		const int mutex_is_available = (pool_info->mutex != NULL) && (pool_info->mutex_lock != NULL) && (pool_info->mutex_unlock != NULL);
		if (mutex_is_available) {
			pool_info->mutex_lock(pool_info->mutex);
		}
		log_file = pool_info->log_file;
		if (mutex_is_available) {
			pool_info->mutex_unlock(pool_info->mutex);
		}
	}
	return log_file;
}

void *pool_malloc(void *pool, size_t size)
{
	void *memory = NULL;
	assert(pool != NULL);
	if (pool) {
		pool_info_type *pool_info = (pool_info_type*) pool;
		const int mutex_is_available = (pool_info->mutex != NULL) && (pool_info->mutex_lock != NULL) && (pool_info->mutex_unlock != NULL);
		if (mutex_is_available) {
			pool_info->mutex_lock(pool_info->mutex);
		}
		memory = pool_malloc_internal(pool, size);
		if (memory == NULL) {
			pool_defragment_internal(pool);
			memory = pool_malloc_internal(pool, size);
		}
		if (mutex_is_available) {
			pool_info->mutex_unlock(pool_info->mutex);
		}
	}
	return memory;
}

void *pool_calloc(void *pool, size_t count, size_t element_size)
{
	void *memory = NULL;
	assert(pool != NULL);
	if (pool != NULL) {
		pool_info_type *pool_info = (pool_info_type*) pool;
		const int mutex_is_available = (pool_info->mutex != NULL) && (pool_info->mutex_lock != NULL) && (pool_info->mutex_unlock != NULL);
		if (mutex_is_available) {
			pool_info->mutex_lock(pool_info->mutex);
		}
		memory = pool_calloc_internal(pool, count, element_size);
		if (memory == NULL) {
			pool_defragment_internal(pool);
			memory = pool_calloc_internal(pool, count, element_size);
		}
		if (mutex_is_available) {
			pool_info->mutex_unlock(pool_info->mutex);
		}
	}
	return memory;
}

void *pool_realloc(void *pool, void *memory, size_t new_size)
{
	void *new_memory = NULL;
	assert(pool != NULL);
	if (pool != NULL) {
		pool_info_type *pool_info = (pool_info_type*) pool;
		const int mutex_is_available = (pool_info->mutex != NULL) && (pool_info->mutex_lock != NULL) && (pool_info->mutex_unlock != NULL);
		if (mutex_is_available) {
			pool_info->mutex_lock(pool_info->mutex);
		}
		new_memory = pool_realloc_internal(pool, memory, new_size);
		if (new_memory == NULL) {
			pool_defragment_internal(pool);
			new_memory = pool_realloc_internal(pool, memory, new_size);
		}
		if (mutex_is_available) {
			pool_info->mutex_unlock(pool_info->mutex);
		}
	}
	return new_memory;
}

void pool_free(void *pool, void *memory)
{
	assert(pool != NULL);
	if (pool != NULL) {
		pool_info_type *pool_info = (pool_info_type*) pool;
		const int mutex_is_available = (pool_info->mutex != NULL) && (pool_info->mutex_lock != NULL) && (pool_info->mutex_unlock != NULL);
		if (mutex_is_available) {
			pool_info->mutex_lock(pool_info->mutex);
		}
		pool_free_internal(pool, memory);
		if (mutex_is_available) {
			pool_info->mutex_unlock(pool_info->mutex);
		}
	}
}

void pool_defragment(void *pool)
{
	assert(pool != NULL);
	if (pool != NULL) {
		pool_info_type *pool_info = (pool_info_type*) pool;
		const int mutex_is_available = (pool_info->mutex != NULL) && (pool_info->mutex_lock != NULL) && (pool_info->mutex_unlock != NULL);
		if (mutex_is_available) {
			pool_info->mutex_lock(pool_info->mutex);
		}
		pool_defragment_internal(pool);
		if (mutex_is_available) {
			pool_info->mutex_unlock(pool_info->mutex);
		}
	}
}
