#include "memory_pool.h"
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
#include "mutex.h"
#endif
#ifdef MEMORY_POOL_WITH_ERROR_LOGGING
#include "logging.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t)0U - 1U)
#endif

typedef struct pool_info_s
{
	const char *name;
	size_t size;
	void *mutex;
	size_t allocation_count;
	pool_exception_handler_s heap_corruption_handler;
	pool_exception_handler_s memory_leak_handler;
	pool_exception_handler_s dangling_pointer_handler;
} pool_info_s;

typedef struct block_info_s
{
	unsigned char pattern[sizeof(size_t)];
	size_t size;
} block_info_s;

static const size_t mask = (sizeof(size_t) - 1);

static void *pool_get_first_valid_address(const pool_info_s *pool)
{
	unsigned char *start = ((unsigned char*) pool) + sizeof *pool + sizeof(block_info_s);
	return start;
}

static void *pool_get_last_valid_address(const pool_info_s *pool)
{
	unsigned char *start = ((unsigned char*) pool) + sizeof *pool + sizeof(block_info_s);
	return (start + pool->size - 1);
}

static void *pool_get_last_valid_block(void *pool)
{
	unsigned char *addr = (unsigned char*) pool_get_last_valid_address((pool_info_s*) pool);
	addr -= (sizeof(block_info_s) + sizeof(size_t) - 1);
	return addr;
}

static int pool_memory_address_is_valid(void *pool, void *memory)
{
	void *start = NULL, *last = NULL;
	start = pool_get_first_valid_address((pool_info_s*) pool);
	last = pool_get_last_valid_address((pool_info_s*) pool);
	assert(memory >= start);
	assert(memory < last);
	assert(((size_t) memory & mask) == 0);
	return (memory >= start && memory < last && ((size_t) memory & mask) == 0);
}

static size_t pool_calculate_block_size(size_t required)
{
	if (required && (required & mask) == 0)
		return required;
	return (required / sizeof(size_t) + 1) * sizeof(size_t);
}

static size_t pool_get_block_size(const block_info_s *block)
{
	return (block->size & ~mask);
}

static block_info_s *pool_get_next_block(const block_info_s *block)
{
	return (block_info_s*) (((unsigned char*) (block + 1)) + pool_get_block_size(block));
}

static void pool_set_block_as_occupied(block_info_s *block)
{
	block->size |= mask;
}

static void pool_set_block_as_free(block_info_s *block)
{
	block->size &= ~mask;
}

static void pool_set_block_size(block_info_s *block, size_t size)
{
	assert((size & mask) == 0);
	size &= ~mask;
	block->size &= mask;
	block->size |= size;
}

static int pool_block_is_available(const block_info_s *block)
{
	return ((block->size & mask) == 0);
}

static void pool_activate_check(block_info_s *block)
{
	memset(block->pattern, 0xCC, sizeof block->pattern);
}

static void pool_deactivate_check(block_info_s *block)
{
	memset(block->pattern, 0x0, sizeof block->pattern);
}

static void *pool_block_head_is_corrupted(const block_info_s *block)
{
	size_t i = 0U;
	for (; i < sizeof block->pattern; i++)
		if (block->pattern[i] != 0xCC)
			return (void*) &(block->pattern[i]);
	return NULL;
}

static void *pool_block_tail_is_corrupted(const block_info_s *block)
{
	size_t i = 0U;
	block_info_s *next = pool_get_next_block(block);
	for (; i < sizeof block->pattern; i++)
		if (next->pattern[i] != 0xCC)
			return (void*) &(next->pattern[i]);
	return NULL;
}

static int pool_detect_heap_corruption(const pool_info_s *pool, const block_info_s *block)
{
	void *start = NULL, *last = NULL, *error_location = NULL;
	if ((error_location = pool_block_head_is_corrupted(block)) != NULL) {
		size_t block_size = pool_get_block_size(block);
		if (block_size > pool->size)
			block_size = pool->size;

		start = (void*) pool;
		last = (void*) (((unsigned char *) (block + 1)) + block_size - 1);
		if (pool->heap_corruption_handler) {
			pool->heap_corruption_handler(pool->name, start, last, error_location);
		} else {
			if (pool->name[0] != '\0') fprintf(stdout, "%s: ", pool->name);
			fprintf(stdout, "Heap corruption occurred at location %p.\n", error_location);
#ifdef MEMORY_POOL_WITH_ERROR_LOGGING
			logging_display_memory_contents(start, last, stdout);
#endif
		}
		return 1;
	}

	if ((error_location = pool_block_tail_is_corrupted(block)) != NULL) {
		start = (void*) block;
		last = (void*) (((unsigned char*) error_location) + sizeof(size_t) - 1);

		if (pool->heap_corruption_handler) {
			pool->heap_corruption_handler(pool->name, start, last, error_location);
		} else {
			if (pool->name[0] != '\0') fprintf(stdout, "%s: ", pool->name);
			fprintf(stdout, "Heap corruption occurred at location %p.\n", error_location);
#ifdef MEMORY_POOL_WITH_ERROR_LOGGING
			logging_display_memory_contents(start, last, stdout);
#endif
		}
		return 1;
	}
	return 0;
}

static int pool_detect_repeated_free(const pool_info_s *pool, const block_info_s *block)
{
	if (pool_block_is_available(block)) {
		void *start = NULL, *last = NULL, *error_location = NULL;
		start = (void*) block;
		error_location = (void*) block;
		last = (void*) ((unsigned char*) (block + 1) + pool_get_block_size(block) - 1);
		if (pool->dangling_pointer_handler) {
			pool->dangling_pointer_handler(pool->name, start, last, error_location);
		} else {
			if (pool->name[0] != '\0') fprintf(stdout, "%s: ", pool->name);
			fprintf(stdout, "Memory at %p has already been released to the pool.\n", error_location);
#ifdef MEMORY_POOL_WITH_ERROR_LOGGING
			logging_display_memory_contents(start, last, stdout);
#endif
		}
		return 1;
	}
	return 0;
}

static int pool_check_block_size(const pool_info_s *pool, const block_info_s *block)
{
	void *start = NULL, *last = NULL, *error_location = NULL;
	size_t block_size = pool_get_block_size(block);
	if (block_size <= pool->size)
		return 1; /* OK */
	start = (void*) block;
	last = (void*) (((unsigned char*) (block + 1)) + block_size);
	error_location = (void*) &(block->size);
	if (pool->heap_corruption_handler) {
		pool->heap_corruption_handler(pool->name, start, last, error_location);
	} else {
		if (pool->name[0] != '\0') fprintf(stdout, "%s: ", pool->name);
		fprintf(stdout, "The block size at %p (%lu) is more than the pool size (%lu).\n",
			error_location, (unsigned long) block_size, (unsigned long) pool->size);
#ifdef MEMORY_POOL_WITH_ERROR_LOGGING
		logging_display_memory_contents(start, last, stdout);		
#endif
	}
	return 0; /* NOT OK */
}

void *pool_create(size_t size)
{
	void *pool = NULL;
	size_t actual_size = 0U;
	unsigned char *p = NULL;

	size = pool_calculate_block_size(size);
	actual_size = sizeof(pool_info_s) + sizeof(block_info_s) + size + sizeof(size_t);

#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
	void *mutex = mutex_create();
	if (!mutex)
		return NULL;
#endif

	pool = calloc(actual_size, sizeof(unsigned char));
	if (!pool) {
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		mutex_destroy(mutex);
#endif
		return pool;
	}

	pool_info_s *pool_info = (pool_info_s*) pool;
	pool_info->name = "";
	pool_info->size = size;
	pool_info->heap_corruption_handler = NULL;
	pool_info->memory_leak_handler = NULL;
	pool_info->dangling_pointer_handler = NULL;

#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
	pool_info->mutex = mutex;
#else
	pool_info->mutex = NULL;
#endif
	pool_info->allocation_count = 0;

	block_info_s *block = (block_info_s*) (pool_info + 1);
	block->size = size;
	memset(block->pattern, 0xCC, sizeof block->pattern);
	p = ((unsigned char*) (block + 1)) + block->size;
	memset(p, 0xCC, sizeof(size_t));
	return pool;
}

void pool_destroy(void *pool)
{
	pool_info_s *pool_info = NULL;
	block_info_s *block_info = NULL;
	void *last_valid_block = NULL;
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
	void *mutex = NULL;
#endif

	if (!pool) return;

	pool_info = (pool_info_s*) pool;
	block_info = (block_info_s*) (pool_info + 1);
	last_valid_block = pool_get_last_valid_block(pool);

#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
	mutex = ((pool_info_s*) pool)->mutex;
	mutex_lock(mutex);
#endif

	if (pool_info->allocation_count > 0) {
		int more_than_1_block = (pool_info->allocation_count > 1);
		if (pool_info->name[0] != '\0') fprintf(stdout, "%s: ", pool_info->name);
		printf("%lu allocated block%s not released.\n", (unsigned long)  pool_info->allocation_count, (more_than_1_block ? "s were" : " was"));
	}

	while ((void*) block_info <= last_valid_block) {
		if (pool_detect_heap_corruption(pool_info, block_info))
			break;
		if (!pool_block_is_available(block_info)) {
			void *start = (void*) (block_info + 1);
			void *last = (void*) (((unsigned char*) start) + pool_get_block_size(block_info) - 1);
#ifdef MEMORY_POOL_WITH_ERROR_LOGGING
			logging_display_memory_contents(start, last, stdout);
#endif
			if (pool_info->memory_leak_handler)
				pool_info->memory_leak_handler(pool_info->name, start, last, start);
		}
		block_info = pool_get_next_block(block_info);
	}

#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
	mutex_unlock(mutex);
	mutex_destroy(mutex);
#endif

	free(pool);
}

static void pool_defragment_internal(void *pool)
{
	pool_info_s *pool_info = (pool_info_s*) pool;
	block_info_s *block_info = (block_info_s*) (pool_info + 1);
	void *last_valid_block = pool_get_last_valid_block(pool);

	while ((void*) block_info < last_valid_block) {
		if (pool_detect_heap_corruption(pool_info, block_info))
			break;
		if (pool_block_is_available(block_info)) {
			block_info_s *next = pool_get_next_block(block_info);
			if ((void*) next < last_valid_block &&	pool_block_is_available(next)) {
				size_t current_block_size, next_block_size;
				current_block_size = pool_get_block_size(block_info);
				next_block_size = pool_get_block_size(next);
				pool_set_block_size(block_info, current_block_size + next_block_size + sizeof *next);
				pool_deactivate_check(next);
				pool_set_block_size(next, 0);
				continue;
			}
		}
		block_info = pool_get_next_block(block_info);
	}
}

static void *pool_malloc_internal(void *pool, size_t size)
{
	pool_info_s *pool_info = (pool_info_s*) pool;
	block_info_s *block_info = (block_info_s*) (pool_info + 1);
	void *last_valid_block = pool_get_last_valid_block(pool);
	size = pool_calculate_block_size(size);

	while ((void*) block_info <= last_valid_block) {
		unsigned char *p = NULL;
		size_t block_size = 0U;
		block_info_s *next = NULL;

		if (pool_detect_heap_corruption(pool_info, block_info))
			return NULL;

		if (!pool_block_is_available(block_info)) {
			block_info = pool_get_next_block(block_info);
			continue;
		}

		block_size = pool_get_block_size(block_info);
		if (block_size <= (size + sizeof(block_info_s))) {
			if (block_size < size) {
				block_info = pool_get_next_block(block_info);
				continue;
			}

			pool_activate_check(block_info);
			pool_set_block_as_occupied(block_info);
			pool_info->allocation_count++;
			return (void*) ((unsigned char*) (block_info + 1));
		}

		pool_activate_check(block_info);
		pool_set_block_as_occupied(block_info);
		pool_set_block_size(block_info, size);
		p = (unsigned char*) (block_info + 1);

		next = pool_get_next_block(block_info);
		pool_activate_check(next);
		pool_set_block_size(next, block_size - size - sizeof(block_info_s));
		pool_set_block_as_free(next);
		pool_info->allocation_count++;
		return (void*) p;
	}

	return NULL;
}

static void *pool_calloc_internal(void *pool, size_t count, size_t element_size)
{
	size_t size = 0U;
	void *mem = NULL;
	if (count > 0U && element_size > 0U) {
		const size_t max_count = SIZE_MAX / element_size;
		const size_t remainder = SIZE_MAX % element_size;
		const int size_is_OK = (max_count > count) || ((max_count == count) && (remainder == 0U));
		assert(size_is_OK);
		if (!size_is_OK)
			return NULL;
	}
	size = count * element_size;
	mem = pool_malloc_internal(pool, size);
	if (mem)
		memset(mem, 0, size);
	return mem;
}

static void pool_free_internal(void *pool, void *memory)
{
	pool_info_s *pool_info = NULL;
	block_info_s *block_info = NULL, *next = NULL;
	void *last_valid_block = NULL;
	int heap_corruption_detected = 0, repeated_free_detected = 0, block_size_is_correct = 0;

	if (!memory || !pool_memory_address_is_valid(pool, memory))
		return;

	pool_info = (pool_info_s*) pool;
	block_info = ((block_info_s*) memory) - 1;
	heap_corruption_detected = pool_detect_heap_corruption(pool_info, block_info);
	repeated_free_detected = pool_detect_repeated_free(pool_info, block_info);
	block_size_is_correct = pool_check_block_size(pool_info, block_info);
	if (heap_corruption_detected || repeated_free_detected || !block_size_is_correct)
		return;

	pool_set_block_as_free(block_info);
	pool_info->allocation_count--;
	last_valid_block = pool_get_last_valid_block(pool);
	next = pool_get_next_block(block_info);

	if ((void*) next <= last_valid_block && pool_block_is_available(next)) {
		size_t current_block_size = 0U, next_block_size = 0U;
		current_block_size = pool_get_block_size(block_info);
		next_block_size = pool_get_block_size(next);
		pool_set_block_size(block_info, current_block_size + next_block_size + sizeof *next);
		pool_deactivate_check(next);
		pool_set_block_size(next, 0);
	}
}

static void *pool_realloc_internal(void *pool, void *memory, size_t new_size)
{
	block_info_s *block_info;
	size_t size;
	void *new_block;

	if (!memory)
		return pool_malloc_internal(pool, new_size);

	if (!pool_memory_address_is_valid(pool, memory))
		return NULL;

	block_info = ((block_info_s*) memory) - 1;
	size = pool_get_block_size(block_info);
	if (new_size <= size)
		return memory;

	new_block = pool_malloc_internal(pool, new_size);
	if (new_block) {
		memcpy(new_block, memory, size);
		pool_free_internal(pool, memory);
	}

	return new_block;
}

pool_exception_handler_s pool_set_heap_corruption_handler(void *pool, pool_exception_handler_s handler)
{
	pool_exception_handler_s prev_handler = NULL;
	pool_info_s *pool_info = (pool_info_s*) pool;
	if (pool_info) {
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		void *mutex = pool_info->mutex;
		mutex_lock(mutex);
#endif
		prev_handler = pool_info->heap_corruption_handler;
		pool_info->heap_corruption_handler = handler;
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		mutex_unlock(mutex);
#endif
	}
	return prev_handler;
}

pool_exception_handler_s pool_set_memory_leak_handler(void *pool, pool_exception_handler_s handler)
{
	pool_exception_handler_s prev_handler = NULL;
	pool_info_s *pool_info = (pool_info_s*) pool;
	if (pool_info) {
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		void *mutex = pool_info->mutex;
		mutex_lock(mutex);
#endif
		prev_handler = pool_info->memory_leak_handler;
		pool_info->memory_leak_handler = handler;
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		mutex_unlock(mutex);
#endif
	}
	return prev_handler;
}

pool_exception_handler_s pool_set_dangling_pointer_handler(void *pool, pool_exception_handler_s handler)
{
	pool_exception_handler_s prev_handler = NULL;
	pool_info_s *pool_info = (pool_info_s*) pool;
	if (pool_info) {
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		void *mutex = pool_info->mutex;
		mutex_lock(mutex);
#endif
		prev_handler = pool_info->dangling_pointer_handler;
		pool_info->dangling_pointer_handler = handler;
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		mutex_unlock(mutex);
#endif
	}
	return prev_handler;
}

void pool_set_name(void *pool, const char *name)
{
	assert(pool != NULL);
	assert(name != NULL);
	if (pool && name)
		((pool_info_s*) pool)->name = name;
}

const char *pool_get_name(void *pool)
{
	assert(pool != NULL);
	if (pool)
		return ((pool_info_s*) pool)->name;
	return "";
}

void *pool_malloc(void *pool, size_t size)
{
	void *mem = NULL;
	assert(pool != NULL);
	if (pool) {
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		void *mutex = ((pool_info_s*) pool)->mutex;
		mutex_lock(mutex);
#endif
		mem = pool_malloc_internal(pool, size);
		if (!mem) {
			pool_defragment_internal(pool);
			mem = pool_malloc_internal(pool, size);
		}
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		mutex_unlock(mutex);
#endif
	}
	return mem;
}

void *pool_calloc(void *pool, size_t count, size_t element_size)
{
	void *mem = NULL;
	assert(pool != NULL);
	if (pool) {
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		void *mutex = ((pool_info_s*) pool)->mutex;
		mutex_lock(mutex);
#endif
		mem = pool_calloc_internal(pool, count, element_size);
		if (!mem) {
			pool_defragment_internal(pool);
			mem = pool_calloc_internal(pool, count, element_size);
		}
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		mutex_unlock(mutex);
#endif
	}
	return mem;
}

void *pool_realloc(void *pool, void *memory, size_t new_size)
{
	void *mem = NULL;
	assert(pool != NULL);
	if (pool) {
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		void *mutex = ((pool_info_s*) pool)->mutex;
		mutex_lock(mutex);
#endif
		mem = pool_realloc_internal(pool, memory, new_size);
		if (!mem) {
			pool_defragment_internal(pool);
			mem = pool_realloc_internal(pool, memory, new_size);
		}
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		mutex_unlock(mutex);
#endif
	}
	return mem;
}

void pool_free(void *pool, void *memory)
{
	assert(pool != NULL);
	if (pool) {
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		void *mutex = ((pool_info_s*) pool)->mutex;
		mutex_lock(mutex);
#endif
		pool_free_internal(pool, memory);
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		mutex_unlock(mutex);
#endif
	}
}

void pool_defragment(void *pool)
{
	assert(pool != NULL);
	if (pool) {
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		void *mutex = ((pool_info_s*) pool)->mutex;
		mutex_lock(mutex);
#endif
		pool_defragment_internal(pool);
#ifdef MEMORY_POOL_WITH_THREAD_SAFETY
		mutex_unlock(mutex);
#endif
	}
}
