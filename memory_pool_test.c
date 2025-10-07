#include "memory_pool.h"
#include "mutex.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char characters[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static const size_t character_count = sizeof(characters) / sizeof(characters[0]) - 1U;

static void set_random_text(char *buffer, size_t buffer_size)
{
	size_t i = 0U;
	for (; i < buffer_size - 1U; i++)
		buffer[i] = characters[rand() % character_count];
	buffer[buffer_size - 1U] = '\0';
}

#define BLOCK_COUNT 10U

#ifndef MEMORY_POOL_TEST_USE_DEFAULT_POOL_CONFIGURATION
static void *user_mutex_create(void)
{
	return mutex_create();
}

static void user_mutex_destroy(void *mutex)
{
	if (mutex != NULL) {
		mutex_destroy(mutex);
	}
}

static void user_mutex_lock(void *mutex)
{
	assert(mutex != NULL);
	(void) mutex_lock(mutex);
}

static void user_mutex_unlock(void *mutex)
{
	assert(mutex != NULL);
	(void) mutex_unlock(mutex);
}

typedef struct static_buffer_type {
	size_t for_alignment;
	unsigned char buffer[2048];
} static_buffer_type;

static static_buffer_type static_buffer = { 0U, {0U} };

static void *static_buffer_allocate(size_t number_of_bytes)
{
	printf("Number of bytes to allocate: %lu, Buffer size: %lu bytes\n", (unsigned long) number_of_bytes, (unsigned long) sizeof(static_buffer.buffer));
	return (number_of_bytes <= sizeof(static_buffer.buffer)) ? static_buffer.buffer : NULL;
}

static void static_buffer_deallocate(void *memory)
{
	assert(memory == static_buffer.buffer);
	/* do nothing else */
}
#endif

int main(void)
{
	int error_code = 0;
	void *pool = NULL;
	size_t i = 0;
	char *mem[BLOCK_COUNT] = {NULL};
	unsigned int seed = 0U;
#ifndef MEMORY_POOL_TEST_USE_DEFAULT_POOL_CONFIGURATION
	pool_allocator_type pool_allocator = {NULL, NULL};
	pool_mutex_type pool_mutex = {NULL, NULL};
#endif
	time_t t = time(NULL);
	memcpy(&seed, &t, sizeof(seed));
	srand(seed);

#ifndef MEMORY_POOL_TEST_USE_DEFAULT_POOL_CONFIGURATION 
	{
		pool_result_type pool_result = {NULL, 0U};
		pool_allocator.alloc = &static_buffer_allocate;
		pool_allocator.dealloc = &static_buffer_deallocate;
		pool_mutex.mutex = user_mutex_create();
		if (pool_mutex.mutex != NULL) {
			pool_mutex.mutex_lock = &user_mutex_lock;
			pool_mutex.mutex_unlock = &user_mutex_unlock;
		} else {
			error_code = 1;
			printf("Failed to create a mutex.\n");
			goto END;
		}

		pool_result = pool_create_with_allocator_or_mutex_support(1024U, &pool_allocator, &pool_mutex);
		pool = pool_result.pool;
		printf("Actual pool size: %lu bytes\n", pool_result.actual_size);
	}
#else
	pool = pool_create(1024U);
#endif
	if (pool == NULL) {
		error_code = 2;
		printf("Failed to create the memory pool.\n");
		goto END;
	}

	pool_set_name(pool, "Example");
	printf("Size of minimum overhead of pool: %lu\n", (unsigned long) pool_minimum_overhead_size());

	printf("Allocation\n");
	for (i = 0; i < BLOCK_COUNT; i++) {
		mem[i] = (char*) pool_calloc(pool, 32, sizeof(char));
		if (mem[i]) {
			set_random_text(mem[i], 32);
			printf("Block %2lu: %s\n", (unsigned long) i + 1U, mem[i]);
		} else {
			printf("Block %2lu: Failed to allocate memory.\n", (unsigned long) i + 1U);
		}
	}

	printf("Reallocation\n");
	for (i = 0; i < BLOCK_COUNT; i++) {
		char *new_mem = (char*) pool_realloc(pool, mem[i], 64);
		if (new_mem != NULL) {
			mem[i] = new_mem;
			set_random_text(mem[i], 64);
			printf("Block %2lu: %s\n", (unsigned long) i + 1U, mem[i]);
		} else {
			printf("Block %2lu: Failed to reallocate memory.\n", (unsigned long) i + 1U);
		}
	}

#ifdef MEMORY_POOL_TEST_ENABLE_HEAP_CORRUPTION
	{
		const size_t last_block = BLOCK_COUNT - 1U;
		const size_t last_buffer_index = 63U;
		if (mem[last_block] != NULL) {
			mem[last_block][last_buffer_index] = '0';
			mem[last_block][last_buffer_index + 1U] = '\0';
			mem[last_block][last_buffer_index + 2U] = '\0';
			mem[last_block][last_buffer_index + 3U] = '\0';
			mem[last_block][last_buffer_index + 4U] = '\0';
			mem[last_block][last_buffer_index + 5U] = '\0';
			mem[last_block][last_buffer_index + 6U] = '\0';
			mem[last_block][last_buffer_index + 7U] = '\0';
			mem[last_block][last_buffer_index + 8U] = '\0';
		}
	}
#endif

#ifndef MEMORY_POOL_TEST_ENABLE_MEMORY_LEAK
	for (i = 0; i < BLOCK_COUNT; i++)
		pool_free(pool, mem[i]);
#endif

#ifdef MEMORY_POOL_TEST_ENABLE_DANGLING_POINTER
	for (i = 0; i < BLOCK_COUNT; i++)
		pool_free(pool, mem[i]);
#endif

END:
	pool_destroy(pool);
#ifndef  MEMORY_POOL_TEST_USE_DEFAULT_POOL_CONFIGURATION
	user_mutex_destroy(pool_mutex.mutex);
#endif
	return error_code;
}
