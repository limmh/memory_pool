#include "memory_pool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char characters[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static const size_t character_count = sizeof(characters) / sizeof(characters[0]) - 1;

void set_random_text(char *buffer, size_t buffer_size)
{
	size_t i;
	for (i = 0; i < buffer_size - 1; i++)
		buffer[i] = characters[rand() % character_count];
	buffer[buffer_size - 1] = '\0';
}

#define BLOCK_COUNT 10

int main(void)
{
	void *pool;
	int i;
	void *mem[BLOCK_COUNT] = {NULL};

	srand(time(NULL));
	pool = pool_create(2048);
	if (!pool) {
		printf("Failed to create the memory pool.\n");
		return 1;
	}

	pool_set_name(pool, "example");

	for (i = 0; i < BLOCK_COUNT; i++) {
		mem[i] = pool_calloc(pool, 32, sizeof(char));
		if (mem[i]) {
			set_random_text((char*) mem[i], 32);
			printf("%s\n", (char*) mem[i]);
		} else {
			printf("Failed to allocate memory block %d.\n", i + 1);
		}
	}

	for (i = 0; i < BLOCK_COUNT; i++) {
		void *new_mem = pool_realloc(pool, mem[i], 64);
		if (new_mem) {
			mem[i] = new_mem;
			set_random_text((char*) mem[i], 64);
			printf("%s\n", (char*) mem[i]);
		} else {
			printf("Failed to reallocate memory block %d.\n", i + 1);
		}
	}

#ifdef ENABLE_HEAP_CORRUPTION
	((char*)mem[BLOCK_COUNT - 1])[63] = '0';
	((char*)mem[BLOCK_COUNT - 1])[64] = '\0';
#endif

#ifndef ENABLE_MEMORY_LEAK
	for (i = 0; i < BLOCK_COUNT; i++)
		pool_free(pool, mem[i]);

#endif

#ifdef ENABLE_DANGLING_POINTER
	for (i = 0; i < BLOCK_COUNT; i++)
		pool_free(pool, mem[i]);
#endif

	pool_destroy(pool);
	return 0;
}
