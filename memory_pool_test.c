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
	void *mem[BLOCK_COUNT] = {0};

	srand(time(NULL));
	pool = pool_create(2048);
	if (!pool) {
		printf("Failed to create the memory pool.\n");
		return 1;
	}

	pool_set_name(pool, "example");

	for (i = 0; i < BLOCK_COUNT; i++) {
		mem[i] = pool_malloc(pool, 32);
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
