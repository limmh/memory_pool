#include "mutex.h"

#include <stdio.h>
#include <string.h>

#if defined _WIN32 || defined _WIN64
#include <process.h>
#include <Windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

typedef struct thread_data_s {
	void *mutex;
	int thread_count;
	int n;
	int exit;
	char text[101];
} thread_data_s;

#if defined _WIN32 || defined _WIN64
unsigned int __stdcall thread_procedure(void *param)
#else
void *thread_procedure(void *param)
#endif
{
	const char *text[] = {
		"Hello World",
		"The quick brown fox jumps over the lazy dog.",
		"0123456789",
		"Haha"
	};

	int thread_id;
	thread_data_s *data = (thread_data_s*) param;

	mutex_lock(data->mutex);
	thread_id = ++(data->thread_count);
	mutex_unlock(data->mutex);
	
	for (;;) {
		int i, exit;

		mutex_lock(data->mutex);
		exit = data->exit;
		if (!exit) {
			i = data->n % (int) (sizeof text / sizeof text[0]);
			data->n++;
			strncpy(data->text, text[i], sizeof data->text);
			data->text[(sizeof data->text) - 1] = '\0';
			printf("Thread %d: count = %d, text = %s\n", thread_id, data->n, data->text);
		}
		mutex_unlock(data->mutex);

		if (exit)
			break;

#if defined _WIN32 || defined _WIN64
		Sleep(1000);
#else
		sleep(1);
#endif
	}

#if defined _WIN32 || defined _WIN64
	return 0;
#else
	return (void*) 0;
#endif
}

#define MAX_THREAD_COUNT 3

int main(void)
{
	const int seconds = 30;
	int i;

#if defined _WIN32 || defined _WIN64
	HANDLE threads[MAX_THREAD_COUNT];
#else
	pthread_t threads[MAX_THREAD_COUNT];
#endif

	thread_data_s data;
	data.n = 0;
	data.thread_count = 0;
	data.exit = 0;
	memset(data.text, 0, sizeof data.text);
	data.mutex = mutex_create();
	if (!data.mutex) {
		printf("Error creating mutex.\n");
		return -1;
	}

#if defined _WIN32 || defined _WIN64
	for (i = 0; i < MAX_THREAD_COUNT; i++)
		threads[i] = (HANDLE) _beginthreadex(NULL, 0, thread_procedure, &data, 0, NULL);

	Sleep(seconds * 1000);
#else
	for (i = 0; i < MAX_THREAD_COUNT; i++)
		pthread_create(&threads[i], NULL, thread_procedure, &data);

	sleep(seconds);
#endif

	for (i = 0; i < MAX_THREAD_COUNT; i++) {
		mutex_lock(data.mutex);
		data.exit = 1;
		mutex_unlock(data.mutex);
	}

#if defined _WIN32 || defined _WIN64
	WaitForMultipleObjects(MAX_THREAD_COUNT, threads, TRUE, INFINITE);
#else
	for (i = 0; i < MAX_THREAD_COUNT; i++)
		pthread_join(threads[i], NULL);
#endif

	mutex_destroy(data.mutex);
	return 0;
}
