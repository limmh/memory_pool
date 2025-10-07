CC=gcc -std=c89
CFLAGS=-Wall

all: 	memory_pool_test \
	memory_pool_test_dp \
	memory_pool_test_leak \
	memory_pool_test_hc \
	mutex_test \
	memory_pool.a \
	logging.a \
	mutex.a

memory_pool_test: memory_pool_test.c memory_pool.h memory_pool.a mutex.a
	$(CC) $(CFLAGS) -o memory_pool_test memory_pool_test.c -L. memory_pool.a mutex.a

memory_pool_test_dp: memory_pool_test.c memory_pool.h memory_pool.a mutex.a
	$(CC) $(CFLAGS) -o memory_pool_test_dp memory_pool_test.c -DMEMORY_POOL_TEST_ENABLE_DANGLING_POINTER -L. memory_pool.a mutex.a

memory_pool_test_hc: memory_pool_test.c memory_pool.h memory_pool.a mutex.a
	$(CC) $(CFLAGS) -o memory_pool_test_hc memory_pool_test.c -DMEMORY_POOL_TEST_ENABLE_HEAP_CORRUPTION -L. memory_pool.a mutex.a

memory_pool_test_leak: memory_pool_test.c memory_pool.h memory_pool.a mutex.a
	$(CC) $(CFLAGS) -o memory_pool_test_leak memory_pool_test.c -DMEMORY_POOL_TEST_ENABLE_MEMORY_LEAK -L. memory_pool.a mutex.a
 
memory_pool.a: memory_pool.o logging.o
	ar rcs memory_pool.a memory_pool.o logging.o

memory_pool.o: memory_pool.c memory_pool.h logging.h mutex.h
	$(CC) $(CFLAGS) -c memory_pool.c -DMEMORY_POOL_WITH_ERROR_LOGGING

logging.a: logging.o
	ar rcs logging.a logging.o

logging.o: logging.c logging.h
	$(CC) $(CFLAGS) -c logging.c

mutex_test: mutex_test.o mutex.a
	$(CC) -o mutex_test mutex_test.o -L. mutex.a -pthread

mutex_test.o: mutex_test.c mutex.h
	$(CC) $(CFLAGS) -c mutex_test.c

mutex.a: mutex.o
	ar rcs mutex.a mutex.o

mutex.o: mutex.c mutex.h
	$(CC) $(CFLAGS) -c mutex.c

clean:
	rm -f memory_pool_test memory_pool_test_dp memory_pool_test_hc memory_pool_test_leak
	rm -f memory_pool.a memory_pool.o
	rm -f logging.a logging.o
	rm -f mutex.a mutex.o
	rm -f mutex_test mutex_test.o
