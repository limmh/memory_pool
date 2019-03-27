cmake_minimum_required(VERSION 3.0)

project(memory_pool)

add_library(logging logging.c logging.h)

add_library(mutex mutex.c mutex.h)
if (UNIX)
	target_link_libraries(mutex pthread)
endif (UNIX)

add_executable(mutex_test mutex_test.c)
target_link_libraries(mutex_test mutex)

add_library(memory_pool memory_pool.c memory_pool.h)
target_compile_definitions(memory_pool PRIVATE MEMORY_POOL_WITH_THREAD_SAFETY)
target_compile_definitions(memory_pool PRIVATE MEMORY_POOL_WITH_ERROR_LOGGING)
target_link_libraries(memory_pool logging mutex)

add_executable(memory_pool_test memory_pool_test.c)
target_link_libraries(memory_pool_test memory_pool)

add_executable(memory_pool_test_dp memory_pool_test.c)
target_compile_definitions(memory_pool_test_dp PRIVATE ENABLE_DANGLING_POINTER)
target_link_libraries(memory_pool_test_dp memory_pool)

add_executable(memory_pool_test_hc memory_pool_test.c)
target_compile_definitions(memory_pool_test_hc PRIVATE ENABLE_HEAP_CORRUPTION)
target_link_libraries(memory_pool_test_hc memory_pool)

add_executable(memory_pool_test_leak memory_pool_test.c)
target_compile_definitions(memory_pool_test_leak PRIVATE ENABLE_MEMORY_LEAK)
target_link_libraries(memory_pool_test_leak memory_pool)
