#ifndef MY_MUTEX_H
#define MY_MUTEX_H

#ifndef MY_MUTEX_EXPORT
#define MY_MUTEX_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

MY_MUTEX_EXPORT void *mutex_create(); /* returns NULL on failure */
MY_MUTEX_EXPORT void mutex_destroy(void *mutex);
MY_MUTEX_EXPORT int mutex_lock(void *mutex); /* returns 0 on success, non-zero otherwise */
MY_MUTEX_EXPORT int mutex_unlock(void *mutex); /* returns 0 on success, non-zero otherwise */

#ifdef __cplusplus
}
#endif

#endif
