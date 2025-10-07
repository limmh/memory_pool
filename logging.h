#ifndef MY_LOGGING_H
#define MY_LOGGING_H

#include <stdio.h>

#ifndef LOGGING_EXPORT
#define LOGGING_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

LOGGING_EXPORT void logging_display_memory_contents(const void *start, const void *last, FILE *fp);

#ifdef __cplusplus
}
#endif

#endif
