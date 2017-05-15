Memory pool
===========

## Introduction

This is an example of a fixed size memory pool.
It can be used in single-threaded and multi-threaded applications to debug memory issues.

## Supported platforms

- Windows
- Ubuntu (may work on other Linux or POSIX platforms as well)

## Purposes

- To replace malloc() to debug memory problems (heap corruption, dangling pointers, memory leaks)
- To learn more about memory management

## Limitations

- The total size of the memory pool is fixed during creation and cannot be changed afterwards.
- The performance is low when many threads access the memory pool simultaneously.
