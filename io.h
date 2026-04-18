/* Copyright (C) 2025 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>


/**
 * Size of the buffer used for copying data from one file descriptor to another.
 **/
#ifndef IO_COPY_BUFSIZE
#define IO_COPY_BUFSIZE (1024 * 1024)
#endif

#ifndef IO_SOCK_DATA_BUFSIZE
#define IO_SOCK_DATA_BUFSIZE (4 * 1024 * 1024)
#endif

#ifndef IO_SOCK_CTRL_BUFSIZE
#define IO_SOCK_CTRL_BUFSIZE (64 * 1024)
#endif

#if defined(__PROSPERO__) || defined(__ORBIS__)
#ifndef IO_AIO_READ_QUEUE_DEPTH
#define IO_AIO_READ_QUEUE_DEPTH 8
#endif

#ifndef IO_AIO_WRITE_QUEUE_DEPTH
#define IO_AIO_WRITE_QUEUE_DEPTH 4
#endif

#define IO_AIO_MAX_QUEUE_DEPTH \
  ((IO_AIO_READ_QUEUE_DEPTH > IO_AIO_WRITE_QUEUE_DEPTH) ? \
   IO_AIO_READ_QUEUE_DEPTH : IO_AIO_WRITE_QUEUE_DEPTH)

#ifndef IO_AIO_CHUNK_SIZE
#define IO_AIO_CHUNK_SIZE (4 * 1024 * 1024)
#endif

#ifndef IO_AIO_SCHED_WINDOW
#define IO_AIO_SCHED_WINDOW 32
#endif

#ifndef IO_AIO_DELAYED_COUNT
#define IO_AIO_DELAYED_COUNT 32
#endif

#ifndef IO_AIO_SPLIT_ENABLE
#define IO_AIO_SPLIT_ENABLE 1
#endif

#ifndef IO_AIO_SPLIT_SIZE
#define IO_AIO_SPLIT_SIZE IO_AIO_CHUNK_SIZE
#endif

#ifndef IO_AIO_SPLIT_CHUNK_SIZE
#define IO_AIO_SPLIT_CHUNK_SIZE (1 * 1024 * 1024)
#endif

typedef struct {
  struct {
    int64_t returnValue;
    uint32_t state;
  } result;
  struct {
    off_t offset;
    size_t nbyte;
    void *buf;
    void *result;
    int fd;
  } req;
  int id;
  size_t len;
  ssize_t result_len;
  int in_flight;
  int ready;
} io_aio_slot_t;
#endif


/**
 * Read exactly N bytes from the given file descriptor.
 **/
int io_nread(int fd, void* buf, size_t n);


/**
 * Write exactly N bytes to the given file descriptor.
 **/
int io_nwrite(int fd, const void* buf, size_t n);


/**
 * Copy exactly N bytes from one file descriptor to another.
 **/
int io_ncopy(int fd_in, int fd_out, size_t n);


/**
 * Copy exactly N bytes using a caller-provided buffer.
 **/
int io_ncopy_buf(int fd_in, int fd_out, size_t n, void *buf, size_t bufsize);


/**
 * Copy exactly N bytes from a file descriptor to a socket.
 **/
int io_sendfile(int fd, int sock, off_t off, size_t n);


/**
 * Read exactly N bytes from the given file descriptor without affecting its
 * position.
 **/
int io_pread(int fd, void* buf, size_t n, off_t off);


/**
 * Write exactly N bytes to the given file descriptor without affecting its
 * position.
 **/
int io_pwrite(int fd, const void* buf, size_t n, off_t off);


/**
 * Copy exactly N bytes from one file descriptor to another without afftecting
 * their positions.
 **/
int io_pcopy(int fd_in, int fd_out, off_t off_in, off_t off_out, size_t n);


/**
 * Apply socket buffer sizes and latency settings.
 **/
int io_set_socket_opts(int fd, int is_data);


#if defined(__PROSPERO__) || defined(__ORBIS__)
/**
 * Ensure kernel AIO is available for the current process.
 **/
int io_aio_require(void);


/**
 * Submit a file read through kernel AIO.
 **/
int io_aio_read_submit(io_aio_slot_t *slot, int fd, void *buf, size_t len,
                       off_t off);


/**
 * Submit a file write through kernel AIO.
 **/
int io_aio_write_submit(io_aio_slot_t *slot, int fd, const void *buf,
                        size_t len, off_t off);


/**
 * Wait for any in-flight request in the slot array to complete.
 *
 * Returns the number of newly completed slots.
 **/
int io_aio_wait_any(io_aio_slot_t slots[], int count);


/**
 * Drain all in-flight AIO requests.
 **/
int io_aio_drain(io_aio_slot_t slots[], int count);
#endif
