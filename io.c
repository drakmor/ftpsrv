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

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/errno.h>

#include "io.h"

#ifndef FTP_CTRL_TIMEOUT_SEC
#define FTP_CTRL_TIMEOUT_SEC 600
#endif
#ifndef FTP_DATA_TIMEOUT_SEC
#define FTP_DATA_TIMEOUT_SEC 300
#endif

#if defined(__PROSPERO__) || defined(__ORBIS__)
#define SCE_OK 0
#define SCE_KERNEL_AIO_PRIORITY_MID 2
#define SCE_KERNEL_AIO_WAIT_OR 0x02
#define SCE_KERNEL_AIO_STATE_NOTIFIED 0x10000
#define SCE_KERNEL_AIO_STATE_COMPLETED 3
#define SCE_KERNEL_AIO_STATE_ABORTED 4
#define SCE_KERNEL_ERROR_ESRCH (-2147352573)
#define SCE_KERNEL_ERROR_EFAULT (-2147352562)
#define SCE_KERNEL_ERROR_EBUSY (-2147352560)
#define SCE_KERNEL_ERROR_EINVAL (-2147352554)

typedef unsigned int SceKernelUseconds;

typedef struct {
  int schedulingWindowSize;
  int delayedCountLimit;
  uint32_t enableSplit;
  uint32_t splitSize;
  uint32_t splitChunkSize;
} SceKernelAioSchedulingParam;

typedef struct {
  SceKernelAioSchedulingParam low;
  SceKernelAioSchedulingParam mid;
  SceKernelAioSchedulingParam high;
} SceKernelAioParam;

typedef int SceKernelAioSubmitId;

typedef struct {
  off_t offset;
  size_t nbyte;
  void *buf;
  void *result;
  int fd;
} SceKernelAioRWRequest;

extern void sceKernelAioInitializeParam(SceKernelAioParam *param);
extern int sceKernelAioSetParam(SceKernelAioSchedulingParam *param,
                                int schedulingWindowSize,
                                int delayedCountLimit,
                                uint32_t enableSplit,
                                uint32_t splitSize,
                                uint32_t splitChunkSize);
extern int sceKernelAioInitializeImpl(void *param, int size);
extern int sceKernelAioSubmitReadCommands(SceKernelAioRWRequest req[],
                                          int size, int prio,
                                          SceKernelAioSubmitId *id);
extern int sceKernelAioSubmitWriteCommands(SceKernelAioRWRequest req[],
                                           int size, int prio,
                                           SceKernelAioSubmitId *id);
extern int sceKernelAioPollRequests(SceKernelAioSubmitId id[], int num,
                                    int states[]);
extern int sceKernelAioWaitRequests(SceKernelAioSubmitId id[], int num,
                                    int states[], uint32_t mode,
                                    SceKernelUseconds *usec);
extern int sceKernelAioDeleteRequest(SceKernelAioSubmitId id, int *ret);

#define sceKernelAioInitialize(x) \
  sceKernelAioInitializeImpl((void*)(x), sizeof(SceKernelAioParam))

static pthread_once_t g_io_aio_once = PTHREAD_ONCE_INIT;
static int g_io_aio_ready = 0;
static int g_io_aio_init_err = 0;

static int
io_aio_set_errno(int err) {
  switch(err) {
  case SCE_OK:
    return 0;
  case SCE_KERNEL_ERROR_EBUSY:
    errno = EBUSY;
    return -1;
  case SCE_KERNEL_ERROR_EINVAL:
    errno = EINVAL;
    return -1;
  case SCE_KERNEL_ERROR_EFAULT:
    errno = EFAULT;
    return -1;
  case SCE_KERNEL_ERROR_ESRCH:
    errno = ESRCH;
    return -1;
  default:
    errno = EIO;
    return -1;
  }
}

static void
io_aio_init_once(void) {
  SceKernelAioParam param;
  int ret;

  memset(&param, 0, sizeof(param));
  sceKernelAioInitializeParam(&param);
  ret = sceKernelAioSetParam(&param.mid,
                             IO_AIO_SCHED_WINDOW,
                             IO_AIO_DELAYED_COUNT,
                             IO_AIO_SPLIT_ENABLE,
                             IO_AIO_SPLIT_SIZE,
                             IO_AIO_SPLIT_CHUNK_SIZE);
  if(ret != SCE_OK) {
    g_io_aio_init_err = ret;
    g_io_aio_ready = 0;
    return;
  }
  ret = sceKernelAioInitialize(&param);
  g_io_aio_init_err = ret;
  g_io_aio_ready = (ret == SCE_OK || ret == SCE_KERNEL_ERROR_EBUSY);
}

static int
io_aio_delete_request_checked(SceKernelAioSubmitId id) {
  int ret = 0;
  int rc = sceKernelAioDeleteRequest(id, &ret);

  if(rc != SCE_OK) {
    return io_aio_set_errno(rc);
  }
  if(ret != SCE_OK) {
    return io_aio_set_errno(ret);
  }

  return 0;
}

int
io_aio_require(void) {
  pthread_once(&g_io_aio_once, io_aio_init_once);
  if(g_io_aio_ready) {
    return 0;
  }

  if(g_io_aio_init_err) {
    return io_aio_set_errno(g_io_aio_init_err);
  }
  errno = ENOSYS;
  return -1;
}

int
io_aio_read_submit(io_aio_slot_t *slot, int fd, void *buf, size_t len,
                   off_t off) {
  SceKernelAioRWRequest *req = (SceKernelAioRWRequest*)&slot->req;

  memset(&slot->result, 0, sizeof(slot->result));
  req->offset = off;
  req->nbyte = len;
  req->buf = buf;
  req->result = &slot->result;
  req->fd = fd;
  slot->len = len;
  slot->result_len = 0;
  slot->ready = 0;

  {
    int rc = sceKernelAioSubmitReadCommands(req, 1, SCE_KERNEL_AIO_PRIORITY_MID,
                                            &slot->id);
    if(rc != SCE_OK) {
      return io_aio_set_errno(rc);
    }
  }

  slot->in_flight = 1;
  return 0;
}

int
io_aio_write_submit(io_aio_slot_t *slot, int fd, const void *buf,
                    size_t len, off_t off) {
  SceKernelAioRWRequest *req = (SceKernelAioRWRequest*)&slot->req;

  memset(&slot->result, 0, sizeof(slot->result));
  req->offset = off;
  req->nbyte = len;
  req->buf = (void*)buf;
  req->result = &slot->result;
  req->fd = fd;
  slot->len = len;
  slot->result_len = 0;
  slot->ready = 0;

  {
    int rc = sceKernelAioSubmitWriteCommands(req, 1, SCE_KERNEL_AIO_PRIORITY_MID,
                                             &slot->id);
    if(rc != SCE_OK) {
      return io_aio_set_errno(rc);
    }
  }

  slot->in_flight = 1;
  return 0;
}

static int
io_aio_process_states(io_aio_slot_t slots[], const int states[],
                      const int index_map[], int pending) {
  int i;
  int completed = 0;
  int first_errno = 0;

  for(i=0; i<pending; i++) {
    io_aio_slot_t *slot = &slots[index_map[i]];
    int state = states[i];

    if(state < 0) {
      slot->in_flight = 0;
      if(!first_errno) {
        (void)io_aio_set_errno(state);
        first_errno = errno;
      }
      continue;
    }

    state &= ~SCE_KERNEL_AIO_STATE_NOTIFIED;
    if(state != SCE_KERNEL_AIO_STATE_COMPLETED &&
       state != SCE_KERNEL_AIO_STATE_ABORTED) {
      continue;
    }

    if(io_aio_delete_request_checked(slot->id) != 0) {
      slot->in_flight = 0;
      if(!first_errno) {
        first_errno = errno;
      }
      continue;
    }

    slot->in_flight = 0;
    if(state != SCE_KERNEL_AIO_STATE_COMPLETED ||
       slot->result.returnValue != (int64_t)slot->len) {
      if(!first_errno) {
        first_errno = EIO;
      }
      continue;
    }

    slot->ready = 1;
    slot->result_len = (ssize_t)slot->result.returnValue;
    completed++;
  }

  if(first_errno) {
    errno = first_errno;
    return -1;
  }

  return completed;
}

static int
io_aio_count_pending(io_aio_slot_t slots[], int count) {
  int i;
  int pending = 0;

  for(i=0; i<count; i++) {
    if(slots[i].in_flight) {
      pending++;
    }
  }

  return pending;
}

int
io_aio_wait_any(io_aio_slot_t slots[], int count) {
  SceKernelAioSubmitId ids[IO_AIO_MAX_QUEUE_DEPTH];
  int states[IO_AIO_MAX_QUEUE_DEPTH];
  int index_map[IO_AIO_MAX_QUEUE_DEPTH];
  int pending = 0;
  int i;
  int rc;
  int completed;

  for(i=0; i<count; i++) {
    if(slots[i].in_flight) {
      ids[pending] = slots[i].id;
      states[pending] = 0;
      index_map[pending] = i;
      pending++;
    }
  }

  if(!pending) {
    return 0;
  }

  rc = sceKernelAioPollRequests(ids, pending, states);
  if(rc != SCE_OK) {
    return io_aio_set_errno(rc);
  }

  completed = io_aio_process_states(slots, states, index_map, pending);
  if(completed != 0) {
    return completed;
  }

  rc = sceKernelAioWaitRequests(ids, pending, states, SCE_KERNEL_AIO_WAIT_OR,
                                NULL);
  if(rc != SCE_OK) {
    return io_aio_set_errno(rc);
  }

  return io_aio_process_states(slots, states, index_map, pending);
}

int
io_aio_drain(io_aio_slot_t slots[], int count) {
  int ret;
  int pending_before;
  int pending_after;
  int rc = 0;

  for(;;) {
    pending_before = io_aio_count_pending(slots, count);
    if(!pending_before) {
      break;
    }

    ret = io_aio_wait_any(slots, count);
    pending_after = io_aio_count_pending(slots, count);

    if(ret < 0) {
      if(pending_after < pending_before) {
        if(rc == 0) {
          rc = -1;
        }
        continue;
      }
      return -1;
    }
    if(ret == 0) {
      errno = EIO;
      return -1;
    }
  }

  return rc;
}
#endif


/**
 * Read exactly n bytes unless an error occurs.
 **/
int
io_nread(int fd, void* buf, size_t n) {
  size_t off = 0;

  while(off < n) {
    ssize_t r = read(fd, (char*)buf + off, n - off);
    if(r < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    if(!r) {
      errno = EIO;
      return -1;
    }
    off += (size_t)r;
  }

  return 0;
}


/**
 * Write exactly n bytes unless an error occurs.
 **/
int
io_nwrite(int fd, const void* buf, size_t n) {
  size_t off = 0;

  while(off < n) {
    ssize_t r = write(fd, (const char*)buf + off, n - off);
    if(r < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    if(!r) {
      errno = EIO;
      return -1;
    }
    off += (size_t)r;
  }

  return 0;
}


/**
 * Copy a fixed number of bytes using a temporary buffer.
 **/
int
io_ncopy(int fd_in, int fd_out, size_t size) {
  size_t copied = 0;
  void* buf;
  size_t n;

  if(!(buf=malloc(IO_COPY_BUFSIZE))) {
    return -1;
  }

  while(copied < size) {
    n = size - copied;
    if(n > IO_COPY_BUFSIZE) {
      n = IO_COPY_BUFSIZE;
    }

    if(io_nread(fd_in, buf, n)) {
      free(buf);
      return -1;
    }
    if(io_nwrite(fd_out, buf, n)) {
      free(buf);
      return -1;
    }

    copied += n;
  }

  free(buf);
  return 0;
}


/**
 * Read exactly n bytes from an offset unless an error occurs.
 **/
int
io_pread(int fd, void* buf, size_t n, off_t off) {
  size_t done = 0;

  while(done < n) {
    ssize_t r = pread(fd, (char*)buf + done, n - done, off + (off_t)done);
    if(r < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    if(!r) {
      errno = EIO;
      return -1;
    }
    done += (size_t)r;
  }

  return 0;
}


/**
 * Write exactly n bytes to an offset unless an error occurs.
 **/
int
io_pwrite(int fd, const void* buf, size_t n, off_t off) {
  size_t done = 0;

  while(done < n) {
    ssize_t r = pwrite(fd, (const char*)buf + done, n - done,
                       off + (off_t)done);
    if(r < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    if(!r) {
      errno = EIO;
      return -1;
    }
    done += (size_t)r;
  }

  return 0;
}


/**
 * Copy a fixed number of bytes using pread/pwrite.
 **/
int
io_pcopy(int fd_in, int fd_out, off_t off_in, off_t off_out, size_t size) {
  size_t copied = 0;
  void* buf;
  size_t n;

  if(!(buf=malloc(IO_COPY_BUFSIZE))) {
    return -1;
  }

  while(copied < size) {
    n = size - copied;
    if(n > IO_COPY_BUFSIZE) {
      n = IO_COPY_BUFSIZE;
    }

    if(io_pread(fd_in, buf, n, off_in)) {
      free(buf);
      return -1;
    }
    if(io_pwrite(fd_out, buf, n, off_out)) {
      free(buf);
      return -1;
    }

    off_out += (off_t)n;
    off_in += (off_t)n;
    copied += n;
  }

  free(buf);
  return 0;
}

/**
 * Copy a fixed number of bytes using a caller-provided buffer.
 **/
int
io_ncopy_buf(int fd_in, int fd_out, size_t size, void* buf, size_t bufsize) {
  size_t copied = 0;
  size_t n;

  if(!buf || !bufsize) {
    errno = EINVAL;
    return -1;
  }

  while(copied < size) {
    n = size - copied;
    if(n > bufsize) {
      n = bufsize;
    }

    if(io_nread(fd_in, buf, n)) {
      return -1;
    }
    if(io_nwrite(fd_out, buf, n)) {
      return -1;
    }

    copied += n;
  }

  return 0;
}

/**
 * Configure socket buffers, timeouts, and keepalive settings.
 **/
int
io_set_socket_opts(int fd, int is_data) {
  int rc = 0;
  int buf = is_data ? IO_SOCK_DATA_BUFSIZE : IO_SOCK_CTRL_BUFSIZE;

  if(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf)) < 0) {
    rc = -1;
  }
  if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf)) < 0) {
    rc = -1;
  }

  int timeout_sec = is_data ? FTP_DATA_TIMEOUT_SEC : FTP_CTRL_TIMEOUT_SEC;
  if(timeout_sec > 0) {
    struct timeval tv;
    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = timeout_sec;
    if(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
      rc = -1;
    }
    if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
      rc = -1;
    }
  }

#ifdef SO_KEEPALIVE
  if(!is_data) {
    (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,  &(int){1}, sizeof(int));

    #ifdef TCP_KEEPIDLE
      int idle = 30;
      (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    #endif
    #ifdef TCP_KEEPINTVL
      int intvl = 10;
      (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    #endif
    #ifdef TCP_KEEPCNT
      int cnt = 3;
      (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
    #endif
  }
#endif

#ifdef TCP_NODELAY
  if(!is_data) {
    if(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,  &(int){1}, sizeof(int)) < 0) {
      rc = -1;
    }
  }
#endif

  return rc;
}
