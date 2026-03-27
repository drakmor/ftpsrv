/* Copyright (C) 2025 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <unistd.h>

#include <zlib.h>

#include "cmd.h"
#include "io.h"
#include "modez.h"

#ifndef FTP_MODE_Z_CHUNK_SIZE
#define FTP_MODE_Z_CHUNK_SIZE (64 * 1024)
#endif

enum {
  FTP_MODE_Z_DIR_SEND = 1,
  FTP_MODE_Z_DIR_RECV = 2,
};

struct ftp_mode_z {
  int direction;
  int finished;
  int saw_socket_eof;
  z_stream stream;

  unsigned char *buf;
  size_t buf_size;
};

static void
ftp_mode_z_set_proto_errno(void) {
#ifdef EPROTO
  errno = EPROTO;
#else
  errno = EIO;
#endif
}

static void
ftp_mode_z_set_zlib_errno(int zerr) {
  switch(zerr) {
  case Z_MEM_ERROR:
    errno = ENOMEM;
    break;

  case Z_DATA_ERROR:
  case Z_NEED_DICT:
  case Z_STREAM_ERROR:
  case Z_BUF_ERROR:
    ftp_mode_z_set_proto_errno();
    break;

  default:
    errno = EIO;
    break;
  }
}

static int
ftp_mode_z_has_buffered_input(int fd) {
  struct pollfd pfd;

  memset(&pfd, 0, sizeof(pfd));
  pfd.fd = fd;
  pfd.events = POLLIN;

  for(;;) {
    int rc = poll(&pfd, 1, 0);
    if(rc == 0) {
      return 0;
    }
    if(rc < 0) {
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }
    break;
  }

  if(pfd.revents & POLLIN) {
    unsigned char ch;
    ssize_t r;

    do {
      r = recv(fd, &ch, 1, MSG_PEEK);
    } while(r < 0 && errno == EINTR);

    if(r < 0) {
      if(errno == EAGAIN
#ifdef EWOULDBLOCK
         || errno == EWOULDBLOCK
#endif
      ) {
        return 0;
      }
      return -1;
    }
    return r > 0;
  }

  return 0;
}


void
ftp_mode_z_session_init(struct ftp_env *env) {
  env->mode = 'S';
  env->mode_z_level = FTP_MODE_Z_LEVEL_DEFAULT;
  env->mode_z_extra = 1;
  env->mode_z = NULL;
}

static void
ftp_mode_z_free(struct ftp_env *env) {
  if(!env->mode_z) {
    return;
  }

  free(env->mode_z->buf);
  free(env->mode_z);
  env->mode_z = NULL;
}


int
ftp_mode_z_xfer_start(struct ftp_env *env, int is_send) {
  struct ftp_mode_z *ctx;
  int ret;
  int window_bits = env->mode_z_extra ? MAX_WBITS : -MAX_WBITS;

  if(env->mode != 'Z' && env->mode != 'z') {
    return 0;
  }
  if(env->mode_z) {
    errno = EBUSY;
    return -1;
  }

  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    return -1;
  }

  ctx->buf_size = env->xfer_buf_size;
  if(ctx->buf_size < FTP_MODE_Z_CHUNK_SIZE) {
    ctx->buf_size = FTP_MODE_Z_CHUNK_SIZE;
  }
  ctx->buf = malloc(ctx->buf_size);
  if(!ctx->buf) {
    free(ctx);
    return -1;
  }

  ctx->direction = is_send ? FTP_MODE_Z_DIR_SEND : FTP_MODE_Z_DIR_RECV;
  memset(&ctx->stream, 0, sizeof(ctx->stream));

  if(is_send) {
    ret = deflateInit2(&ctx->stream, env->mode_z_level, Z_DEFLATED,
                       window_bits, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
  } else {
    ret = inflateInit2(&ctx->stream, window_bits);
  }
  if(ret != Z_OK) {
    free(ctx->buf);
    free(ctx);
    ftp_mode_z_set_zlib_errno(ret);
    return -1;
  }

  env->mode_z = ctx;
  return 0;
}


int
ftp_mode_z_xfer_finish(struct ftp_env *env, int success) {
  struct ftp_mode_z *ctx = env->mode_z;
  int rc = 0;

  if(!ctx) {
    return 0;
  }

  if(success && ctx->direction == FTP_MODE_Z_DIR_SEND) {
    for(;;) {
      size_t produced;
      int ret;

      ctx->stream.next_in = Z_NULL;
      ctx->stream.avail_in = 0;
      ctx->stream.next_out = ctx->buf;
      ctx->stream.avail_out = (uInt)ctx->buf_size;

      ret = deflate(&ctx->stream, Z_FINISH);
      produced = ctx->buf_size - ctx->stream.avail_out;

      if(produced && io_nwrite(env->data_fd, ctx->buf, produced)) {
        rc = -1;
        break;
      }
      if(ret == Z_STREAM_END) {
        break;
      }
      if(ret != Z_OK) {
        errno = EIO;
        rc = -1;
        break;
      }
    }
  } else if(success && ctx->direction == FTP_MODE_Z_DIR_RECV) {
    if(!ctx->finished || ctx->stream.avail_in != 0) {
      ftp_mode_z_set_proto_errno();
      rc = -1;
    } else {
      int has_input = ftp_mode_z_has_buffered_input(env->data_fd);
      if(has_input != 0) {
        if(has_input > 0) {
          ftp_mode_z_set_proto_errno();
        }
        rc = -1;
      }
    }
  }

  if(ctx->direction == FTP_MODE_Z_DIR_SEND) {
    if(deflateEnd(&ctx->stream) != Z_OK && rc == 0) {
      errno = EIO;
      rc = -1;
    }
  } else {
    if(inflateEnd(&ctx->stream) != Z_OK && rc == 0) {
      errno = EIO;
      rc = -1;
    }
  }

  ftp_mode_z_free(env);
  return rc;
}


ssize_t
ftp_mode_z_read(struct ftp_env *env, void *buf, size_t count) {
  struct ftp_mode_z *ctx = env->mode_z;
  unsigned char *out = buf;
  size_t produced;

  if(!ctx || ctx->direction != FTP_MODE_Z_DIR_RECV) {
    errno = EINVAL;
    return -1;
  }
  if(!count) {
    return 0;
  }
  if(ctx->finished) {
    return 0;
  }

  ctx->stream.next_out = out;
  ctx->stream.avail_out = (uInt)count;

  while(ctx->stream.avail_out > 0 && !ctx->finished) {
    int ret;

    if(ctx->stream.avail_in == 0) {
      ssize_t r;

      if(ctx->saw_socket_eof) {
        ftp_mode_z_set_proto_errno();
        return -1;
      }

      for(;;) {
        r = recv(env->data_fd, ctx->buf, ctx->buf_size, 0);
        if(r < 0 && errno == EINTR) {
          continue;
        }
        break;
      }
      if(r < 0) {
        return -1;
      }
      if(r == 0) {
        ctx->saw_socket_eof = 1;
        continue;
      }

      ctx->stream.next_in = ctx->buf;
      ctx->stream.avail_in = (uInt)r;
    }

    ret = inflate(&ctx->stream, Z_NO_FLUSH);
    if(ret == Z_STREAM_END) {
      ctx->finished = 1;
      break;
    }
    if(ret == Z_OK) {
      continue;
    }
    if(ret == Z_BUF_ERROR) {
      if(ctx->stream.avail_out != (uInt)count) {
        break;
      }
      continue;
    }

    ftp_mode_z_set_zlib_errno(ret);
    return -1;
  }

  produced = count - (size_t)ctx->stream.avail_out;
  if(!produced) {
    if(ctx->finished) {
      return 0;
    }
    if(ctx->saw_socket_eof) {
      ftp_mode_z_set_proto_errno();
      return -1;
    }
  }

  return (ssize_t)produced;
}


int
ftp_mode_z_write(struct ftp_env *env, const void *buf, size_t count) {
  struct ftp_mode_z *ctx = env->mode_z;

  if(!ctx || ctx->direction != FTP_MODE_Z_DIR_SEND) {
    errno = EINVAL;
    return -1;
  }

  ctx->stream.next_in = (Bytef*)buf;
  ctx->stream.avail_in = (uInt)count;

  while(ctx->stream.avail_in > 0) {
    size_t produced;
    int ret;

    ctx->stream.next_out = ctx->buf;
    ctx->stream.avail_out = (uInt)ctx->buf_size;
    ret = deflate(&ctx->stream, Z_NO_FLUSH);
    if(ret != Z_OK) {
      errno = EIO;
      return -1;
    }

    produced = ctx->buf_size - ctx->stream.avail_out;
    if(produced && io_nwrite(env->data_fd, ctx->buf, produced)) {
      return -1;
    }
  }

  return 0;
}
