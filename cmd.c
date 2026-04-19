/* Copyright (C) 2023 John Törnblom

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

#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <utime.h>
#ifdef __linux__
#include <sys/sysmacros.h>
#endif
#include <time.h>
#include <unistd.h>

#include "cmd.h"
#include "io.h"
#include "kstuff_autopause.h"
#include "log.h"
#include "notify.h"
#include "self.h"

#ifdef ECANCELED
#define FTP_BG_OP_CANCELLED_ERR ECANCELED
#else
#define FTP_BG_OP_CANCELLED_ERR INT_MAX
#endif

#ifndef FTP_LIST_OUTBUF_SIZE
#define FTP_LIST_OUTBUF_SIZE (256 * 1024)
#endif

#define DISABLE_ASCII_MODE

// #define IO_USE_SENDFILE  // Disabled. Speed x2 down ?!

#if defined(IO_USE_AIO)
static int
ftp_cmd_RETR_fd_aio(ftp_env_t *env, int fd, off_t off, size_t remaining);

static void
ftp_free_owned_buffers(void *buffers[], const int owned[], int count) {
  int i;

  for(i=0; i<count; i++) {
    if(owned[i] && buffers[i]) {
      free(buffers[i]);
    }
  }
}

static int
ftp_aio_find_reusable_slot(io_aio_slot_t slots[], int count) {
  int i;

  for(i=0; i<count; i++) {
    if(!slots[i].in_flight) {
      slots[i].ready = 0;
      slots[i].result_len = 0;
      return i;
    }
  }

  return -1;
}
#endif


/**
 * Create a string representation of a file mode.
 **/
static void
ftp_mode_string(mode_t mode, char *buf) {
  int c, d, i;
  mode_t bit;

  buf[10] = 0;
  for(i=0; i<9; i++) {
    bit = mode & ((mode_t)1<<i);
    c = i%3;
    if(!c && (mode & ((mode_t)1<<((d=i/3)+9)))) {
      c = "tss"[d];
      if (!bit) c &= ~0x20;
    } else c = bit ? "xwr"[c] : '-';
    buf[9-i] = (char)c;
  }

  if (S_ISDIR(mode)) c = 'd';
  else if (S_ISBLK(mode)) c = 'b';
  else if (S_ISCHR(mode)) c = 'c';
  else if (S_ISLNK(mode)) c = 'l';
  else if (S_ISFIFO(mode)) c = 'p';
  else if (S_ISSOCK(mode)) c = 's';
  else c = '-';
  *buf = (char)c;
}


static int
ftp_set_stat_size(struct stat *st, size_t size) {
  if((uint64_t)size > (uint64_t)INT64_MAX) {
    errno = EFBIG;
    return -1;
  }
  st->st_size = (off_t)size;
  return 0;
}


/**
 * Normalize a path by resolving '.', '..', and redundant slashes.
 **/
static int
ftp_normpath(const char *path, char *out, size_t out_size) {
  size_t stack[PATH_MAX / 2 + 2];
  size_t sp = 0;
  size_t len = 1;
  const char *p = path;

  if(!path || !out || out_size < 2) {
    errno = EINVAL;
    return -1;
  }

  out[0] = '/';
  out[1] = '\0';

  p += strspn(p, "/");

  while(*p) {
    const char *start = p;
    size_t comp_len = strcspn(p, "/");
    p += comp_len;
    p += strspn(p, "/");

    if(!comp_len || (comp_len == 1 && start[0] == '.')) {
      continue;
    }

    if(comp_len == 2 && start[0] == '.' && start[1] == '.') {
      if(sp > 0) {
        len = stack[--sp];
        out[len] = '\0';
      } else {
        len = 1;
        out[1] = '\0';
      }
      continue;
    }

    size_t prelen = len;
    if(len > 1) {
      if(len + 1 >= out_size) {
        errno = ENAMETOOLONG;
        return -1;
      }
      out[len++] = '/';
    }

    if(len + comp_len >= out_size) {
      errno = ENAMETOOLONG;
      return -1;
    }

    memcpy(out + len, start, comp_len);
    len += comp_len;
    out[len] = '\0';

    if(sp < (sizeof(stack) / sizeof(stack[0]))) {
      stack[sp++] = prelen;
    }
  }
  return 0;
}


/**
 * Open the data connection.
 */
int
ftp_data_open(ftp_env_t *env) {
  struct sockaddr_in data_addr;
  struct sockaddr_in ctrl_addr;
  socklen_t addr_len;
  socklen_t ctrl_len;

  if(env->data_addr.sin_port) {
    if(env->data_fd < 0) {
      env->data_fd = socket(AF_INET, SOCK_STREAM, 0);
      if(env->data_fd < 0) {
        return -1;
      }
    }
    while(connect(env->data_fd, (struct sockaddr*)&env->data_addr,
                  sizeof(env->data_addr)) != 0) {
      if(errno == EINTR) {
        continue;
      }
      ftp_data_close(env);
      return -1;
    }
  } else {
    if(env->passive_fd < 0) {
      errno = ENOTCONN;
      return -1;
    }
    addr_len = sizeof(data_addr);
    for(;;) {
      env->data_fd = accept(env->passive_fd, (struct sockaddr*)&data_addr,
                            &addr_len);
      if(env->data_fd >= 0) {
        break;
      }
      if(errno == EINTR) {
        continue;
      }
      return -1;
    }

    close(env->passive_fd);
    env->passive_fd = -1;

    memset(&ctrl_addr, 0, sizeof(ctrl_addr));
    ctrl_len = sizeof(ctrl_addr);
    if(getpeername(env->active_fd, (struct sockaddr *)&ctrl_addr, &ctrl_len) !=
       0) {
      ftp_data_close(env);
      errno = EACCES;
      return -1;
    }
    if(ctrl_addr.sin_family != AF_INET ||
       ctrl_addr.sin_addr.s_addr != data_addr.sin_addr.s_addr) {
      ftp_data_close(env);
      errno = EACCES;
      return -1;
    }
  }

  io_set_socket_opts(env->data_fd, 1);

  return 0;
}


/**
 * Read data from an existing data connection.
 **/
static ssize_t
ftp_data_read(ftp_env_t *env, void *buf, size_t count) {
  for(;;) {
    ssize_t r = recv(env->data_fd, buf, count, 0);
    if(r < 0 && errno == EINTR) {
      continue;
    }
    return r;
  }
}

/**
 * Copy file data to the data socket, converting to CRLF (ASCII mode).
 **/
static int
ftp_copy_ascii_out(ftp_env_t *env, int fd_in) {
  char *inbuf = env->xfer_buf;
  size_t bufsize = env->xfer_buf_size;
  char *outbuf = NULL;
  size_t outcap = 0;
  int free_in = 0;
  int prev_cr = 0;

  if(!inbuf || !bufsize) {
    inbuf = malloc(IO_COPY_BUFSIZE);
    bufsize = IO_COPY_BUFSIZE;
    free_in = 1;
    if(!inbuf) {
      return -1;
    }
  }

  outcap = bufsize * 2 + 2;
  outbuf = malloc(outcap);
  if(!outbuf) {
    if(free_in) {
      free(inbuf);
    }
    return -1;
  }

  for(;;) {
    ssize_t r = read(fd_in, inbuf, bufsize);
    size_t out_len = 0;

    if(r < 0) {
      if(errno == EINTR) {
        continue;
      }
      goto error;
    }
    if(r == 0) {
      break;
    }

    for(ssize_t i = 0; i < r; i++) {
      unsigned char c = (unsigned char)inbuf[i];

      if(prev_cr) {
        if(c == '\n') {
          outbuf[out_len++] = '\r';
          outbuf[out_len++] = '\n';
          prev_cr = 0;
          continue;
        }
        outbuf[out_len++] = '\r';
        prev_cr = 0;
      }

      if(c == '\r') {
        prev_cr = 1;
        continue;
      }
      if(c == '\n') {
        outbuf[out_len++] = '\r';
        outbuf[out_len++] = '\n';
        continue;
      }
      outbuf[out_len++] = (char)c;
    }

    if(out_len && io_nwrite(env->data_fd, outbuf, out_len)) {
      goto error;
    }
  }

  if(prev_cr) {
    outbuf[0] = '\r';
    if(io_nwrite(env->data_fd, outbuf, 1)) {
      goto error;
    }
  }

  free(outbuf);
  if(free_in) {
    free(inbuf);
  }
  return 0;

error:
  free(outbuf);
  if(free_in) {
    free(inbuf);
  }
  return -1;
}

/**
 * Copy data from the data socket to a file, converting CRLF to LF.
 **/
static int
ftp_copy_ascii_in(ftp_env_t *env, int fd_out, off_t *out_off) {
  char *inbuf = env->xfer_buf;
  size_t bufsize = env->xfer_buf_size;
  char *outbuf = NULL;
  size_t outcap = 0;
  int free_in = 0;
  int prev_cr = 0;

  if(!out_off) {
    errno = EINVAL;
    return -1;
  }

  if(!inbuf || !bufsize) {
    inbuf = malloc(IO_COPY_BUFSIZE);
    bufsize = IO_COPY_BUFSIZE;
    free_in = 1;
    if(!inbuf) {
      return -1;
    }
  }

  outcap = bufsize + 1;
  outbuf = malloc(outcap);
  if(!outbuf) {
    if(free_in) {
      free(inbuf);
    }
    return -1;
  }

  for(;;) {
    ssize_t r = recv(env->data_fd, inbuf, bufsize, 0);
    size_t out_len = 0;

    if(r < 0) {
      if(errno == EINTR) {
        continue;
      }
      goto error;
    }
    if(r == 0) {
      break;
    }

    for(ssize_t i = 0; i < r; i++) {
      unsigned char c = (unsigned char)inbuf[i];

      if(prev_cr) {
        if(c == '\n') {
          outbuf[out_len++] = '\n'; // \r\n -> \n
          prev_cr = 0;
          continue;
        }
        // Emit the swallowed \r
        if(out_len < outcap) {
          outbuf[out_len++] = '\r'; 
        }
        prev_cr = 0;
      }

      if(c == '\r') {
        prev_cr = 1;
        continue; // Swallow \r
      }
      if(out_len < outcap) outbuf[out_len++] = (char)c;
    }

    if(out_len && io_nwrite(fd_out, outbuf, out_len)) {
      goto error;
    }
    *out_off += (off_t)out_len;
  }

  if(prev_cr) {
    outbuf[0] = '\r';
    if(io_nwrite(fd_out, outbuf, 1)) {
      goto error;
    }
    *out_off += 1;
  }

  free(outbuf);
  if(free_in) {
    free(inbuf);
  }
  return 0;

error:
  free(outbuf);
  if(free_in) {
    free(inbuf);
  }
  return -1;
}


/**
 * Close the data connection.
 **/
int
ftp_data_close(ftp_env_t *env) {
  int rc = 0;
  if(env->data_fd >= 0) {
    if(close(env->data_fd)) {
      rc = -1;
    }
    env->data_fd = -1;
  }
  return rc;
}

/**
 * Close data and passive sockets and reset state.
 **/
static void
ftp_close_data_fds(ftp_env_t *env) {
  ftp_data_close(env);
  if(env->passive_fd >= 0) {
    close(env->passive_fd);
    env->passive_fd = -1;
  }
}

/**
 * Send a 550 reply and close passive socket.
 **/
static int
ftp_perror_close_passive(ftp_env_t *env) {
  int ret = ftp_perror(env);
  if(env->passive_fd >= 0) {
    close(env->passive_fd);
    env->passive_fd = -1;
  }
  return ret;
}

/**
 * Validate and configure active data connection parameters.
 **/
static int
ftp_setup_active_data(ftp_env_t *env, struct in_addr in_addr,
                      uint16_t port, const char *illegal_msg) {
  struct sockaddr_in ctrl_addr;
  socklen_t ctrl_len;

  memset(&ctrl_addr, 0, sizeof(ctrl_addr));
  ctrl_len = sizeof(ctrl_addr);
  if(getpeername(env->active_fd, (struct sockaddr *)&ctrl_addr, &ctrl_len) !=
     0 || ctrl_addr.sin_family != AF_INET ||
     ctrl_addr.sin_addr.s_addr != in_addr.s_addr) {
    return ftp_active_printf(env, "%s\r\n", illegal_msg);
  }

  ftp_close_data_fds(env);

  if((env->data_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    return ftp_perror(env);
  }

  env->data_addr.sin_family = AF_INET;
  env->data_addr.sin_addr = in_addr;
  env->data_addr.sin_port = htons(port);

  return 0;
}

/**
 * Create a passive listener and return the bound port.
 **/
static int
ftp_listen_passive(ftp_env_t *env, uint16_t *port_out) {
  socklen_t sockaddr_len = sizeof(struct sockaddr_in);
  struct sockaddr_in sockaddr;

  *port_out = 0;

  if((env->passive_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    return ftp_perror(env);
  }

  if(setsockopt(env->passive_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1},
                sizeof(int)) < 0) {
    return ftp_perror_close_passive(env);
  }

  memset(&sockaddr, 0, sockaddr_len);
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  sockaddr.sin_port = htons(0);

  if(bind(env->passive_fd, (struct sockaddr *)&sockaddr, sockaddr_len) != 0) {
    return ftp_perror_close_passive(env);
  }

  if(listen(env->passive_fd, 1) != 0) {
    return ftp_perror_close_passive(env);
  }

  if(getsockname(env->passive_fd, (struct sockaddr *)&sockaddr,
                 &sockaddr_len)) {
    return ftp_perror_close_passive(env);
  }

  *port_out = ntohs(sockaddr.sin_port);
  return 0;
}


/**
 * Write a string to the active connection with printf semantics.
 **/
int
ftp_active_printf(ftp_env_t *env, const char *fmt, ...) {
  char buf[0x1000];
  va_list args;

  va_start(args, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  if(n < 0) {
    return -1;
  }

  size_t len = (size_t)n;
  if(len >= sizeof(buf)) {
    len = sizeof(buf) - 1;
  }

  pthread_mutex_lock(&env->ctrl_mutex);
  int rc = io_nwrite(env->active_fd, buf, len);
  pthread_mutex_unlock(&env->ctrl_mutex);
  if(rc) {
    return -1;
  }

  return 0;
}


/**
 * Write a string to the active connection with perror semantics.
 **/
int
ftp_perror(ftp_env_t *env) {
  char buf[255];

  if(strerror_r(errno, buf, sizeof(buf))) {
    strncpy(buf, "Unknown error", sizeof(buf));
  }

  return ftp_active_printf(env, "550 %s\r\n", buf);
}

/**
 * Check whether an errno value indicates a timeout.
 **/
static int
ftp_errno_is_timeout(int e) {
  if(e == EAGAIN
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
     || e == EWOULDBLOCK
#endif
#ifdef ETIMEDOUT
     || e == ETIMEDOUT
#endif
  ) {
    return 1;
  }
  return 0;
}

/**
 * Reply with a data transfer error message for common errno values.
 **/
static int
ftp_data_xfer_error_reply(ftp_env_t *env) {
  int e = errno;
  if(e == EPIPE
#ifdef ECONNRESET
     || e == ECONNRESET
#endif
  ) {
    return ftp_active_printf(env, "426 Data connection closed\r\n");
  }
  if(ftp_errno_is_timeout(e)) {
    return ftp_active_printf(env, "426 Data connection timed out\r\n");
  }
  errno = e;
  return ftp_perror(env);
}

/**
 * Reply with a data open error message for common errno values.
 **/
static int
ftp_data_open_error_reply(ftp_env_t *env) {
  int e = errno;
  if(e == ENOTCONN) {
    return ftp_active_printf(env, "425 Use PORT or PASV first\r\n");
  }
  if(e == EACCES) {
    return ftp_active_printf(env, "425 Can't open data connection\r\n");
  }
  errno = e;
  return ftp_perror(env);
}

/**
 * Verify that a data connection is configured before opening it.
 **/
static int
ftp_data_precheck(ftp_env_t *env) {
  if(!env->data_addr.sin_port && env->passive_fd < 0) {
    errno = ENOTCONN;
    int err = ftp_data_open_error_reply(env);
    if(err < 0) {
      return -1;
    }
    return 1;
  }
  return 0;
}

/**
 * Send 150 and open the data connection, with optional precheck.
 **/
static int
ftp_data_xfer_start(ftp_env_t *env, int prechecked) {
  if(!prechecked) {
    int precheck = ftp_data_precheck(env);
    if(precheck) {
      return precheck;
    }
  }
  if(ftp_active_printf(env, "150 Opening data transfer\r\n")) {
    return -1;
  }
  if(ftp_data_open(env)) {
    int err = ftp_data_open_error_reply(env);
    if(err < 0) {
      return -1;
    }
    return 1;
  }
  return 0;
}


/**
 * Create an absolute path from the current working directory.
 * Returns 0 on success, -1 on error (errno set).
 **/
int
ftp_abspath(ftp_env_t *env, char *abspath, size_t abspath_size,
            const char *path) {
  char buf[PATH_MAX + 1];
  int n;

  if(!env || !abspath || !path || abspath_size < 2) {
    errno = EINVAL;
    return -1;
  }

  if(path[0] != '/') {
    n = snprintf(buf, sizeof(buf), "%s/%s", env->cwd, path);
  } else {
    n = snprintf(buf, sizeof(buf), "%s", path);
  }
  if(n < 0 || (size_t)n >= sizeof(buf)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  if(ftp_normpath(buf, abspath, abspath_size)) {
    return -1;
  }
  return 0;
}

/**
 * Trim leading/trailing spaces and copy a path argument.
 **/
static const char *
ftp_copy_path_arg(const char *arg, char *buf, size_t bufsize) {
  const char *p = arg;
  if(!buf || bufsize < 2) {
    return NULL;
  }
  if(!p) {
    return NULL;
  }

  p += strspn(p, " ");
  if(!*p) {
    return NULL;
  }

  size_t len = strlen(p);
  while(len && p[len - 1] == ' ') {
    len--;
  }
  if(len == 0) {
    return NULL;
  }

  if(len >= bufsize) {
    len = bufsize - 1;
  }
  memcpy(buf, p, len);
  buf[len] = '\0';
  return buf;
}

/**
 * Parse a LIST path argument, skipping option tokens.
 **/
static const char *
ftp_list_path_arg(const char *arg, char *buf, size_t bufsize) {
  const char *p = arg;
  if(!buf || bufsize < 2) {
    return NULL;
  }

  p += strspn(p, " ");
  if(!*p) {
    return NULL;
  }

  // If it doesn't start with options, treat the whole remainder as the path.
  if(*p != '-') {
    return ftp_copy_path_arg(p, buf, bufsize);
  }

  // Skip leading options (e.g., "-al") and honor "--" to end options.
  while(*p == '-') {
    const char *tok = p;
    size_t len = strcspn(p, " ");
    p += len;
    p += strspn(p, " ");
    if(len == 2 && tok[0] == '-' && tok[1] == '-') {
      break;
    }
    if(len <= 1) {
      p = tok;
      break;
    }
    if(!*p) {
      return NULL;
    }
    if(*p != '-') {
      break;
    }
  }

  p += strspn(p, " ");
  if(!*p) {
    return NULL;
  }
  return ftp_copy_path_arg(p, buf, bufsize);
}


/**
 * Format an MDTM/MLSD UTC timestamp.
 **/
static int
ftp_format_mdtm(time_t t, char *buf, size_t bufsize) {
  struct tm tm;

  if(!buf || bufsize < 15) {
    return -1;
  }

  if(!gmtime_r(&t, &tm)) {
    return -1;
  }

  if(snprintf(buf, bufsize, "%04d%02d%02d%02d%02d%02d", tm.tm_year + 1900,
              tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
              tm.tm_sec) >= (int)bufsize) {
    return -1;
  }

  return 0;
}

/**
 * Format a LIST timestamp in an ls -l compatible form.
 **/
static int
ftp_format_list_time(time_t t, char *buf, size_t bufsize) {
  struct tm tm;
  time_t now;

  // LIST output is typically server-local time (unlike MLSD's UTC "modify"). 
  static const char *mon[] = {"Jan","Feb","Mar","Apr","May","Jun",
                              "Jul","Aug","Sep","Oct","Nov","Dec"};

  if(!buf || bufsize < 14) {
    return -1;
  }

  if(!localtime_r(&t, &tm)) {
    // Fallback to a fixed epoch-ish timestamp rather than garbage. 
    (void)snprintf(buf, bufsize, "Jan  1  1970");
    return 0;
  }

  now = time(NULL);
  long long diff = (long long)now - (long long)t;
  const long long six_months = 180LL * 24LL * 60LL * 60LL;
  const char *mname = mon[(tm.tm_mon >= 0 && tm.tm_mon < 12) ? tm.tm_mon : 0];

  if(diff < 0 || diff > six_months) {
    // Older timestamps: show year like "ls -l".
    (void)snprintf(buf, bufsize, "%s %2d  %4d", mname, tm.tm_mday, tm.tm_year + 1900);
  } else {
    // Recent timestamps: show time.
    (void)snprintf(buf, bufsize, "%s %2d %02d:%02d", mname, tm.tm_mday, tm.tm_hour, tm.tm_min);
  }

  return 0;
}


/**
 * Enter passive mode.
 **/
int
ftp_cmd_PASV(ftp_env_t *env, const char* arg) {
  socklen_t sockaddr_len = sizeof(struct sockaddr_in);
  struct sockaddr_in sockaddr;
  uint32_t addr = 0;
  uint16_t port = 0;
  int ret = 0;

  if(arg[0]) {
    return ftp_active_printf(env, "501 Usage: PASV\r\n");
  }

  env->data_addr.sin_port = 0;
  env->data_addr.sin_addr.s_addr = 0;
  ftp_close_data_fds(env);

  if(getsockname(env->active_fd, (struct sockaddr*)&sockaddr, &sockaddr_len)) {
    return ftp_perror(env);
  }
  addr = sockaddr.sin_addr.s_addr;

  ret = ftp_listen_passive(env, &port);
  if(ret) {
    return ret;
  }
  uint32_t ip = ntohl(addr);
  uint16_t p = port;

  return ftp_active_printf(env, "227 Entering Passive Mode (%hhu,%hhu,%hhu,%hhu,%hhu,%hhu).\r\n",
    (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, (ip >> 0) & 0xFF,
    (p >> 8) & 0xFF, (p >> 0) & 0xFF);
}


/**
 * Enter extended passive mode.
 **/
int
ftp_cmd_EPSV(ftp_env_t *env, const char *arg) {
  uint16_t port = 0;
  int ret = 0;

  if(arg[0]) {
    char *end = NULL;
    long proto = strtol(arg, &end, 10);
    if(end == arg || *end) {
      return ftp_active_printf(env, "501 Usage: EPSV [<NET-PRT>]\r\n");
    }
    if(proto != 1) {
      return ftp_active_printf(env, "522 Network protocol not supported\r\n");
    }
  }

  env->data_addr.sin_port = 0;
  env->data_addr.sin_addr.s_addr = 0;
  ftp_close_data_fds(env);

  ret = ftp_listen_passive(env, &port);
  if(ret) {
    return ret;
  }

  return ftp_active_printf(env,
                           "229 Entering Extended Passive Mode (|||%hu|)\r\n",
                           port);
}


/**
 * Change the working directory to its parent.
 **/
int
ftp_cmd_CDUP(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat st;

  (void)arg;

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), "..")) {
    return ftp_perror(env);
  }
  if(stat(pathbuf, &st)) {
    return ftp_perror(env);
  }
  if(!S_ISDIR(st.st_mode)) {
    return ftp_active_printf(env, "550 No such directory\r\n");
  }
  snprintf(env->cwd, sizeof(env->cwd), "%s", pathbuf);

  return ftp_active_printf(env, "250 OK\r\n");
}


/**
 * Change the permission mode bits of a path.
 **/
int
ftp_cmd_CHMOD(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  mode_t mode = 0;
  char* ptr;
  char* end;
  unsigned long parsed_mode;
  struct stat lst;

  if(!arg[0] || !(ptr=strstr(arg, " "))) {
    return ftp_active_printf(env, "501 Usage: CHMOD <MODE> <PATH>\r\n");
  }

  errno = 0;
  parsed_mode = strtoul(arg, &end, 8);
  if(errno || end == arg || end != ptr ||
     parsed_mode > 07777) {
    return ftp_active_printf(env, "501 Usage: CHMOD <MODE> <PATH>\r\n");
  }
  mode = (mode_t)parsed_mode;

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), ptr+1)) {
    return ftp_perror(env);
  }

  if(lstat(pathbuf, &lst)) {
    return ftp_perror(env);
  }
  if(S_ISLNK(lst.st_mode)) {
    return ftp_active_printf(env, "550 Symlinks are not allowed\r\n");
  }
  if(chmod(pathbuf, mode)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "200 OK\r\n");
}

/**
 * Get or set the process umask (UMASK).
 **/
int
ftp_cmd_UMASK(ftp_env_t *env, const char* arg) {
  (void)env;

  arg += strspn(arg, " ");

  if(!*arg) {
    mode_t old = umask(0);
    umask(old);
    return ftp_active_printf(env, "200 UMASK %03o\r\n", old & 0777);
  }

  char *end = NULL;
  long mode = strtol(arg, &end, 8);
  if(end) {
    end += strspn(end, " ");
  }
  if(end == arg || (end && *end) || mode < 0 || mode > 0777) {
    return ftp_active_printf(env, "501 Usage: UMASK <MODE>\r\n");
  }

  umask((mode_t)mode);
  return ftp_active_printf(env, "200 UMASK set to %03o\r\n", (int)mode);
}

/**
 * Create a symlink (SYMLINK <TARGET> <LINK>).
 **/
int
ftp_cmd_SYMLINK(ftp_env_t *env, const char* arg) {
  char target_arg[PATH_MAX + 1];
  char link_arg[PATH_MAX + 1];
  char target_path[PATH_MAX];
  char link_path[PATH_MAX];
  const char *p = arg;

  p += strspn(p, " ");
  if(!*p) {
    return ftp_active_printf(env, "501 Usage: SYMLINK <TARGET> <LINK>\r\n");
  }

  const char *sep = strchr(p, ' ');
  if(!sep) {
    return ftp_active_printf(env, "501 Usage: SYMLINK <TARGET> <LINK>\r\n");
  }

  size_t target_len = (size_t)(sep - p);
  if(target_len == 0 || target_len >= sizeof(target_arg)) {
    errno = ENAMETOOLONG;
    return ftp_perror(env);
  }
  memcpy(target_arg, p, target_len);
  target_arg[target_len] = '\0';

  p = sep;
  p += strspn(p, " ");
  if(!*p) {
    return ftp_active_printf(env, "501 Usage: SYMLINK <TARGET> <LINK>\r\n");
  }

  const char *end = p + strlen(p);
  while(end > p && end[-1] == ' ') {
    end--;
  }
  size_t link_len = (size_t)(end - p);
  if(link_len == 0 || link_len >= sizeof(link_arg)) {
    errno = ENAMETOOLONG;
    return ftp_perror(env);
  }
  memcpy(link_arg, p, link_len);
  link_arg[link_len] = '\0';

  if(ftp_abspath(env, target_path, sizeof(target_path), target_arg)) {
    return ftp_perror(env);
  }
  if(ftp_abspath(env, link_path, sizeof(link_path), link_arg)) {
    return ftp_perror(env);
  }

  if(symlink(target_path, link_path)) {
    if(errno == 0) {
#ifdef EOPNOTSUPP
      errno = EOPNOTSUPP;
#else
      errno = EIO;
#endif
    }
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "200 SYMLINK created\r\n");
}

/**
 * Resolve an optional path and fetch filesystem stats.
 **/
static int
ftp_get_vfs(ftp_env_t *env, const char *arg, struct statvfs *vfs_out) {
  char pathbuf[PATH_MAX];
  const char *path_arg = ftp_copy_path_arg(arg, pathbuf, sizeof(pathbuf));
  const char *path = NULL;

  if(!vfs_out) {
    errno = EINVAL;
    return -1;
  }

  if(path_arg) {
    if(ftp_abspath(env, pathbuf, sizeof(pathbuf), path_arg)) {
      return -1;
    }
    path = pathbuf;
  } else {
    if(ftp_normpath(env->cwd, pathbuf, sizeof(pathbuf))) {
      return -1;
    }
    path = pathbuf;
  }

  if(statvfs(path, vfs_out)) {
    return -1;
  }
  return 0;
}

/**
 * Return available space for a path (AVBL).
 **/
int
ftp_cmd_AVBL(ftp_env_t *env, const char* arg) {
  struct statvfs vfs;
  if(ftp_get_vfs(env, arg, &vfs)) {
    return ftp_perror(env);
  }
  uintmax_t unit = vfs.f_frsize ? (uintmax_t)vfs.f_frsize
                                : (uintmax_t)vfs.f_bsize;
  uintmax_t avail = (uintmax_t)vfs.f_bavail * unit;
  return ftp_active_printf(env, "213 %" PRIuMAX "\r\n", avail);
}

/**
 * Return available space for a path (XQUOTA).
 **/
int
ftp_cmd_XQUOTA(ftp_env_t *env, const char* arg) {
  struct statvfs vfs;
  if(ftp_get_vfs(env, arg, &vfs)) {
    return ftp_perror(env);
  }

  uintmax_t block = vfs.f_frsize ? (uintmax_t)vfs.f_frsize
                                 : (uintmax_t)vfs.f_bsize;
  uintmax_t file_limit = (uintmax_t)vfs.f_files;
  uintmax_t file_count = 0;
  if(vfs.f_files >= vfs.f_ffree) {
    file_count = (uintmax_t)(vfs.f_files - vfs.f_ffree);
  }
  uintmax_t disk_limit = (uintmax_t)vfs.f_blocks * block;
  uintmax_t disk_usage = 0;
  if(vfs.f_blocks >= vfs.f_bavail) {
    disk_usage = (uintmax_t)(vfs.f_blocks - vfs.f_bavail) * block;
  }

  if(ftp_active_printf(env, "213-File and disk usage\r\n")) {
    return -1;
  }
  if(ftp_active_printf(env, " File count: %" PRIuMAX "\r\n", file_count)) {
    return -1;
  }
  if(ftp_active_printf(env, " File limit: %" PRIuMAX "\r\n", file_limit)) {
    return -1;
  }
  if(ftp_active_printf(env, " Disk usage: %" PRIuMAX "\r\n", disk_usage)) {
    return -1;
  }
  if(ftp_active_printf(env, " Disk limit: %" PRIuMAX "\r\n", disk_limit)) {
    return -1;
  }
  return ftp_active_printf(env, "213 File and disk usage end\r\n");
}


/**
 * Change the working directory.
 **/
int
ftp_cmd_CWD(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat st;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: CWD <PATH>\r\n");
  }

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }
  if(stat(pathbuf, &st)) {
    return ftp_perror(env);
  }

  if(!S_ISDIR(st.st_mode)) {
    return ftp_active_printf(env, "550 No such directory\r\n");
  }

  snprintf(env->cwd, sizeof(env->cwd), "%s", pathbuf);

  return ftp_active_printf(env, "250 OK\r\n");
}


/**
 * Delete a given file.
 **/
int
ftp_cmd_DELE(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat st;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: DELE <FILENAME>\r\n");
  }

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }
  if(lstat(pathbuf, &st)) {
    return ftp_perror(env);
  }
  if(S_ISDIR(st.st_mode)) {
    return ftp_active_printf(env, "550 Not a regular file\r\n");
  }
  if(remove(pathbuf)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "250 File deleted\r\n");
}



/**
 * Buffered data-transfer helpers for directory listings.
 *
 **/
typedef struct ftp_xfer_buf {
  ftp_env_t *env;
  char *buf;
  size_t cap;
  size_t len;
  int free_buf;
  int failed;
} ftp_xfer_buf_t;

/**
 * Release any heap buffer used by the listing transfer buffer.
 **/
static void
ftp_xfer_buf_release(ftp_xfer_buf_t *x) {
  if(x->free_buf && x->buf) {
    free(x->buf);
  }
  x->buf = NULL;
  x->cap = 0;
  x->len = 0;
  x->free_buf = 0;
}

/**
 * Write raw bytes to the data socket and mark failure on error.
 **/
static int
ftp_xfer_write_raw(ftp_xfer_buf_t *x, const void *data, size_t len) {
  if(x->failed) {
    return -1;
  }
  if(io_nwrite(x->env->data_fd, data, len)) {
    (void)ftp_data_xfer_error_reply(x->env);
    x->failed = 1;
    return -1;
  }
  return 0;
}

/**
 * Flush buffered listing output to the data socket.
 **/
static int
ftp_xfer_flush(ftp_xfer_buf_t *x) {
  if(x->failed) {
    return -1;
  }
  if(x->len) {
    if(ftp_xfer_write_raw(x, x->buf, x->len)) {
      return -1;
    }
    x->len = 0;
  }
  return 0;
}

/**
 * Format a line into the buffer, flushing as needed.
 **/
static int
ftp_xfer_vprintf(ftp_xfer_buf_t *x, const char *fmt, va_list ap) {
  for(;;) {
    size_t rem;

    if(x->failed) {
      return -1;
    }

    rem = x->cap - x->len;

    va_list aq;
    va_copy(aq, ap);
    int n = vsnprintf(x->buf + x->len, rem, fmt, aq);
    va_end(aq);

    if(n < 0) {
      // Formatting error; let caller decide whether to skip entry.
      return -1;
    }

    if((size_t)n < rem) {
      x->len += (size_t)n;
      return 0;
    }

    // Not enough space -> flush and try again. 
    if(ftp_xfer_flush(x)) {
      return -1;
    }

    // If a single line is larger than the buffer, format into a temp string and write directly. 
    if((size_t)n >= x->cap) {
      size_t need = (size_t)n + 1;
      char *tmp = malloc(need);
      if(!tmp) {
        x->failed = 1;
        return -1;
      }

      va_list ar;
      va_copy(ar, ap);
      int m = vsnprintf(tmp, need, fmt, ar);
      va_end(ar);

      if(m < 0) {
        free(tmp);
        return -1;
      }

      int wr = ftp_xfer_write_raw(x, tmp, (size_t)m);
      free(tmp);
      return wr;
    }

    // else: retry with empty buffer 
  }
}

/**
 * Convenience wrapper around ftp_xfer_vprintf.
 **/
static int
ftp_xfer_printf(ftp_xfer_buf_t *x, const char *fmt, ...) {
  int rc;
  va_list ap;
  va_start(ap, fmt);
  rc = ftp_xfer_vprintf(x, fmt, ap);
  va_end(ap);
  return rc;
}


/**
* Shared prologue/epilogue for LIST/NLST/MLSD 
**/
static int
ftp_list_xfer_start(ftp_env_t *env, DIR *dir, ftp_xfer_buf_t *x) {
  memset(x, 0, sizeof(*x));
  x->env = env;
  x->buf = env->xfer_buf;
  x->cap = env->xfer_buf_size;
  if(!x->buf || !x->cap) {
    x->cap = FTP_LIST_OUTBUF_SIZE;
    x->buf = malloc(x->cap);
    x->free_buf = 1;
    if(!x->buf) {
      int err = ftp_perror(env);
      if(dir) {
        closedir(dir);
      }
      if(err < 0) {
        return -1;
      }
      return 1;
    }
  }

  int open_err = ftp_data_xfer_start(env, 0);
  if(open_err) {
    ftp_xfer_buf_release(x);
    if(dir) {
      closedir(dir);
    }
    return open_err;
  }

  kstuff_autopause_active_begin();
  return 0;
}

/**
 * Flush and finalize a directory listing transfer.
 **/
static int
ftp_list_xfer_finish(ftp_env_t *env, DIR *dir, ftp_xfer_buf_t *x) {
  if(!x->failed) {
    (void)ftp_xfer_flush(x);
  }

  if(ftp_data_close(env)) {
    (void)ftp_perror(env);
    x->failed = 1;
  }

  if(dir) {
    if(closedir(dir)) {
      (void)ftp_perror(env);
      x->failed = 1;
    }
  }

  ftp_xfer_buf_release(x);
  kstuff_autopause_active_end();

  if(x->failed) {
    return 0;
  }
  return ftp_active_printf(env, "226 Transfer complete\r\n");
}


/**
 * Join a directory path and entry name into a single path.
 **/
static int
ftp_join_path(char *dst, size_t dst_sz, const char *dir_path, const char *name) {
  int n;

  if(!dst || dst_sz < 2) {
    errno = ENAMETOOLONG;
    return -1;
  }

  if(dir_path[1] == '\0') {
    n = snprintf(dst, dst_sz, "/%s", name);
  } else {
    n = snprintf(dst, dst_sz, "%s/%s", dir_path, name);
  }

  if(n < 0 || (size_t)n >= dst_sz) {
    errno = ENAMETOOLONG;
    return -1;
  }

  return 0;
}

/**
 * Recursively compute the size of a directory.
 **/
static int ftp_dir_next_entry(DIR *dir, struct dirent **ent_out);
static int ftp_dir_open_child(DIR *dir, const char *child_path,
                              const char *name, DIR **child_out);
static int ftp_dir_size_walk(DIR *dir, const char *path, uintmax_t *size_out);
static int ftp_dir_child_lstat(DIR *dir, const char *dir_path,
                               const char *name, struct stat *st);

static int
ftp_dir_size(const char *path, uintmax_t *size_out) {
  DIR *dir = opendir(path);
  if(!dir) {
    return -1;
  }

  if(ftp_dir_size_walk(dir, path, size_out) != 0) {
    int saved_errno = errno;
    closedir(dir);
    errno = saved_errno;
    return -1;
  }

  if(closedir(dir) != 0) {
    return -1;
  }
  return 0;
}

/**
 * Recursively delete a directory and its contents.
 **/
#define FTP_NOTIFY_PATH_SIZE 224
#define FTP_DELETE_NOTIFY_CHECK_ITEMS 64

typedef enum {
  FTP_BG_COPY,
  FTP_BG_MOVE,
} ftp_bg_op_t;

static pthread_mutex_t ftp_server_bg_op_mutex = PTHREAD_MUTEX_INITIALIZER;
static int ftp_server_bg_op_in_progress = 0;
static int ftp_server_bg_op_cancel_requested = 0;

static int
ftp_server_bg_op_acquire(void) {
  int busy;

  pthread_mutex_lock(&ftp_server_bg_op_mutex);
  busy = ftp_server_bg_op_in_progress;
  if(!busy) {
    ftp_server_bg_op_in_progress = 1;
    ftp_server_bg_op_cancel_requested = 0;
  }
  pthread_mutex_unlock(&ftp_server_bg_op_mutex);

  return !busy;
}

static int
ftp_server_bg_op_busy(void) {
  int busy;

  pthread_mutex_lock(&ftp_server_bg_op_mutex);
  busy = ftp_server_bg_op_in_progress;
  pthread_mutex_unlock(&ftp_server_bg_op_mutex);

  return busy;
}

static int
ftp_server_bg_op_cancelled(void) {
  int cancelled;

  pthread_mutex_lock(&ftp_server_bg_op_mutex);
  cancelled = ftp_server_bg_op_cancel_requested;
  pthread_mutex_unlock(&ftp_server_bg_op_mutex);

  return cancelled;
}

static int
ftp_server_bg_op_cancel(void) {
  int state;

  pthread_mutex_lock(&ftp_server_bg_op_mutex);
  if(!ftp_server_bg_op_in_progress) {
    state = 0;
  } else if(ftp_server_bg_op_cancel_requested) {
    state = 2;
  } else {
    ftp_server_bg_op_cancel_requested = 1;
    state = 1;
  }
  pthread_mutex_unlock(&ftp_server_bg_op_mutex);

  return state;
}

static void
ftp_server_bg_op_release(void) {
  pthread_mutex_lock(&ftp_server_bg_op_mutex);
  ftp_server_bg_op_in_progress = 0;
  ftp_server_bg_op_cancel_requested = 0;
  pthread_mutex_unlock(&ftp_server_bg_op_mutex);
}

static void
ftp_compact_path(const char *path, char *out, size_t out_size) {
  size_t len;
  size_t head;
  size_t tail;

  if(!out || out_size == 0) {
    return;
  }

  out[0] = '\0';
  if(!path) {
    return;
  }

  len = strlen(path);
  if(len + 1 <= out_size) {
    memcpy(out, path, len + 1);
    return;
  }

  if(out_size < 5) {
    strncpy(out, path, out_size - 1);
    out[out_size - 1] = '\0';
    return;
  }

  head = (out_size - 4) / 2;
  tail = out_size - 4 - head;
  memcpy(out, path, head);
  memcpy(out + head, "...", 3);
  memcpy(out + head + 3, path + len - tail, tail);
  out[out_size - 1] = '\0';
}

static uintmax_t
ftp_saturating_add(uintmax_t lhs, uintmax_t rhs) {
  if(UINTMAX_MAX - lhs < rhs) {
    return UINTMAX_MAX;
  }

  return lhs + rhs;
}

static void
ftp_now(struct timespec *ts) {
  if(!ts) {
    return;
  }

#ifdef CLOCK_MONOTONIC
  if(clock_gettime(CLOCK_MONOTONIC, ts) == 0) {
    return;
  }
#endif

  ts->tv_sec = time(NULL);
  ts->tv_nsec = 0;
}

static double
ftp_elapsed_seconds(const struct timespec *start, const struct timespec *end) {
  time_t sec;
  long nsec;

  if(!start || !end) {
    return 0.0;
  }

  sec = end->tv_sec - start->tv_sec;
  nsec = end->tv_nsec - start->tv_nsec;
  if(nsec < 0) {
    sec -= 1;
    nsec += 1000000000L;
  }

  return (double)sec + ((double)nsec / 1000000000.0);
}

typedef struct {
  uintmax_t total_entries;
  uintmax_t deleted_entries;
  uintmax_t last_notify_entries;
  uintmax_t next_check_entries;
  struct timespec last_notify_ts;
  int has_last_notify_ts;
} ftp_delete_progress_t;

typedef struct {
  ftp_env_t *env;
  char path[PATH_MAX];
  char path_notify[FTP_NOTIFY_PATH_SIZE];
  ftp_delete_progress_t progress;
} ftp_delete_task_t;

static void ftp_copy_thread_cleanup(ftp_env_t *env);
static void ftp_delete_thread_cleanup(ftp_env_t *env);
static void *ftp_delete_thread(void *arg);
static int ftp_split_copy_args(const char *arg, char *src, size_t src_sz,
                               char *dst, size_t dst_sz);
static int ftp_mkdirs_parent(const char *path);
static int ftp_dir_is_empty(const char *path);
static int ftp_dirent_is_dots(const char *name);
static int ftp_dir_next_entry(DIR *dir, struct dirent **ent_out);
#if (defined(AT_FDCWD) || defined(AT_SYMLINK_NOFOLLOW)) && !defined(__ORBIS__)
static int ftp_dir_fastpath_should_fallback(int err);
#endif
static int ftp_dir_child_lstat(DIR *dir, const char *dir_path,
                               const char *name, struct stat *st);
static int ftp_dir_child_unlink(DIR *dir, const char *dir_path,
                                const char *name);
static void ftp_store_first_error(int *err_out, int err);
static int ftp_copy_probe_destination(const char *dst_path, int target_is_dir,
                                      int create_parent_dirs);
static int ftp_target_statvfs(const char *dst_path, int target_is_dir,
                              struct statvfs *vfs_out);
static int ftp_copy_check_space(const char *dst_path, int target_is_dir,
                                uintmax_t total_bytes);
static int ftp_copy_total_for_stat(const char *path, const struct stat *st,
                                   uintmax_t *total_out);
static int ftp_copy_prepare_total(const char *src_path,
                                  const struct stat *src_st,
                                  const char *dst_path, int target_is_dir,
                                  uintmax_t *total_bytes_out);
static int ftp_move_same_device(const char *src_path, const struct stat *src_st,
                                const char *dst_path, int *same_device);
static int ftp_move_start_background(ftp_env_t *env, ftp_bg_op_t op,
                                     const char *src_path,
                                     const char *dst_path,
                                     const struct stat *src_st,
                                     int create_parent_dirs);

static void
ftp_delete_format_rate(double items_per_sec, char *out, size_t out_size) {
  if(!out || out_size == 0) {
    return;
  }

  if(items_per_sec < 0.0) {
    items_per_sec = 0.0;
  }

  if(items_per_sec >= 100.0) {
    snprintf(out, out_size, "%.0f items/s", items_per_sec);
  } else if(items_per_sec >= 10.0) {
    snprintf(out, out_size, "%.1f items/s", items_per_sec);
  } else {
    snprintf(out, out_size, "%.2f items/s", items_per_sec);
  }
}

static unsigned
ftp_delete_progress_percent(const ftp_delete_task_t *task) {
  if(!task) {
    return 0;
  }

  if(task->progress.total_entries == 0) {
    return 100;
  }

  uintmax_t deleted = task->progress.deleted_entries;
  if(deleted > task->progress.total_entries) {
    deleted = task->progress.total_entries;
  }

  return (unsigned)((deleted * 100) / task->progress.total_entries);
}

static void
ftp_delete_notify_start(ftp_delete_task_t *task) {
  struct timespec now;

  if(!task) {
    return;
  }

  ftp_now(&now);
  task->progress.last_notify_ts = now;
  task->progress.has_last_notify_ts = 1;
  task->progress.last_notify_entries = task->progress.deleted_entries;
  task->progress.next_check_entries =
    ftp_saturating_add(task->progress.deleted_entries,
                       FTP_DELETE_NOTIFY_CHECK_ITEMS);
  notify("Delete started: %s", task->path_notify);
}

static void
ftp_delete_notify_progress(ftp_delete_task_t *task) {
  struct timespec now;
  double elapsed;
  double items_per_sec;
  uintmax_t deleted_delta;
  uintmax_t deleted;
  uintmax_t total;
  char rate[32];

  if(!task) {
    return;
  }

  ftp_now(&now);
  if(!task->progress.has_last_notify_ts) {
    task->progress.last_notify_ts = now;
    task->progress.has_last_notify_ts = 1;
    task->progress.last_notify_entries = task->progress.deleted_entries;
    task->progress.next_check_entries =
      ftp_saturating_add(task->progress.deleted_entries,
                         FTP_DELETE_NOTIFY_CHECK_ITEMS);
    return;
  }

  elapsed = ftp_elapsed_seconds(&task->progress.last_notify_ts, &now);
  if(elapsed < 10.0) {
    task->progress.next_check_entries =
      ftp_saturating_add(task->progress.deleted_entries,
                         FTP_DELETE_NOTIFY_CHECK_ITEMS);
    return;
  }

  deleted_delta =
    task->progress.deleted_entries - task->progress.last_notify_entries;
  items_per_sec = elapsed > 0.0 ? (double)deleted_delta / elapsed : 0.0;
  ftp_delete_format_rate(items_per_sec, rate, sizeof(rate));

  deleted = task->progress.deleted_entries;
  total = task->progress.total_entries;
  if(total > 0 && deleted > total) {
    deleted = total;
  }

  task->progress.last_notify_ts = now;
  task->progress.last_notify_entries = task->progress.deleted_entries;
  task->progress.next_check_entries =
    ftp_saturating_add(task->progress.deleted_entries,
                       FTP_DELETE_NOTIFY_CHECK_ITEMS);
  notify("Delete %u%% (%ju / %ju items) - %s",
         ftp_delete_progress_percent(task),
         (uintmax_t)deleted, (uintmax_t)total, rate);
}

static void
ftp_delete_progress_add(ftp_delete_task_t *task, uintmax_t amount) {
  if(!task || amount == 0) {
    return;
  }

  task->progress.deleted_entries =
    ftp_saturating_add(task->progress.deleted_entries, amount);

  if(task->progress.deleted_entries < task->progress.next_check_entries) {
    return;
  }

  ftp_delete_notify_progress(task);
}

static void
ftp_delete_notify_result(const ftp_delete_task_t *task, int rc, int err) {
  unsigned pct = rc ? ftp_delete_progress_percent(task) : 100;

  if(rc) {
    if(err == 0) {
      err = EIO;
    }
    if(err == FTP_BG_OP_CANCELLED_ERR) {
      notify("Delete stopped %u%%: %s", pct, task->path_notify);
      return;
    }
    notify("Delete failed %u%%: %s (%s)",
           pct, task->path_notify, strerror(err));
    return;
  }

  notify("Delete finished %u%%: %s (OK)", pct, task->path_notify);
}

static int
ftp_dirent_is_dots(const char *name) {
  if(!name || name[0] != '.') {
    return 0;
  }

  return name[1] == '\0' ||
         (name[1] == '.' && name[2] == '\0');
}

static int
ftp_dir_next_entry(DIR *dir, struct dirent **ent_out) {
  for(;;) {
    errno = 0;
    *ent_out = readdir(dir);
    if(!*ent_out) {
      return errno ? -1 : 0;
    }
    if(!ftp_dirent_is_dots((*ent_out)->d_name)) {
      return 1;
    }
  }
}

#if (defined(AT_FDCWD) || defined(AT_SYMLINK_NOFOLLOW)) && !defined(__ORBIS__)
static int
ftp_dir_fastpath_should_fallback(int err) {
  return err == ENOSYS
#ifdef EINVAL
         || err == EINVAL
#endif
#ifdef EOPNOTSUPP
         || err == EOPNOTSUPP
#endif
         ;
}
#endif

typedef enum {
  FTP_DIRENT_UNKNOWN,
  FTP_DIRENT_REG,
  FTP_DIRENT_DIR,
  FTP_DIRENT_LNK,
  FTP_DIRENT_OTHER,
} ftp_dirent_kind_t;

static ftp_dirent_kind_t
ftp_dirent_kind(const struct dirent *ent) {
  if(!ent) {
    return FTP_DIRENT_UNKNOWN;
  }

#if defined(DT_DIR) && defined(DT_REG) && defined(DT_LNK) && defined(DT_UNKNOWN)
  switch(ent->d_type) {
    case DT_DIR:
      return FTP_DIRENT_DIR;
    case DT_REG:
      return FTP_DIRENT_REG;
    case DT_LNK:
      return FTP_DIRENT_LNK;
    case DT_UNKNOWN:
      return FTP_DIRENT_UNKNOWN;
    default:
      return FTP_DIRENT_OTHER;
  }
#else
  (void)ent;
  return FTP_DIRENT_UNKNOWN;
#endif
}

static int
ftp_dir_open_child(DIR *dir, const char *child_path,
                   const char *name, DIR **child_out) {
  if(!child_path || !name || !child_out) {
    errno = EINVAL;
    return -1;
  }

#if defined(AT_FDCWD) && !defined(__ORBIS__)
  {
    int dir_fd = dirfd(dir);

    if(dir_fd >= 0) {
      int flags = O_RDONLY;
      int fd;

#ifdef O_CLOEXEC
      flags |= O_CLOEXEC;
#endif
#ifdef O_DIRECTORY
      flags |= O_DIRECTORY;
#endif

      fd = openat(dir_fd, name, flags, 0);
      if(fd >= 0) {
        *child_out = fdopendir(fd);
        if(*child_out) {
          return 0;
        }
        {
          int saved_errno = errno;
          close(fd);
          errno = saved_errno;
          return -1;
        }
      }
      if(!ftp_dir_fastpath_should_fallback(errno)) {
        return -1;
      }
    }
  }
#else
  (void)dir;
#endif

  *child_out = opendir(child_path);
  return *child_out ? 0 : -1;
}

static int
ftp_dir_child_lstat(DIR *dir, const char *dir_path,
                    const char *name, struct stat *st) {
#if defined(AT_SYMLINK_NOFOLLOW) && !defined(__ORBIS__)
  int dir_fd = dirfd(dir);

  if(dir_fd >= 0) {
    if(fstatat(dir_fd, name, st, AT_SYMLINK_NOFOLLOW) == 0) {
      return 0;
    }
    if(!ftp_dir_fastpath_should_fallback(errno)) {
      return -1;
    }
  }
#else
  (void)dir;
#endif

  char child[PATH_MAX];
  if(ftp_join_path(child, sizeof(child), dir_path, name) != 0) {
    return -1;
  }

  return lstat(child, st);
}

static int
ftp_dir_size_walk(DIR *dir, const char *path, uintmax_t *size_out) {
  struct dirent *ent;

  if(!dir || !path || !size_out) {
    errno = EINVAL;
    return -1;
  }

  for(;;) {
    int rc = ftp_dir_next_entry(dir, &ent);
    if(rc <= 0) {
      if(rc < 0) {
        return -1;
      }
      break;
    }

    ftp_dirent_kind_t kind = ftp_dirent_kind(ent);
    if(kind == FTP_DIRENT_DIR) {
      char child[PATH_MAX];
      DIR *child_dir;
      int saved_errno;

      if(ftp_join_path(child, sizeof(child), path, ent->d_name) != 0) {
        return -1;
      }
      if(ftp_dir_open_child(dir, child, ent->d_name, &child_dir) != 0) {
        return -1;
      }
      if(ftp_dir_size_walk(child_dir, child, size_out) != 0) {
        saved_errno = errno;
        closedir(child_dir);
        errno = saved_errno;
        return -1;
      }
      if(closedir(child_dir) != 0) {
        return -1;
      }
      continue;
    }

    if(kind == FTP_DIRENT_OTHER) {
      errno = EINVAL;
      return -1;
    }

    struct stat st;
    if(ftp_dir_child_lstat(dir, path, ent->d_name, &st) != 0) {
      return -1;
    }

    if(S_ISDIR(st.st_mode)) {
      char child[PATH_MAX];
      DIR *child_dir;
      int saved_errno;

      if(ftp_join_path(child, sizeof(child), path, ent->d_name) != 0) {
        return -1;
      }
      if(ftp_dir_open_child(dir, child, ent->d_name, &child_dir) != 0) {
        return -1;
      }
      if(ftp_dir_size_walk(child_dir, child, size_out) != 0) {
        saved_errno = errno;
        closedir(child_dir);
        errno = saved_errno;
        return -1;
      }
      if(closedir(child_dir) != 0) {
        return -1;
      }
      continue;
    }

    if(S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
      if(UINTMAX_MAX - *size_out < (uintmax_t)st.st_size) {
        errno = EOVERFLOW;
        return -1;
      }
      *size_out += (uintmax_t)st.st_size;
      continue;
    }

    errno = EINVAL;
    return -1;
  }

  return 0;
}

static int
ftp_dir_child_unlink(DIR *dir, const char *dir_path, const char *name) {
#if defined(AT_FDCWD) && !defined(__ORBIS__)
  int dir_fd = dirfd(dir);

  if(dir_fd >= 0) {
    if(unlinkat(dir_fd, name, 0) == 0) {
      return 0;
    }
    if(!ftp_dir_fastpath_should_fallback(errno)) {
      return -1;
    }
  }
#else
  (void)dir;
#endif

  char child[PATH_MAX];
  if(ftp_join_path(child, sizeof(child), dir_path, name) != 0) {
    return -1;
  }

  return unlink(child);
}

static void
ftp_store_first_error(int *err_out, int err) {
  if(err_out && !*err_out) {
    *err_out = err;
  }
}

static int
ftp_delete_count_dir(const char *path, uintmax_t *count_out) {
  DIR *dir = opendir(path);
  struct dirent *ent;

  if(!dir) {
    return -1;
  }

  for(;;) {
    if(ftp_server_bg_op_cancelled()) {
      closedir(dir);
      errno = FTP_BG_OP_CANCELLED_ERR;
      return -1;
    }
    int rc = ftp_dir_next_entry(dir, &ent);
    if(rc <= 0) {
      if(rc < 0) {
        int saved_errno = errno;
        closedir(dir);
        errno = saved_errno;
        return -1;
      }
      break;
    }

    struct stat st;
    if(ftp_dir_child_lstat(dir, path, ent->d_name, &st) != 0) {
      int err = errno;
      closedir(dir);
      errno = err;
      return -1;
    }

    if(S_ISDIR(st.st_mode)) {
      char child[PATH_MAX];

      if(ftp_join_path(child, sizeof(child), path, ent->d_name) != 0) {
        int err = errno;
        closedir(dir);
        errno = err;
        return -1;
      }
      if(ftp_delete_count_dir(child, count_out) != 0) {
        int err = errno;
        closedir(dir);
        errno = err;
        return -1;
      }
    } else if(!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
      int err = EINVAL;
      closedir(dir);
      errno = err;
      return -1;
    }

    *count_out = ftp_saturating_add(*count_out, 1);
  }

  if(closedir(dir) != 0) {
    return -1;
  }

  *count_out = ftp_saturating_add(*count_out, 1);
  return 0;
}

static int
ftp_rmda_delete_dir(const char *path, int *err_out, ftp_delete_task_t *task) {
  DIR *dir = opendir(path);
  if(!dir) {
    ftp_store_first_error(err_out, errno);
    return -1;
  }

  int failed = 0;
  struct dirent *ent;
  for(;;) {
    if(ftp_server_bg_op_cancelled()) {
      ftp_store_first_error(err_out, FTP_BG_OP_CANCELLED_ERR);
      failed = 1;
      break;
    }
    int rc = ftp_dir_next_entry(dir, &ent);
    if(rc <= 0) {
      if(rc < 0) {
        ftp_store_first_error(err_out, errno);
        failed = 1;
      }
      break;
    }

    struct stat st;
    if(ftp_dir_child_lstat(dir, path, ent->d_name, &st) != 0) {
      ftp_store_first_error(err_out, errno);
      failed = 1;
      continue;
    }

    if(S_ISDIR(st.st_mode)) {
      char child[PATH_MAX];

      if(ftp_join_path(child, sizeof(child), path, ent->d_name) != 0) {
        ftp_store_first_error(err_out, errno);
        failed = 1;
        continue;
      }
      if(ftp_rmda_delete_dir(child, err_out, task)) {
        failed = 1;
        if(ftp_server_bg_op_cancelled()) {
          break;
        }
      }
      continue;
    }

    if(ftp_dir_child_unlink(dir, path, ent->d_name) != 0) {
      ftp_store_first_error(err_out, errno);
      failed = 1;
    } else {
      ftp_delete_progress_add(task, 1);
    }
  }

  if(closedir(dir)) {
    ftp_store_first_error(err_out, errno);
    failed = 1;
  }

  if(failed) {
    return -1;
  }

  if(ftp_server_bg_op_cancelled()) {
    ftp_store_first_error(err_out, FTP_BG_OP_CANCELLED_ERR);
    return -1;
  }

  if(rmdir(path)) {
    ftp_store_first_error(err_out, errno);
    return -1;
  }

  ftp_delete_progress_add(task, 1);
  return 0;
}

static ftp_delete_task_t*
ftp_delete_create_task(ftp_env_t *env, const char *path) {
  ftp_delete_task_t *task;

  if(!env || !path) {
    errno = EINVAL;
    return NULL;
  }

  task = calloc(1, sizeof(*task));
  if(!task) {
    return NULL;
  }

  task->env = env;
  snprintf(task->path, sizeof(task->path), "%s", path);
  ftp_compact_path(path, task->path_notify, sizeof(task->path_notify));
  return task;
}

static void
ftp_delete_thread_cleanup(ftp_env_t *env) {
  pthread_t thread;
  int should_join = 0;

  pthread_mutex_lock(&env->delete_mutex);
  if(env->delete_thread_valid && !env->delete_in_progress) {
    thread = env->delete_thread;
    env->delete_thread_valid = 0;
    should_join = 1;
  }
  pthread_mutex_unlock(&env->delete_mutex);

  if(should_join) {
    pthread_join(thread, NULL);
  }
}

static int
ftp_delete_start_task(ftp_env_t *env, ftp_delete_task_t *task) {
  int thread_rc;

  if(!ftp_server_bg_op_acquire()) {
    free(task);
    return ftp_active_printf(env, "450 Background file operation in progress\r\n");
  }

  pthread_mutex_lock(&env->delete_mutex);
  env->delete_in_progress = 1;
  env->delete_thread_valid = 1;
  pthread_mutex_unlock(&env->delete_mutex);

  thread_rc = pthread_create(&env->delete_thread, NULL,
                             ftp_delete_thread, task);
  if(thread_rc != 0) {
    pthread_mutex_lock(&env->delete_mutex);
    env->delete_in_progress = 0;
    env->delete_thread_valid = 0;
    pthread_mutex_unlock(&env->delete_mutex);
    ftp_server_bg_op_release();
    free(task);
    errno = thread_rc;
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "250 Delete started in background\r\n");
}

static void *
ftp_delete_thread(void *arg) {
  ftp_delete_task_t *task = (ftp_delete_task_t *)arg;
  ftp_env_t *env = task->env;
  int err = 0;
  int rc;

  ftp_delete_notify_start(task);

  rc = ftp_delete_count_dir(task->path, &task->progress.total_entries);
  if(rc == 0) {
    rc = ftp_rmda_delete_dir(task->path, &err, task);
  } else {
    err = errno;
  }

  if(rc != 0 && err == 0) {
    err = errno;
  }

  ftp_delete_notify_result(task, rc, err);

  pthread_mutex_lock(&env->delete_mutex);
  env->delete_in_progress = 0;
  pthread_mutex_unlock(&env->delete_mutex);
  ftp_server_bg_op_release();

  free(task);
  return NULL;
}

typedef struct {
  char *argbuf;
  char *list_path;
  char *pathbuf;
  const char *dir_path;
  DIR *dir;
} ftp_list_ctx_t;

/**
 * Fetch the next directory entry, returning 1/0/-1.
 **/
static int
ftp_list_next_dirent(DIR *dir, struct dirent **ent_out) {
  errno = 0;
  *ent_out = readdir(dir);
  if(!*ent_out) {
    return errno ? -1 : 0;
  }
  return 1;
}

/**
 * Stat a directory entry and apply any size adjustments.
 **/
static int
ftp_list_get_stat(ftp_env_t *env, int dir_fd, const char *dir_path,
                  char *pathbuf, size_t pathbuf_sz, struct dirent *ent,
                  struct stat *statbuf) {
  int have_path = 0;
  int stat_rc = -1;

#if defined(AT_SYMLINK_NOFOLLOW) && !defined(__ORBIS__)
  if(dir_fd >= 0) {
    stat_rc = fstatat(dir_fd, ent->d_name, statbuf, AT_SYMLINK_NOFOLLOW);
  }
#else
  (void)dir_fd;
#endif

  if(stat_rc != 0) {
    if(ftp_join_path(pathbuf, pathbuf_sz, dir_path, ent->d_name) != 0) {
      return -1;
    }
    have_path = 1;
#ifdef AT_SYMLINK_NOFOLLOW
    if(lstat(pathbuf, statbuf) != 0)
#else
    if(stat(pathbuf, statbuf) != 0)
#endif
    {
      return -1;
    }
  }

  if(env->self2elf && S_ISREG(statbuf->st_mode)) {
    if(!have_path) {
      if(ftp_join_path(pathbuf, pathbuf_sz, dir_path, ent->d_name) != 0) {
        return -1;
      }
      have_path = 1;
    }
    size_t elf_size = self_is_valid(pathbuf);
    if(elf_size && ftp_set_stat_size(statbuf, elf_size) != 0) {
      return -1;
    }
  }

  return 0;
}

/**
 * Iterate directory entries until one can be stat'd.
 **/
static int
ftp_list_next_entry(ftp_env_t *env, DIR *dir, int dir_fd, const char *dir_path,
                    char *pathbuf, size_t pathbuf_sz, struct dirent **ent_out,
                    struct stat *statbuf) {
  for(;;) {
    struct dirent *ent = NULL;
    int rc = ftp_list_next_dirent(dir, &ent);
    if(rc <= 0) {
      return rc;
    }
    if(ftp_list_get_stat(env, dir_fd, dir_path, pathbuf, pathbuf_sz,
                         ent, statbuf) != 0) {
      continue;
    }
    *ent_out = ent;
    return 1;
  }
}


/**
 * Escape a symlink target for MLST/MLSD output.
 **/
static void
ftp_escape_slink(char *dst, size_t dst_sz, const char *prefix,
                 const char *src, size_t src_len) {
  size_t pos = 0;
  size_t remaining = dst_sz;
  static const char hex[] = "0123456789ABCDEF";

  if(!dst || !dst_sz) {
    return;
  }

  int wrote = snprintf(dst, dst_sz, "%s", prefix);
  if(wrote < 0) {
    dst[0] = '\0';
    return;
  }
  if((size_t)wrote >= dst_sz) {
    dst[dst_sz - 1] = '\0';
    return;
  }

  pos = (size_t)wrote;
  remaining = dst_sz - pos;

  for(size_t i = 0; i < src_len && remaining > 1; i++) {
    unsigned char c = (unsigned char)src[i];
    int safe = (c >= 0x20 && c < 0x7f && c != ';' && c != '%');
    if(safe) {
      dst[pos++] = (char)c;
      remaining--;
      continue;
    }
    if(remaining <= 3) {
      break;
    }
    dst[pos++] = '%';
    dst[pos++] = hex[(c >> 4) & 0x0f];
    dst[pos++] = hex[c & 0x0f];
    remaining -= 3;
  }

  if(remaining > 1) {
    dst[pos++] = ';';
    remaining--;
  }
  dst[pos] = '\0';
}


/**
 * Build the MLST type fact string for an entry.
 **/
static const char *
ftp_mlst_type_fact(char *dst, size_t dst_sz, const char *name,
                   const struct stat *st, const char *path) {
  const char *slink_prefix = "type=OS.unix=slink:";
  if(name && name[0] == '.' && name[1] == '\0') {
    (void)snprintf(dst, dst_sz, "type=cdir;");
    return dst;
  }
  if(name && name[0] == '.' && name[1] == '.' && name[2] == '\0') {
    (void)snprintf(dst, dst_sz, "type=pdir;");
    return dst;
  }
  if(S_ISDIR(st->st_mode)) {
    (void)snprintf(dst, dst_sz, "type=dir;");
    return dst;
  }
  if(S_ISREG(st->st_mode)) {
    (void)snprintf(dst, dst_sz, "type=file;");
    return dst;
  }
  if(S_ISLNK(st->st_mode)) {
    char linkbuf[256];
    if(path) {
      ssize_t n = readlink(path, linkbuf, sizeof(linkbuf) - 1);
      if(n >= 0) {
        linkbuf[n] = '\0';
        ftp_escape_slink(dst, dst_sz, slink_prefix, linkbuf, (size_t)n);
        return dst;
      }
    }
    (void)snprintf(dst, dst_sz, "type=OS.unix=slink;");
    return dst;
  }
  if(S_ISCHR(st->st_mode)) {
    (void)snprintf(dst, dst_sz, "type=OS.unix=chr-%u/%u;",
                   (unsigned)major(st->st_rdev),
                   (unsigned)minor(st->st_rdev));
    return dst;
  }
  if(S_ISBLK(st->st_mode)) {
    (void)snprintf(dst, dst_sz, "type=OS.unix=blk-%u/%u;",
                   (unsigned)major(st->st_rdev),
                   (unsigned)minor(st->st_rdev));
    return dst;
  }
  if(S_ISFIFO(st->st_mode)) {
    (void)snprintf(dst, dst_sz, "type=OS.unix=fifo;");
    return dst;
  }
  if(S_ISSOCK(st->st_mode)) {
    (void)snprintf(dst, dst_sz, "type=OS.unix=socket;");
    return dst;
  }
  (void)snprintf(dst, dst_sz, "type=unknown;");
  return dst;
}

/**
 * Build the MLST unique fact string for an entry.
 **/
static const char *
ftp_mlst_unique_fact(char *dst, size_t dst_sz, const struct stat *st) {
  (void)snprintf(dst, dst_sz, "unique=%" PRIxMAX ".%" PRIxMAX ";",
                 (uintmax_t)st->st_dev, (uintmax_t)st->st_ino);
  return dst;
}

/**
 * Format a full MLST/MLSD line with facts.
 **/
static int
ftp_mlst_format_line(char *dst, size_t dst_sz, int leading_space,
                     const char *type, const char *unique, uintmax_t size,
                     time_t mtime, unsigned mode_bits, uintmax_t uid,
                     uintmax_t gid, const char *name) {
  char timebuf[32];
  if(ftp_format_mdtm(mtime, timebuf, sizeof(timebuf))) {
    return -1;
  }
  int n = snprintf(dst, dst_sz,
                   "%s%s%ssize=%" PRIuMAX ";modify=%s;unix.mode=%04o;"
                   "unix.uid=%" PRIuMAX ";unix.gid=%" PRIuMAX "; %s\r\n",
                   leading_space ? " " : "", type, unique, size, timebuf,
                   mode_bits, uid, gid, name);
  if(n < 0 || (size_t)n >= dst_sz) {
    return -1;
  }
  return 0;
}

/**
 * Free buffers in the list context.
 **/
static void
ftp_list_ctx_free(ftp_list_ctx_t *ctx) {
  if(ctx->pathbuf) {
    free(ctx->pathbuf);
  }
  if(ctx->list_path) {
    free(ctx->list_path);
  }
  if(ctx->argbuf) {
    free(ctx->argbuf);
  }
  ctx->pathbuf = NULL;
  ctx->list_path = NULL;
  ctx->argbuf = NULL;
  ctx->dir_path = NULL;
  ctx->dir = NULL;
}

/**
 * Prepare list context, resolve path, and open directory if needed.
 * Returns 0 on success, 1 if an FTP error reply was sent, or -1 if replying
 * failed and the control connection should be closed.
 **/
static int
ftp_list_open(ftp_env_t *env, const char *arg, int need_pathbuf,
              int allow_file, int allow_opts, ftp_list_ctx_t *ctx,
              int *dir_errno) {
  memset(ctx, 0, sizeof(*ctx));

  // Allocate large buffers on Heap to avoid SceLibcInternalHeap error due to stack overflow
  ctx->argbuf = malloc(PATH_MAX + 1);
  ctx->list_path = malloc(PATH_MAX + 1);
  if(need_pathbuf) {
    ctx->pathbuf = malloc(PATH_MAX * 3);
  }

  if(!ctx->argbuf || !ctx->list_path || (need_pathbuf && !ctx->pathbuf)) {
    int err;
    ftp_list_ctx_free(ctx);
    err = ftp_perror(env);
    return err < 0 ? -1 : 1;
  }

  const char *dir_path = allow_opts
                           ? ftp_list_path_arg(arg, ctx->argbuf, PATH_MAX + 1)
                           : ftp_copy_path_arg(arg, ctx->argbuf, PATH_MAX + 1);
  if(dir_path) {
    if(ftp_abspath(env, ctx->list_path, PATH_MAX + 1, dir_path)) {
      int err;
      ftp_list_ctx_free(ctx);
      err = ftp_perror(env);
      return err < 0 ? -1 : 1;
    }
  } else {
    if(ftp_normpath(env->cwd, ctx->list_path, PATH_MAX + 1)) {
      int err;
      ftp_list_ctx_free(ctx);
      err = ftp_perror(env);
      return err < 0 ? -1 : 1;
    }
  }
  ctx->dir_path = ctx->list_path;

  ctx->dir = opendir(ctx->dir_path);
  if(!ctx->dir) {
    if(dir_errno) {
      *dir_errno = errno;
    }
    if(allow_file) {
      return 0;
    }
    int err;
    ftp_list_ctx_free(ctx);
    err = ftp_perror(env);
    return err < 0 ? -1 : 1;
  }
  if(dir_errno) {
    *dir_errno = 0;
  }

  return 0;
}

/**
 * Trasfer a list of files and folder.
 **/
int
ftp_cmd_LIST(ftp_env_t *env, const char *arg) {
  ftp_list_ctx_t ctx;
  struct dirent *ent;
  struct stat statbuf;
  char timebuf[32];
  char modebuf[20];
  ftp_xfer_buf_t x;
  int dir_errno = 0;
  int err = ftp_list_open(env, arg, 1, 1, 1, &ctx, &dir_errno);
  if(err) {
    return err < 0 ? err : 0;
  }

  if(!ctx.dir) {
    struct stat st;
    if(lstat(ctx.dir_path, &st)) {
      err = ftp_perror(env);
      ftp_list_ctx_free(&ctx);
      return err;
    }
    if(S_ISDIR(st.st_mode)) {
      if(dir_errno) {
        errno = dir_errno;
      }
      err = ftp_perror(env);
      ftp_list_ctx_free(&ctx);
      return err;
    }

    if(env->self2elf && S_ISREG(st.st_mode)) {
      size_t elf_size = self_is_valid(ctx.dir_path);
      if(elf_size && ftp_set_stat_size(&st, elf_size) != 0) {
        err = ftp_perror(env);
        ftp_list_ctx_free(&ctx);
        return err;
      }
    }

    int err_xfer = ftp_list_xfer_start(env, NULL, &x);
    if(err_xfer) {
      ftp_list_ctx_free(&ctx);
      return err_xfer < 0 ? err_xfer : 0;
    }

    ftp_mode_string(st.st_mode, modebuf);
    if(!ftp_format_list_time(st.st_mtime, timebuf, sizeof(timebuf))) {
      const char *name = strrchr(ctx.dir_path, '/');
      name = name ? name + 1 : ctx.dir_path;
      if(!*name) {
        name = ctx.dir_path;
      }
      if(ftp_xfer_printf(&x,
                         "%s %" PRIuMAX " %" PRIuMAX " %" PRIuMAX
                         " %" PRIuMAX " %s %s\r\n",
                         modebuf, (uintmax_t)st.st_nlink,
                         (uintmax_t)st.st_uid,
                         (uintmax_t)st.st_gid,
                         (uintmax_t)st.st_size, timebuf, name)) {
        // formatting error or transfer failure, handled in finish
      }
    }

    err = ftp_list_xfer_finish(env, NULL, &x);
    ftp_list_ctx_free(&ctx);
    return err;
  }

  int err_xfer = ftp_list_xfer_start(env, ctx.dir, &x);
  if(err_xfer) {
    ftp_list_ctx_free(&ctx);
    return err_xfer < 0 ? err_xfer : 0;
  }

  int dir_fd = -1;
#if defined(AT_SYMLINK_NOFOLLOW) && !defined(__ORBIS__)
  dir_fd = dirfd(ctx.dir);
#endif

  int read_errno = 0;

  for(;;) {
    int next = ftp_list_next_entry(env, ctx.dir, dir_fd, ctx.dir_path,
                                   ctx.pathbuf, PATH_MAX * 3, &ent, &statbuf);
    if(next < 0) {
      read_errno = errno;
      break;
    }
    if(next == 0) {
      break;
    }

    ftp_mode_string(statbuf.st_mode, modebuf);
    if(ftp_format_list_time(statbuf.st_mtime, timebuf, sizeof(timebuf))) {
      continue;
    }

    if(ftp_xfer_printf(&x,
                       "%s %" PRIuMAX " %" PRIuMAX " %" PRIuMAX
                       " %" PRIuMAX " %s %s\r\n",
                       modebuf, (uintmax_t)statbuf.st_nlink,
                       (uintmax_t)statbuf.st_uid,
                       (uintmax_t)statbuf.st_gid,
                       (uintmax_t)statbuf.st_size, timebuf, ent->d_name)) {
      if(x.failed) {
        break;
      }
      // formatting error -> skip entry
      continue;
    }

    if(x.failed) {
      break;
    }
  }

  if(read_errno && !x.failed) {
    errno = read_errno;
    (void)ftp_perror(env);
    x.failed = 1;
  }

  err = ftp_list_xfer_finish(env, ctx.dir, &x);
  ftp_list_ctx_free(&ctx);
  return err;
}


/**
 * Transfer a list of file names (no stat).
 **/
int
ftp_cmd_NLST(ftp_env_t *env, const char *arg) {
  ftp_list_ctx_t ctx;
  struct dirent *ent;
  ftp_xfer_buf_t x;
  int err = ftp_list_open(env, arg, 0, 0, 0, &ctx, NULL);
  if(err) {
    return err < 0 ? err : 0;
  }

  int err_xfer = ftp_list_xfer_start(env, ctx.dir, &x);
  if(err_xfer) {
    ftp_list_ctx_free(&ctx);
    return err_xfer < 0 ? err_xfer : 0;
  }

  int read_errno = 0;

  for(;;) {
    int next = ftp_list_next_dirent(ctx.dir, &ent);
    if(next < 0) {
      read_errno = errno;
      break;
    }
    if(next == 0) {
      break;
    }

    if(ftp_xfer_printf(&x, "%s\r\n", ent->d_name)) {
      if(x.failed) {
        break;
      }
      // shouldn't happen; but if it does, skip entry 
      continue;
    }

    if(x.failed) {
      break;
    }
  }

  if(read_errno && !x.failed) {
    errno = read_errno;
    (void)ftp_perror(env);
    x.failed = 1;
  }
  
  err = ftp_list_xfer_finish(env, ctx.dir, &x);
  ftp_list_ctx_free(&ctx);
  return err;
}


/**
 * Transfer a machine-readable list.
 **/
int
ftp_cmd_MLSD(ftp_env_t *env, const char *arg) {
  ftp_list_ctx_t ctx;
  struct dirent *ent;
  struct stat statbuf;
  ftp_xfer_buf_t x;
  int err = ftp_list_open(env, arg, 1, 0, 0, &ctx, NULL);
  if(err) {
    return err < 0 ? err : 0;
  }

  int err_xfer = ftp_list_xfer_start(env, ctx.dir, &x);
  if(err_xfer) {
    ftp_list_ctx_free(&ctx);
    return err_xfer < 0 ? err_xfer : 0;
  }

  int dir_fd = -1;
#if defined(AT_SYMLINK_NOFOLLOW) && !defined(__ORBIS__)
  dir_fd = dirfd(ctx.dir);
#endif

  int read_errno = 0;

  for(;;) {
    const char *type;
    const char *unique;
    uintmax_t size;
    unsigned mode_bits;
    uintmax_t uid;
    uintmax_t gid;
    char *typebuf = ctx.argbuf;
    char uniquebuf[64];
    char *linebuf = ctx.pathbuf;

    int next = ftp_list_next_entry(env, ctx.dir, dir_fd, ctx.dir_path,
                                   ctx.pathbuf, PATH_MAX * 3, &ent, &statbuf);
    if(next < 0) {
      read_errno = errno;
      break;
    }
    if(next == 0) {
      break;
    }

    const char *link_path = NULL;
    if(S_ISLNK(statbuf.st_mode)) {
      if(ftp_join_path(ctx.pathbuf, PATH_MAX * 3, ctx.dir_path,
                       ent->d_name) == 0) {
        link_path = ctx.pathbuf;
      }
    }
    type = ftp_mlst_type_fact(typebuf, PATH_MAX + 1, ent->d_name, &statbuf,
                              link_path);
    unique = ftp_mlst_unique_fact(uniquebuf, sizeof(uniquebuf), &statbuf);

    size = (uintmax_t)statbuf.st_size;
    mode_bits = (unsigned)(statbuf.st_mode & 07777);
    uid = (uintmax_t)statbuf.st_uid;
    gid = (uintmax_t)statbuf.st_gid;

    if(ftp_mlst_format_line(linebuf, PATH_MAX * 3, 0, type, unique, size,
                            statbuf.st_mtime, mode_bits, uid, gid,
                            ent->d_name)) {
      continue;
    }

    if(ftp_xfer_printf(&x, "%s", linebuf)) {
      if(x.failed) {
        break;
      }
      continue;
    }

    if(x.failed) {
      break;
    }
  }

  if(read_errno && !x.failed) {
    errno = read_errno;
    (void)ftp_perror(env);
    x.failed = 1;
  }
  
  err = ftp_list_xfer_finish(env, ctx.dir, &x);
  ftp_list_ctx_free(&ctx);
  return err;
}


/**
 * Create a new directory at a given path.
 **/
int
ftp_cmd_MKD(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: MKD <DIRNAME>\r\n");
  }

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }
  if(mkdir(pathbuf, 0777)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "257 \"%s\"\r\n", pathbuf);
}


/**
 * No operation.
 **/
int
ftp_cmd_NOOP(ftp_env_t *env, const char* arg) {
  (void)arg;
  return ftp_active_printf(env, "200 NOOP OK\r\n");
}


/**
 * Establish a data connection with client.
 **/
int
ftp_cmd_PORT(ftp_env_t *env, const char* arg) {
  unsigned int addr[6];
  struct in_addr in_addr;
  uint32_t s_addr_host;
  uint16_t port_host;
  char tail;
  int ret = 0;

  if(sscanf(arg, "%3u,%3u,%3u,%3u,%3u,%3u%c",
            addr, addr+1, addr+2, addr+3, addr+4, addr+5, &tail) != 6) {
    return ftp_active_printf(env, "501 Usage: PORT <addr>\r\n");
  }
  for(int i=0; i<6; i++) {
    if(addr[i] > 255) {
      return ftp_active_printf(env, "501 Usage: PORT <addr>\r\n");
    }
  }

  s_addr_host = ((uint32_t)addr[0] << 24) |
                ((uint32_t)addr[1] << 16) |
                ((uint32_t)addr[2] << 8) |
                (uint32_t)addr[3];
  in_addr.s_addr = htonl(s_addr_host);
  port_host = (uint16_t)((addr[4] << 8) | addr[5]);

  ret = ftp_setup_active_data(env, in_addr, port_host,
                              "500 Illegal PORT command");
  if(ret) {
    return ret;
  }

  return ftp_active_printf(env, "200 PORT command successful.\r\n");
}

/**
 * Establish a data connection with client (extended).
 **/
int
ftp_cmd_EPRT(ftp_env_t *env, const char *arg) {
  char addrbuf[INET_ADDRSTRLEN] = {0};
  char portbuf[16] = {0};
  char delim;
  const char *p1;
  const char *p2;
  const char *p3;
  char *endptr = NULL;
  unsigned long port_ul;
  struct in_addr in_addr;
  int ret = 0;

  delim = arg[0];
  p1 = (arg[0] ? strchr(arg + 1, delim) : NULL);
  p2 = (p1 ? strchr(p1 + 1, delim) : NULL);
  p3 = (p2 ? strchr(p2 + 1, delim) : NULL);

  if(!arg[0] || !p1 || !p2 || !p3 || p3[1]) {
    return ftp_active_printf(
      env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }
  if(p1 != arg + 2 || arg[1] != '1') {
    return ftp_active_printf(env, "522 Network protocol not supported\r\n");
  }

  size_t addr_len = (size_t)(p2 - (p1 + 1));
  if(!addr_len || addr_len >= sizeof(addrbuf)) {
    return ftp_active_printf(
      env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }
  memcpy(addrbuf, p1 + 1, addr_len);
  addrbuf[addr_len] = '\0';

  size_t port_len = (size_t)(p3 - (p2 + 1));
  if(!port_len || port_len >= sizeof(portbuf)) {
    return ftp_active_printf(
      env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }
  memcpy(portbuf, p2 + 1, port_len);
  portbuf[port_len] = '\0';

  if(inet_pton(AF_INET, addrbuf, &in_addr) != 1) {
    return ftp_active_printf(
      env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }

  port_ul = strtoul(portbuf, &endptr, 10);
  if(!port_ul || port_ul > 65535 || endptr == portbuf || *endptr) {
    return ftp_active_printf(
      env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }

  ret = ftp_setup_active_data(env, in_addr, (uint16_t)port_ul,
                              "500 Illegal EPRT command");
  if(ret) {
    return ret;
  }

  return ftp_active_printf(env, "200 EPRT command successful.\r\n");
}

/**
 * Print working directory.
 **/
int
ftp_cmd_PWD(ftp_env_t *env, const char* arg) {
  (void)arg;
  return ftp_active_printf(env, "257 \"%s\"\r\n", env->cwd);
}


/**
 * Disconnect client.
 **/
int
ftp_cmd_QUIT(ftp_env_t *env, const char* arg) {
  (void)arg;
  ftp_active_printf(env, "221 Goodbye\r\n");
  return -1;
}


/**
 * Mark the offset to start from in a future file transer.
 **/
int
ftp_cmd_REST(ftp_env_t *env, const char* arg) {
  char *end = NULL;
  long long off = 0;

  if(env->type == 'A') {
    env->data_offset = 0;
    env->data_offset_is_rest = 0;
    return ftp_active_printf(env, "504 REST not supported in ASCII mode\r\n");
  }

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: REST <OFFSET>\r\n");
  }

  errno = 0;
  off = strtoll(arg, &end, 10);
  if(errno || end == arg) {
    return ftp_active_printf(env, "501 Usage: REST <OFFSET>\r\n");
  }
  if(*end || off < 0 || (off_t)off != off) {
    return ftp_active_printf(env, "501 Usage: REST <OFFSET>\r\n");
  }

  env->data_offset = (off_t)off;

    env->data_offset_is_rest = 1;
  return ftp_active_printf(env, "350 REST OK\r\n");
}


/**
 * Retreive data from a given file.
 **/
static int
ftp_cmd_RETR_fd(ftp_env_t *env, int fd) {
  off_t off = env->data_offset;
  int is_rest = env->data_offset_is_rest;
  env->data_offset = 0;
  env->data_offset_is_rest = 0;
  struct stat st;
  size_t remaining;
  int err = 0;
  int active = 0;

  if(env->type == 'A' && off != 0 && is_rest) {
    return ftp_active_printf(env, "504 REST not supported in ASCII mode\r\n");
  }

  if(fstat(fd, &st)) {
    return ftp_perror(env);
  }
  if(lseek(fd, off, SEEK_SET) < 0) {
    return ftp_perror(env);
  }

  if(off >= st.st_size) {
    remaining = 0;
  } else {
    remaining = (size_t)(st.st_size - off);
  }

  int open_err = ftp_data_xfer_start(env, 1);
  if(open_err) {
    return open_err < 0 ? open_err : 0;
  }
  kstuff_autopause_active_begin();
  active = 1;

  if(env->type == 'A') {
    if(ftp_copy_ascii_out(env, fd)) {
      err = ftp_data_xfer_error_reply(env);
      ftp_data_close(env);
      goto out;
    }
  } else if(remaining) {
#if defined(IO_USE_AIO)
    return ftp_cmd_RETR_fd_aio(env, fd, off, remaining);
#else
    if(remaining < 1460) {  // Typical MSS size
#ifdef TCP_NODELAY
      (void)setsockopt(env->data_fd, IPPROTO_TCP, TCP_NODELAY,  &(int){1},
                       sizeof(int));
#endif
    } else if(remaining >= 128*1024) {
#ifdef TCP_NOPUSH
      (void)setsockopt(env->data_fd, IPPROTO_TCP, TCP_NOPUSH,  &(int){1},
                       sizeof(int));
#endif
    }

#ifdef IO_USE_SENDFILE
    if(io_sendfile(fd, env->data_fd, off, remaining)) {
      err = ftp_data_xfer_error_reply(env);
      ftp_data_close(env);
      goto out;
    }
#else

    if(env->xfer_buf && env->xfer_buf_size) {
      if(io_ncopy_buf(fd, env->data_fd, remaining, env->xfer_buf,
                      env->xfer_buf_size)) {
        err = ftp_data_xfer_error_reply(env);
        ftp_data_close(env);
        goto out;
      }
    } else if(io_ncopy(fd, env->data_fd, remaining)) {
      err = ftp_data_xfer_error_reply(env);
      ftp_data_close(env);
      goto out;
    }
#endif
#endif
  }

  if(ftp_data_close(env)) {
    err = ftp_perror(env);
    goto out;
  }

  err = ftp_active_printf(env, "226 Transfer completed\r\n");

out:
  if(active) {
    kstuff_autopause_active_end();
  }
  return err;
}


/**
 * Retreive an ELF file embedded within a SELF file.
 **/
static int
ftp_cmd_RETR_self2elf(ftp_env_t *env, int fd) {
  FILE* tmpf;
  int err;

  if(!(tmpf=tmpfile())) {
    return ftp_perror(env);
  }

  if(ftp_active_printf(env, "150-Extracting ELF...\r\n")) {
    fclose(tmpf);
    return -1;
  }
  kstuff_autopause_required_begin();
  if(self_extract_elf_ex(fd, fileno(tmpf), env->self_verify)) {
    kstuff_autopause_required_end();
    if(errno != EBADMSG) {
      err = ftp_perror(env);
      fclose(tmpf);
      return err;
    }
    if(ftp_active_printf(env, "150-Warning: ELF digest mismatch\r\n")) {
      fclose(tmpf);
      return -1;
    }
  } else {
    kstuff_autopause_required_end();
  }

  rewind(tmpf);
  err = ftp_cmd_RETR_fd(env, fileno(tmpf));
  fclose(tmpf);

  return err;
}

#if defined(IO_USE_AIO)
static int
ftp_cmd_RETR_fd_aio(ftp_env_t *env, int fd, off_t off, size_t remaining) {
  void *buffers[IO_AIO_READ_QUEUE_DEPTH] = {0};
  int buffer_owned[IO_AIO_READ_QUEUE_DEPTH] = {0};
  io_aio_slot_t slots[IO_AIO_READ_QUEUE_DEPTH];
  size_t bufsize = env->xfer_buf_size;
  int head = 0;
  int queued = 0;
  off_t next_off = off;
  ssize_t len = 0;
  int err = 0;
  int i;

  memset(slots, 0, sizeof(slots));

  if(io_aio_require() != 0) {
    err = ftp_perror(env);
    (void)ftp_data_close(env);
    kstuff_autopause_active_end();
    return err;
  }

  if(!bufsize || bufsize < IO_AIO_CHUNK_SIZE) {
    bufsize = IO_AIO_CHUNK_SIZE;
  }

  if(env->xfer_buf && env->xfer_buf_size >= bufsize) {
    buffers[0] = env->xfer_buf;
  } else {
    buffers[0] = malloc(bufsize);
    buffer_owned[0] = 1;
  }

  if(!buffers[0]) {
    err = ftp_perror(env);
    (void)ftp_data_close(env);
    kstuff_autopause_active_end();
    return err;
  }

  for(i=1; i<IO_AIO_READ_QUEUE_DEPTH; i++) {
    buffers[i] = malloc(bufsize);
    buffer_owned[i] = 1;
    if(!buffers[i]) {
      err = ftp_perror(env);
      (void)ftp_data_close(env);
      ftp_free_owned_buffers(buffers, buffer_owned, IO_AIO_READ_QUEUE_DEPTH);
      kstuff_autopause_active_end();
      return err;
    }
  }

  while(queued < IO_AIO_READ_QUEUE_DEPTH && remaining > 0) {
    size_t chunk = remaining < bufsize ? remaining : bufsize;
    int slot_idx = (head + queued) % IO_AIO_READ_QUEUE_DEPTH;

    if(io_aio_read_submit(&slots[slot_idx], fd, buffers[slot_idx], chunk,
                          next_off) != 0) {
      err = ftp_perror(env);
      (void)ftp_data_close(env);
      ftp_free_owned_buffers(buffers, buffer_owned, IO_AIO_READ_QUEUE_DEPTH);
      kstuff_autopause_active_end();
      return err;
    }

    next_off += (off_t)chunk;
    remaining -= chunk;
    queued++;
  }

  while(queued > 0) {
    io_aio_slot_t *slot = &slots[head];

    if(slot->ready) {
      len = slot->result_len;
      if(len <= 0 || io_nwrite(env->data_fd, buffers[head], (size_t)len)) {
        err = ftp_data_xfer_error_reply(env);
        break;
      }

      slot->ready = 0;
      slot->result_len = 0;
      queued--;
      head = (head + 1) % IO_AIO_READ_QUEUE_DEPTH;

      if(remaining > 0) {
        size_t chunk = remaining < bufsize ? remaining : bufsize;
        int slot_idx = (head + queued) % IO_AIO_READ_QUEUE_DEPTH;

        if(io_aio_read_submit(&slots[slot_idx], fd, buffers[slot_idx], chunk,
                              next_off) != 0) {
          err = ftp_perror(env);
          break;
        }

        next_off += (off_t)chunk;
        remaining -= chunk;
        queued++;
      }

      continue;
    }

    if(!slot->in_flight) {
      errno = EIO;
      err = ftp_perror(env);
      break;
    }

    i = io_aio_wait_any(slots, IO_AIO_READ_QUEUE_DEPTH);
    if(i < 0) {
      err = ftp_perror(env);
      break;
    }
    if(i == 0) {
      errno = EIO;
      err = ftp_perror(env);
      break;
    }
  }

  if(io_aio_drain(slots, IO_AIO_READ_QUEUE_DEPTH) != 0 && !err) {
    err = ftp_perror(env);
  }

  if(err) {
    (void)ftp_data_close(env);
    ftp_free_owned_buffers(buffers, buffer_owned, IO_AIO_READ_QUEUE_DEPTH);
    kstuff_autopause_active_end();
    return err;
  }

  if(ftp_data_close(env)) {
    err = ftp_perror(env);
  } else {
    err = ftp_active_printf(env, "226 Transfer completed\r\n");
  }

  ftp_free_owned_buffers(buffers, buffer_owned, IO_AIO_READ_QUEUE_DEPTH);
  kstuff_autopause_active_end();
  return err;
}

static int
ftp_cmd_STOR_binary_aio(ftp_env_t *env, int fd, void *readbuf, size_t bufsize,
                        int free_buf, off_t off) {
  void *buffers[IO_AIO_WRITE_QUEUE_DEPTH] = {0};
  int buffer_owned[IO_AIO_WRITE_QUEUE_DEPTH] = {0};
  io_aio_slot_t slots[IO_AIO_WRITE_QUEUE_DEPTH];
  size_t chunk_size = bufsize;
  int slot_idx;
  ssize_t len = 0;
  int err = 0;
  int i;

  memset(slots, 0, sizeof(slots));

  if(io_aio_require() != 0) {
    err = ftp_perror(env);
    ftp_data_close(env);
    close(fd);
    if(free_buf && readbuf) {
      free(readbuf);
    }
    kstuff_autopause_active_end();
    return err;
  }

  if(chunk_size < IO_AIO_CHUNK_SIZE) {
    chunk_size = IO_AIO_CHUNK_SIZE;
  }

  if(readbuf && bufsize >= chunk_size) {
    buffers[0] = readbuf;
    buffer_owned[0] = free_buf;
  } else {
    if(free_buf && readbuf) {
      free(readbuf);
      readbuf = NULL;
      free_buf = 0;
    }
    buffers[0] = malloc(chunk_size);
    buffer_owned[0] = 1;
  }

  if(!buffers[0]) {
    err = ftp_perror(env);
    ftp_data_close(env);
    close(fd);
    kstuff_autopause_active_end();
    return err;
  }

  for(i=1; i<IO_AIO_WRITE_QUEUE_DEPTH; i++) {
    buffers[i] = malloc(chunk_size);
    buffer_owned[i] = 1;
    if(!buffers[i]) {
      err = ftp_perror(env);
      ftp_data_close(env);
      close(fd);
      ftp_free_owned_buffers(buffers, buffer_owned, IO_AIO_WRITE_QUEUE_DEPTH);
      kstuff_autopause_active_end();
      return err;
    }
  }

  for(;;) {
    slot_idx = ftp_aio_find_reusable_slot(slots, IO_AIO_WRITE_QUEUE_DEPTH);
    if(slot_idx < 0) {
      i = io_aio_wait_any(slots, IO_AIO_WRITE_QUEUE_DEPTH);
      if(i < 0) {
        err = ftp_perror(env);
        break;
      }
      if(i == 0) {
        errno = EIO;
        err = ftp_perror(env);
        break;
      }
      continue;
    }

    len = ftp_data_read(env, buffers[slot_idx], chunk_size);
    if(len < 0) {
      err = ftp_data_xfer_error_reply(env);
      break;
    }
    if(len == 0) {
      break;
    }

    if(io_aio_write_submit(&slots[slot_idx], fd, buffers[slot_idx], (size_t)len,
                           off) != 0) {
      err = ftp_perror(env);
      break;
    }
    off += len;
  }

  if(io_aio_drain(slots, IO_AIO_WRITE_QUEUE_DEPTH) != 0 && !err) {
    err = ftp_perror(env);
  }

  if(err) {
    ftp_data_close(env);
    close(fd);
    ftp_free_owned_buffers(buffers, buffer_owned, IO_AIO_WRITE_QUEUE_DEPTH);
    kstuff_autopause_active_end();
    return err;
  }

  if(ftruncate(fd, off)) {
    err = ftp_perror(env);
    ftp_data_close(env);
    close(fd);
    ftp_free_owned_buffers(buffers, buffer_owned, IO_AIO_WRITE_QUEUE_DEPTH);
    kstuff_autopause_active_end();
    return err;
  }

  close(fd);
  if(ftp_data_close(env)) {
    err = ftp_perror(env);
    ftp_free_owned_buffers(buffers, buffer_owned, IO_AIO_WRITE_QUEUE_DEPTH);
    kstuff_autopause_active_end();
    return err;
  }

  ftp_free_owned_buffers(buffers, buffer_owned, IO_AIO_WRITE_QUEUE_DEPTH);
  kstuff_autopause_active_end();
  return ftp_active_printf(env, "226 Data transfer complete\r\n");
}
#endif


/**
 * Retreive data from a given file.
 **/
int
ftp_cmd_RETR(ftp_env_t *env, const char* arg) {
  char path[PATH_MAX];
  int err;
  int fd;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: RETR <PATH>\r\n");
  }

  int precheck = ftp_data_precheck(env);
  if(precheck) {
    return precheck < 0 ? precheck : 0;
  }

  if(ftp_abspath(env, path, sizeof(path), arg)) {
    return ftp_perror(env);
  }
  if((fd=open(path, O_RDONLY, 0)) < 0) {
    return ftp_perror(env);
  }

  if(env->self2elf && self_is_valid(path)) {
    err = ftp_cmd_RETR_self2elf(env, fd);
  } else {
    err = ftp_cmd_RETR_fd(env, fd);
  }

  close(fd);
  return err;
}

typedef enum {
  FTP_CASE_LOWER,
  FTP_CASE_UPPER,
} ftp_case_mode_t;

typedef struct {
  char *name;
  char *mapped;
} ftp_case_name_t;

typedef struct {
  ftp_case_name_t *items;
  size_t count;
  size_t cap;
} ftp_case_name_list_t;

static int
ftp_case_convert_name(const char *name, ftp_case_mode_t mode,
                      char *mapped, size_t mapped_size,
                      int *changed_out) {
  size_t len;
  int changed = 0;

  if(!name || !mapped || mapped_size == 0) {
    errno = EINVAL;
    return -1;
  }

  len = strlen(name);
  if(len >= mapped_size) {
    errno = ENAMETOOLONG;
    return -1;
  }

  for(size_t i=0; i<len; i++) {
    unsigned char c = (unsigned char)name[i];
    int out = mode == FTP_CASE_LOWER ? tolower(c) : toupper(c);
    mapped[i] = (char)out;
    if(mapped[i] != name[i]) {
      changed = 1;
    }
  }
  mapped[len] = '\0';

  if(changed_out) {
    *changed_out = changed;
  }
  return 0;
}

static void
ftp_case_name_list_free(ftp_case_name_list_t *list) {
  if(!list) {
    return;
  }

  for(size_t i=0; i<list->count; i++) {
    free(list->items[i].name);
    free(list->items[i].mapped);
  }
  free(list->items);
  list->items = NULL;
  list->count = 0;
  list->cap = 0;
}

static int
ftp_case_name_list_add(ftp_case_name_list_t *list, const char *name,
                       ftp_case_mode_t mode, int map_name) {
  char *name_copy;
  char *mapped = NULL;
  size_t len;

  if(!list || !name) {
    errno = EINVAL;
    return -1;
  }

  if(list->count == list->cap) {
    size_t new_cap = list->cap ? list->cap * 2 : 32;
    ftp_case_name_t *items;

    if(new_cap <= list->cap ||
       new_cap > (SIZE_MAX / sizeof(*list->items))) {
      errno = EOVERFLOW;
      return -1;
    }

    items = realloc(list->items, new_cap * sizeof(*list->items));
    if(!items) {
      return -1;
    }
    list->items = items;
    list->cap = new_cap;
  }

  len = strlen(name);
  name_copy = malloc(len + 1);
  if(!name_copy) {
    return -1;
  }
  memcpy(name_copy, name, len + 1);

  if(map_name) {
    mapped = malloc(len + 1);
    if(!mapped) {
      free(name_copy);
      return -1;
    }
    if(ftp_case_convert_name(name, mode, mapped, len + 1, NULL) != 0) {
      free(name_copy);
      free(mapped);
      return -1;
    }
  }

  list->items[list->count].name = name_copy;
  list->items[list->count].mapped = mapped;
  list->count++;
  return 0;
}

static int
ftp_case_name_cmp(const void *lhs, const void *rhs) {
  const ftp_case_name_t *a = (const ftp_case_name_t *)lhs;
  const ftp_case_name_t *b = (const ftp_case_name_t *)rhs;

  return strcmp(a->mapped, b->mapped);
}

static int
ftp_case_read_dir_names(const char *path, ftp_case_mode_t mode,
                        int map_names, ftp_case_name_list_t *list) {
  DIR *dir;
  struct dirent *ent;
  int saved_errno = 0;
  int rc = 0;

  if(!path || !list) {
    errno = EINVAL;
    return -1;
  }

  memset(list, 0, sizeof(*list));
  dir = opendir(path);
  if(!dir) {
    return -1;
  }

  for(;;) {
    if(ftp_server_bg_op_cancelled()) {
      saved_errno = FTP_BG_OP_CANCELLED_ERR;
      rc = -1;
      break;
    }

    int next = ftp_dir_next_entry(dir, &ent);
    if(next <= 0) {
      if(next < 0) {
        saved_errno = errno;
        rc = -1;
      }
      break;
    }

    if(ftp_case_name_list_add(list, ent->d_name, mode, map_names) != 0) {
      saved_errno = errno;
      rc = -1;
      break;
    }
  }

  if(closedir(dir) != 0 && saved_errno == 0) {
    saved_errno = errno;
    rc = -1;
  }

  if(rc != 0) {
    ftp_case_name_list_free(list);
    errno = saved_errno;
    return -1;
  }

  return 0;
}

static int
ftp_case_build_target_path(const char *path, ftp_case_mode_t mode,
                           char *target, size_t target_size,
                           int *changed_out) {
  const char *slash;
  const char *name;
  char mapped[PATH_MAX];
  int changed = 0;
  int n;

  if(!path || !target || target_size == 0) {
    errno = EINVAL;
    return -1;
  }

  if(path[0] == '/' && path[1] == '\0') {
    if(target_size < 2) {
      errno = ENAMETOOLONG;
      return -1;
    }
    target[0] = '/';
    target[1] = '\0';
    if(changed_out) {
      *changed_out = 0;
    }
    return 0;
  }

  slash = strrchr(path, '/');
  if(!slash || !slash[1]) {
    errno = EINVAL;
    return -1;
  }
  name = slash + 1;

  if(ftp_case_convert_name(name, mode, mapped, sizeof(mapped),
                           &changed) != 0) {
    return -1;
  }

  if(slash == path) {
    n = snprintf(target, target_size, "/%s", mapped);
  } else {
    n = snprintf(target, target_size, "%.*s/%s",
                 (int)(slash - path), path, mapped);
  }

  if(n < 0 || (size_t)n >= target_size) {
    errno = ENAMETOOLONG;
    return -1;
  }

  if(changed_out) {
    *changed_out = changed;
  }
  return 0;
}

static int
ftp_case_same_file(const struct stat *a, const struct stat *b) {
  return a && b && a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static int
ftp_case_check_exact_sibling(const char *path, const char *target) {
  const char *path_name;
  const char *target_name;
  char parent[PATH_MAX];
  size_t parent_len;
  DIR *dir;
  struct dirent *ent;
  int found_path = 0;
  int found_target = 0;
  int rc = 0;

  path_name = strrchr(path, '/');
  target_name = strrchr(target, '/');
  if(!path_name || !target_name) {
    errno = EINVAL;
    return -1;
  }
  path_name++;
  target_name++;

  parent_len = (size_t)((path_name - 1) - path);
  if(parent_len == 0) {
    parent_len = 1;
  }
  if(parent_len >= sizeof(parent)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  memcpy(parent, path, parent_len);
  parent[parent_len] = '\0';

  dir = opendir(parent);
  if(!dir) {
    return -1;
  }

  for(;;) {
    int next = ftp_dir_next_entry(dir, &ent);
    if(next <= 0) {
      if(next < 0) {
        rc = -1;
      }
      break;
    }
    if(strcmp(ent->d_name, path_name) == 0) {
      found_path = 1;
    }
    if(strcmp(ent->d_name, target_name) == 0) {
      found_target = 1;
    }
    if(found_path && found_target) {
      break;
    }
  }

  if(closedir(dir) != 0 && rc == 0) {
    rc = -1;
  }
  if(rc != 0) {
    return -1;
  }

  if(found_path && found_target) {
    errno = EEXIST;
    return -1;
  }
  return 0;
}

static int
ftp_case_check_target_conflict(const char *path, const struct stat *st,
                               ftp_case_mode_t mode) {
  char target[PATH_MAX];
  struct stat target_st;
  int changed = 0;

  if(ftp_case_build_target_path(path, mode, target, sizeof(target),
                                &changed) != 0) {
    return -1;
  }
  if(!changed) {
    return 0;
  }

  if(lstat(target, &target_st) == 0) {
    if(ftp_case_same_file(st, &target_st)) {
      return ftp_case_check_exact_sibling(path, target);
    }
    errno = EEXIST;
    return -1;
  }
  if(errno != ENOENT) {
    return -1;
  }

  return 0;
}

static int
ftp_case_make_temp_path(const char *path, char *tmp_path,
                        size_t tmp_path_size) {
  const char *slash;
  struct stat tmp_st;
  int n;

  if(!path || !tmp_path || tmp_path_size == 0) {
    errno = EINVAL;
    return -1;
  }

  slash = strrchr(path, '/');
  if(!slash) {
    errno = EINVAL;
    return -1;
  }

  for(unsigned i=0; i<100; i++) {
    if(slash == path) {
      n = snprintf(tmp_path, tmp_path_size,
                   "/.ftpsrv-case-%ld-%u", (long)getpid(), i);
    } else {
      n = snprintf(tmp_path, tmp_path_size,
                   "%.*s/.ftpsrv-case-%ld-%u",
                   (int)(slash - path), path, (long)getpid(), i);
    }
    if(n < 0 || (size_t)n >= tmp_path_size) {
      errno = ENAMETOOLONG;
      return -1;
    }
    if(lstat(tmp_path, &tmp_st) != 0) {
      if(errno == ENOENT) {
        return 0;
      }
      return -1;
    }
  }

  errno = EEXIST;
  return -1;
}

static int
ftp_case_rename_path(const char *path, const struct stat *st,
                     ftp_case_mode_t mode) {
  char target[PATH_MAX];
  char tmp_path[PATH_MAX];
  struct stat target_st;
  int changed = 0;
  int same_target = 0;

  if(ftp_server_bg_op_cancelled()) {
    errno = FTP_BG_OP_CANCELLED_ERR;
    return -1;
  }

  if(ftp_case_build_target_path(path, mode, target, sizeof(target),
                                &changed) != 0) {
    return -1;
  }
  if(!changed) {
    return 0;
  }

  if(lstat(target, &target_st) == 0) {
    same_target = ftp_case_same_file(st, &target_st);
    if(!same_target) {
      errno = EEXIST;
      return -1;
    }
  } else if(errno != ENOENT) {
    return -1;
  }

  if(!same_target) {
    return rename(path, target);
  }

  if(ftp_case_make_temp_path(path, tmp_path, sizeof(tmp_path)) != 0) {
    return -1;
  }
  if(rename(path, tmp_path) != 0) {
    return -1;
  }
  if(rename(tmp_path, target) != 0) {
    int saved_errno = errno;
    (void)rename(tmp_path, path);
    errno = saved_errno;
    return -1;
  }

  return 0;
}

static int
ftp_case_check_name_collisions(ftp_case_name_list_t *list) {
  if(!list) {
    errno = EINVAL;
    return -1;
  }

  if(list->count > 1) {
    qsort(list->items, list->count, sizeof(*list->items),
          ftp_case_name_cmp);
  }
  for(size_t i=1; i<list->count; i++) {
    if(strcmp(list->items[i - 1].mapped, list->items[i].mapped) == 0) {
      errno = EEXIST;
      return -1;
    }
  }

  return 0;
}

static int
ftp_case_walk_dir(const char *path, ftp_case_mode_t mode, int apply) {
  ftp_case_name_list_t list;
  struct stat st;

  if(ftp_case_read_dir_names(path, mode, !apply, &list) != 0) {
    return -1;
  }

  if(!apply && ftp_case_check_name_collisions(&list) != 0) {
    ftp_case_name_list_free(&list);
    return -1;
  }

  for(size_t i=0; i<list.count; i++) {
    char child[PATH_MAX];

    if(ftp_server_bg_op_cancelled()) {
      ftp_case_name_list_free(&list);
      errno = FTP_BG_OP_CANCELLED_ERR;
      return -1;
    }

    if(ftp_join_path(child, sizeof(child), path, list.items[i].name) != 0) {
      ftp_case_name_list_free(&list);
      return -1;
    }
    if(lstat(child, &st) != 0) {
      ftp_case_name_list_free(&list);
      return -1;
    }

    if(!apply && ftp_case_check_target_conflict(child, &st, mode) != 0) {
      ftp_case_name_list_free(&list);
      return -1;
    }
    if(S_ISDIR(st.st_mode) && ftp_case_walk_dir(child, mode, apply) != 0) {
      ftp_case_name_list_free(&list);
      return -1;
    }
    if(apply && ftp_case_rename_path(child, &st, mode) != 0) {
      ftp_case_name_list_free(&list);
      return -1;
    }
  }

  ftp_case_name_list_free(&list);
  return 0;
}

static int
ftp_case_process_path(const char *path, const struct stat *st,
                      ftp_case_mode_t mode, int apply) {
  if(!apply && ftp_case_check_target_conflict(path, st, mode) != 0) {
    return -1;
  }

  if(S_ISDIR(st->st_mode) && ftp_case_walk_dir(path, mode, apply) != 0) {
    return -1;
  }

  return apply ? ftp_case_rename_path(path, st, mode) : 0;
}

static void
ftp_case_update_cwd(ftp_env_t *env, const char *root_path,
                    ftp_case_mode_t mode) {
  const char *tail;
  const char *slash;
  char updated[PATH_MAX];
  char mapped[PATH_MAX];
  size_t prefix_len;
  size_t root_len;
  size_t mapped_len;

  if(!env || !root_path) {
    return;
  }

  root_len = strlen(root_path);
  if(root_path[0] == '/' && root_path[1] == '\0') {
    prefix_len = 1;
    tail = env->cwd + 1;
    updated[0] = '/';
    updated[1] = '\0';
  } else {
    if(strncmp(env->cwd, root_path, root_len) != 0 ||
       (env->cwd[root_len] != '\0' && env->cwd[root_len] != '/')) {
      return;
    }

    slash = strrchr(root_path, '/');
    if(!slash) {
      return;
    }
    prefix_len = slash == root_path ? 1 : (size_t)(slash - root_path + 1);
    if(prefix_len >= sizeof(updated)) {
      return;
    }
    memcpy(updated, root_path, prefix_len);
    updated[prefix_len] = '\0';
    tail = env->cwd + prefix_len;
  }

  if(ftp_case_convert_name(tail, mode, mapped, sizeof(mapped), NULL) != 0) {
    return;
  }
  mapped_len = strlen(mapped);
  if(prefix_len + mapped_len < sizeof(updated)) {
    memcpy(updated + prefix_len, mapped, mapped_len + 1);
    snprintf(env->cwd, sizeof(env->cwd), "%s", updated);
  }
}

static int
ftp_cmd_case(ftp_env_t *env, const char *arg, ftp_case_mode_t mode) {
  char argbuf[PATH_MAX + 1];
  char pathbuf[PATH_MAX];
  struct stat st;
  const char *path_arg;
  int rc = -1;
  int err = 0;
  int is_dir = 0;

  path_arg = ftp_copy_path_arg(arg, argbuf, sizeof(argbuf));
  if(!path_arg) {
    return ftp_active_printf(env, "501 Usage: %s <PATH>\r\n",
                             mode == FTP_CASE_LOWER ? "LOWER" : "UPPER");
  }

  ftp_copy_thread_cleanup(env);
  ftp_delete_thread_cleanup(env);
  if(!ftp_server_bg_op_acquire()) {
    return ftp_active_printf(env,
                             "450 Background file operation in progress\r\n");
  }

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), path_arg) != 0) {
    err = errno;
    goto done;
  }
  if(lstat(pathbuf, &st) != 0) {
    err = errno;
    goto done;
  }
  if(!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
    ftp_server_bg_op_release();
    return ftp_active_printf(env, "550 Unsupported file type\r\n");
  }
  is_dir = S_ISDIR(st.st_mode);

  if(ftp_case_process_path(pathbuf, &st, mode, 0) != 0) {
    err = errno;
    goto done;
  }
  if(ftp_case_process_path(pathbuf, &st, mode, 1) != 0) {
    err = errno;
    goto done;
  }

  rc = 0;

done:
  ftp_server_bg_op_release();

  if(rc != 0) {
    if(err == FTP_BG_OP_CANCELLED_ERR) {
      return ftp_active_printf(env, "426 Operation cancelled\r\n");
    }
    errno = err;
    return ftp_perror(env);
  }

  if(is_dir) {
    ftp_case_update_cwd(env, pathbuf, mode);
  }

  return ftp_active_printf(env, "250 Path renamed recursively\r\n");
}

int
ftp_cmd_LOWER(ftp_env_t *env, const char* arg) {
  return ftp_cmd_case(env, arg, FTP_CASE_LOWER);
}

int
ftp_cmd_UPPER(ftp_env_t *env, const char* arg) {
  return ftp_cmd_case(env, arg, FTP_CASE_UPPER);
}


/**
 * Remove a directory.
 **/
int
ftp_cmd_RMD(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: RMD <DIRNAME>\r\n");
  }

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }
  if(rmdir(pathbuf)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "250 Directory deleted\r\n");
}

/**
 * Remove a directory and its contents.
 **/
int
ftp_cmd_RMDA(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat st;
  ftp_delete_task_t *task;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: RMDA <DIRNAME>\r\n");
  }

  ftp_copy_thread_cleanup(env);
  ftp_delete_thread_cleanup(env);
  if(ftp_server_bg_op_busy()) {
    return ftp_active_printf(env, "450 Background file operation in progress\r\n");
  }

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_active_printf(env, "550 %s: %s.\r\n", arg, strerror(errno));
  }

  if(stat(pathbuf, &st)) {
    return ftp_active_printf(env, "550 %s: %s.\r\n", arg, strerror(errno));
  }

  if(S_ISREG(st.st_mode)) {
    return ftp_active_printf(env, "550 %s: Is a file.\r\n", arg);
  }
  if(!S_ISDIR(st.st_mode)) {
    return ftp_active_printf(env, "550 %s: Not a directory.\r\n", arg);
  }

  task = ftp_delete_create_task(env, pathbuf);
  if(!task) {
    return ftp_perror(env);
  }

  return ftp_delete_start_task(env, task);
}


/**
 * Specify a path that will later be renamed by the RNTO command.
 **/
int
ftp_cmd_RNFR(ftp_env_t *env, const char* arg) {
  struct stat st;

  env->rename_ready = 0;
  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: RNFR <PATH>\r\n");
  }

  if(ftp_abspath(env, env->rename_path, sizeof(env->rename_path), arg)) {
    return ftp_perror(env);
  }
  if(lstat(env->rename_path, &st)) {
    return ftp_perror(env);
  }

  env->rename_ready = 1;
  return ftp_active_printf(env, "350 Awaiting new name\r\n");
}


/**
 * Rename a path previously specified by the RNFR command.
 **/
int
ftp_cmd_RNTO(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat st;
  int same_device = 0;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: RNTO <PATH>\r\n");
  }

  if(!env->rename_ready) {
    return ftp_active_printf(env, "503 Bad sequence of commands\r\n");
  }

  ftp_copy_thread_cleanup(env);
  ftp_delete_thread_cleanup(env);
  if(ftp_server_bg_op_busy()) {
    return ftp_active_printf(env,
                             "450 Background file operation in progress\r\n");
  }

  env->rename_ready = 0;
  if(lstat(env->rename_path, &st)) {
    return ftp_perror(env);
  }

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }

  if(ftp_move_same_device(env->rename_path, &st, pathbuf, &same_device)) {
    return ftp_perror(env);
  }
  if(same_device) {
    if(rename(env->rename_path, pathbuf) == 0) {
      return ftp_active_printf(env, "250 Path renamed\r\n");
    }
    if(errno != EXDEV) {
      return ftp_perror(env);
    }
  }

  return ftp_move_start_background(env, FTP_BG_MOVE,
                                   env->rename_path, pathbuf, &st, 0);
}

/**
 * Specify a source file to be copied by the CPTO command.
 **/
static void ftp_copy_thread_cleanup(ftp_env_t *env);
static void *ftp_copy_thread(void *arg);

int
ftp_cmd_CPFR(ftp_env_t *env, const char* arg) {
  struct stat st;
  char argbuf[PATH_MAX + 1];
  const char *path_arg = ftp_copy_path_arg(arg, argbuf, sizeof(argbuf));

  ftp_copy_thread_cleanup(env);
  pthread_mutex_lock(&env->copy_mutex);
  int busy = env->copy_in_progress;
  pthread_mutex_unlock(&env->copy_mutex);
  if(busy) {
    return ftp_active_printf(env, "450 Copy in progress\r\n");
  }

  env->copy_ready = 0;
  if(!path_arg) {
    return ftp_active_printf(env, "501 Usage: CPFR <PATH>\r\n");
  }

  if(ftp_abspath(env, env->copy_path, sizeof(env->copy_path), path_arg)) {
    return ftp_perror(env);
  }
  if(lstat(env->copy_path, &st)) {
    return ftp_perror(env);
  }
  if(!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
    return ftp_active_printf(env, "550 Unsupported file type\r\n");
  }

  env->copy_ready = 1;
  return ftp_active_printf(env, "350 Awaiting CPTO\r\n");
}

int
ftp_cmd_MOVE(ftp_env_t *env, const char* arg) {
  char src_arg[PATH_MAX + 1];
  char dst_arg[PATH_MAX + 1];
  char src_path[PATH_MAX];
  char dst_path[PATH_MAX];
  struct stat src_st;
  int same_device = 0;

  if(ftp_split_copy_args(arg, src_arg, sizeof(src_arg),
                         dst_arg, sizeof(dst_arg))) {
    return ftp_active_printf(env, "501 Usage: MOVE <FROM> <TO>\r\n");
  }

  ftp_copy_thread_cleanup(env);
  ftp_delete_thread_cleanup(env);
  if(ftp_server_bg_op_busy()) {
    return ftp_active_printf(env,
                             "450 Background file operation in progress\r\n");
  }

  if(ftp_abspath(env, src_path, sizeof(src_path), src_arg)) {
    return ftp_perror(env);
  }
  if(ftp_abspath(env, dst_path, sizeof(dst_path), dst_arg)) {
    return ftp_perror(env);
  }
  if(strcmp(src_path, dst_path) == 0) {
    return ftp_active_printf(env, "553 Source and destination are the same\r\n");
  }
  if(lstat(src_path, &src_st)) {
    return ftp_perror(env);
  }

  if(S_ISDIR(src_st.st_mode)) {
    size_t src_len = strlen(src_path);
    if(strncmp(dst_path, src_path, src_len) == 0 &&
       (dst_path[src_len] == '/' || dst_path[src_len] == '\0')) {
      return ftp_active_printf(env, "553 Cannot move into itself\r\n");
    }
  }

  if(ftp_move_same_device(src_path, &src_st, dst_path, &same_device)) {
    return ftp_perror(env);
  }

  if(same_device) {
    if(ftp_mkdirs_parent(dst_path)) {
      return ftp_perror(env);
    }
    if(rename(src_path, dst_path) == 0) {
      return ftp_active_printf(env, "250 Path moved\r\n");
    }
    if(errno != EXDEV) {
      return ftp_perror(env);
    }
  }

  return ftp_move_start_background(env, FTP_BG_MOVE,
                                   src_path, dst_path, &src_st, 1);
}

/**
 * Split COPY arguments into source and destination paths.
 **/
static int
ftp_split_copy_args(const char *arg, char *src, size_t src_sz,
                    char *dst, size_t dst_sz) {
  if(!arg || !src || !dst || src_sz < 2 || dst_sz < 2) {
    return -1;
  }

  const char *p = arg;
  p += strspn(p, " ");
  if(!*p) {
    return -1;
  }

  const char *sep = strchr(p, ' ');
  if(!sep) {
    return -1;
  }

  size_t src_len = (size_t)(sep - p);
  if(src_len == 0 || src_len >= src_sz) {
    return -1;
  }
  memcpy(src, p, src_len);
  src[src_len] = '\0';

  sep += strspn(sep, " ");
  if(!*sep) {
    return -1;
  }

  const char *end = sep + strlen(sep);
  while(end > sep && end[-1] == ' ') {
    end--;
  }
  size_t dst_len = (size_t)(end - sep);
  if(dst_len == 0 || dst_len >= dst_sz) {
    return -1;
  }
  memcpy(dst, sep, dst_len);
  dst[dst_len] = '\0';

  return 0;
}

static int
ftp_path_parent_dir(const char *path, char *parent, size_t parent_size) {
  char *slash;
  size_t len;

  if(!path || !parent || parent_size == 0) {
    errno = EINVAL;
    return -1;
  }

  len = strlen(path);
  if(len >= parent_size) {
    errno = ENAMETOOLONG;
    return -1;
  }
  memcpy(parent, path, len + 1);

  slash = strrchr(parent, '/');
  if(!slash) {
    errno = EINVAL;
    return -1;
  }
  if(slash == parent) {
    parent[1] = '\0';
  } else {
    *slash = '\0';
  }

  return 0;
}

static int
ftp_path_parent_must_exist(const char *path) {
  char parent[PATH_MAX];
  struct stat st;

  if(ftp_path_parent_dir(path, parent, sizeof(parent)) != 0) {
    return -1;
  }
  if(stat(parent, &st) != 0) {
    return -1;
  }
  if(!S_ISDIR(st.st_mode)) {
    errno = ENOTDIR;
    return -1;
  }

  return 0;
}

static int
ftp_make_temp_path(const char *path, char *tmp_path, size_t tmp_path_size) {
  char parent[PATH_MAX];
  int n;

  if(ftp_path_parent_dir(path, parent, sizeof(parent)) != 0) {
    return -1;
  }

  n = snprintf(tmp_path, tmp_path_size, "%s/.ftpsrv-tmp-XXXXXX", parent);
  if(n < 0 || (size_t)n >= tmp_path_size) {
    errno = ENAMETOOLONG;
    return -1;
  }

  return 0;
}

static int
ftp_dir_make_temp_path(const char *dir_path, const char *suffix,
                       char *tmp_path, size_t tmp_path_size) {
  int n;

  if(!dir_path || !suffix || !tmp_path || tmp_path_size == 0) {
    errno = EINVAL;
    return -1;
  }

  n = snprintf(tmp_path, tmp_path_size, "%s/%s", dir_path, suffix);
  if(n < 0 || (size_t)n >= tmp_path_size) {
    errno = ENAMETOOLONG;
    return -1;
  }

  return 0;
}

static int
ftp_probe_write_in_dir(const char *dir_path) {
  char probe_path[PATH_MAX];
  int fd = -1;
  int saved_errno = 0;
  static const char probe_byte = '\0';

  if(ftp_dir_make_temp_path(dir_path, ".ftpsrv-probe-XXXXXX",
                            probe_path, sizeof(probe_path)) != 0) {
    return -1;
  }

  fd = mkstemp(probe_path);
  if(fd < 0) {
    return -1;
  }

  if(io_nwrite(fd, &probe_byte, sizeof(probe_byte)) != 0) {
    saved_errno = errno;
    close(fd);
    unlink(probe_path);
    errno = saved_errno;
    return -1;
  }

  if(close(fd) != 0) {
    saved_errno = errno;
    unlink(probe_path);
    errno = saved_errno;
    return -1;
  }

  if(unlink(probe_path) != 0) {
    return -1;
  }

  return 0;
}

static int
ftp_probe_create_dir_and_write(const char *dst_path) {
  char parent[PATH_MAX];
  char probe_dir[PATH_MAX];
  int saved_errno = 0;

  if(ftp_path_parent_dir(dst_path, parent, sizeof(parent)) != 0) {
    return -1;
  }
  if(ftp_dir_make_temp_path(parent, ".ftpsrv-probe-dir-XXXXXX",
                            probe_dir, sizeof(probe_dir)) != 0) {
    return -1;
  }

  if(!mkdtemp(probe_dir)) {
    return -1;
  }

  if(ftp_probe_write_in_dir(probe_dir) != 0) {
    saved_errno = errno;
    rmdir(probe_dir);
    errno = saved_errno;
    return -1;
  }

  if(rmdir(probe_dir) != 0) {
    return -1;
  }

  return 0;
}

static int
ftp_copy_probe_destination(const char *dst_path, int target_is_dir,
                           int create_parent_dirs) {
  char parent[PATH_MAX];
  struct stat st;

  if(!dst_path) {
    errno = EINVAL;
    return -1;
  }

  if(create_parent_dirs) {
    if(ftp_mkdirs_parent(dst_path) != 0) {
      return -1;
    }
  } else if(ftp_path_parent_must_exist(dst_path) != 0) {
    return -1;
  }

  if(target_is_dir) {
    if(lstat(dst_path, &st) == 0) {
      if(!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
      }
      return ftp_probe_write_in_dir(dst_path);
    }
    if(errno != ENOENT) {
      return -1;
    }
    return ftp_probe_create_dir_and_write(dst_path);
  }

  if(ftp_path_parent_dir(dst_path, parent, sizeof(parent)) != 0) {
    return -1;
  }

  return ftp_probe_write_in_dir(parent);
}

static int
ftp_path_parent_stat(const char *path, struct stat *st) {
  char parent[PATH_MAX];

  if(!path || !st) {
    errno = EINVAL;
    return -1;
  }

  if(ftp_path_parent_dir(path, parent, sizeof(parent)) != 0) {
    return -1;
  }

  while(1) {
    char *slash;

    if(stat(parent, st) == 0) {
      return 0;
    }
    if(errno != ENOENT) {
      return -1;
    }
    if(strcmp(parent, "/") == 0) {
      return -1;
    }

    slash = strrchr(parent, '/');
    if(!slash) {
      errno = ENOENT;
      return -1;
    }
    if(slash == parent) {
      parent[1] = '\0';
    } else {
      *slash = '\0';
    }
  }
}

static int
ftp_target_statvfs(const char *dst_path, int target_is_dir,
                   struct statvfs *vfs_out) {
  char path[PATH_MAX];

  if(!dst_path || !vfs_out) {
    errno = EINVAL;
    return -1;
  }

  if(target_is_dir) {
    size_t len = strlen(dst_path);

    if(len >= sizeof(path)) {
      errno = ENAMETOOLONG;
      return -1;
    }
    memcpy(path, dst_path, len + 1);
  } else if(ftp_path_parent_dir(dst_path, path, sizeof(path)) != 0) {
    return -1;
  }

  while(1) {
    if(statvfs(path, vfs_out) == 0) {
      return 0;
    }
    if(errno != ENOENT) {
      return -1;
    }
    if(strcmp(path, "/") == 0) {
      return -1;
    }

    if(ftp_path_parent_dir(path, path, sizeof(path)) != 0) {
      return -1;
    }
  }
}

static int
ftp_copy_check_space(const char *dst_path, int target_is_dir,
                     uintmax_t total_bytes) {
  struct statvfs vfs;
  uintmax_t unit;
  uintmax_t avail;
  uintmax_t slack = 0;
  uintmax_t required;

  if(ftp_target_statvfs(dst_path, target_is_dir, &vfs) != 0) {
    return -1;
  }

  unit = vfs.f_frsize ? (uintmax_t)vfs.f_frsize : (uintmax_t)vfs.f_bsize;
  avail = (uintmax_t)vfs.f_bavail * unit;
  if(total_bytes != 0) {
    slack = (total_bytes + 99) / 100;
  }
  required = ftp_saturating_add(total_bytes, slack);
  if(avail < required) {
    errno = ENOSPC;
    return -1;
  }

  return 0;
}

static int
ftp_copy_prepare_total(const char *src_path, const struct stat *src_st,
                       const char *dst_path, int target_is_dir,
                       uintmax_t *total_bytes_out) {
  uintmax_t total_bytes = 0;

  if(!src_path || !src_st || !dst_path || !total_bytes_out) {
    errno = EINVAL;
    return -1;
  }

  if(ftp_copy_total_for_stat(src_path, src_st, &total_bytes) != 0) {
    return -1;
  }
  if(ftp_copy_check_space(dst_path, target_is_dir, total_bytes) != 0) {
    return -1;
  }

  *total_bytes_out = total_bytes;
  return 0;
}

static int
ftp_dir_is_empty(const char *path) {
  DIR *dir;
  int empty = 1;
  int saved_errno = 0;

  dir = opendir(path);
  if(!dir) {
    return -1;
  }

  struct dirent *ent;
  int rc = ftp_dir_next_entry(dir, &ent);
  if(rc < 0) {
    saved_errno = errno;
    empty = -1;
  } else if(rc > 0) {
    empty = 0;
  }

  if(closedir(dir) != 0 && saved_errno == 0 && empty >= 0) {
    saved_errno = errno;
    empty = -1;
  }
  if(saved_errno) {
    errno = saved_errno;
  }

  return empty;
}

static int
ftp_move_same_device(const char *src_path, const struct stat *src_st,
                     const char *dst_path, int *same_device) {
  struct stat st;

  if(!src_path || !src_st || !dst_path || !same_device) {
    errno = EINVAL;
    return -1;
  }

  if(lstat(dst_path, &st) == 0) {
    *same_device = st.st_dev == src_st->st_dev;
    return 0;
  }
  if(errno != ENOENT) {
    return -1;
  }

  if(ftp_path_parent_stat(dst_path, &st) != 0) {
    return -1;
  }

  *same_device = st.st_dev == src_st->st_dev;
  return 0;
}

/**
 * Copy a symlink from src to dst.
 **/
static int
ftp_copy_symlink(const char *src_path, const char *dst_path) {
  char linkbuf[PATH_MAX + 1];
  char tmp_path[PATH_MAX];
  ssize_t len = 0;
  int fd;

  if(ftp_server_bg_op_cancelled()) {
    errno = FTP_BG_OP_CANCELLED_ERR;
    return -1;
  }

  len = readlink(src_path, linkbuf, sizeof(linkbuf) - 1);
  if(len < 0) {
    return -1;
  }
  linkbuf[len] = '\0';

  if(ftp_make_temp_path(dst_path, tmp_path, sizeof(tmp_path)) != 0) {
    return -1;
  }

  fd = mkstemp(tmp_path);
  if(fd < 0) {
    return -1;
  }
  close(fd);
  if(unlink(tmp_path) != 0) {
    return -1;
  }

  if(symlink(linkbuf, tmp_path) != 0) {
    return -1;
  }

  if(ftp_server_bg_op_cancelled()) {
    unlink(tmp_path);
    errno = FTP_BG_OP_CANCELLED_ERR;
    return -1;
  }

  if(rename(tmp_path, dst_path) != 0) {
    int saved_errno = errno;
    unlink(tmp_path);
    errno = saved_errno;
    return -1;
  }

  return 0;
}

typedef enum {
  FTP_COPY_REG,
  FTP_COPY_DIR,
  FTP_COPY_SYMLINK,
} ftp_copy_kind_t;

#define FTP_COPY_NOTIFY_CHECK_BYTES (4 * 1024 * 1024)

typedef struct {
  uintmax_t total_bytes;
  uintmax_t copied_bytes;
  uintmax_t last_notify_bytes;
  uintmax_t next_check_bytes;
  struct timespec last_notify_ts;
  int has_last_notify_ts;
} ftp_copy_progress_t;

typedef struct {
  ftp_env_t *env;
  ftp_bg_op_t op;
  ftp_copy_kind_t kind;
  char src[PATH_MAX];
  char dst[PATH_MAX];
  char src_notify[FTP_NOTIFY_PATH_SIZE];
  char dst_notify[FTP_NOTIFY_PATH_SIZE];
  ftp_copy_progress_t progress;
} ftp_copy_task_t;

static ftp_copy_task_t*
ftp_copy_create_task(ftp_env_t *env, ftp_bg_op_t op, ftp_copy_kind_t kind,
                     const char *src, const char *dst,
                     uintmax_t total_bytes) {
  ftp_copy_task_t *task;

  if(!env || !src || !dst) {
    errno = EINVAL;
    return NULL;
  }

  task = calloc(1, sizeof(*task));
  if(!task) {
    return NULL;
  }

  task->env = env;
  task->op = op;
  task->kind = kind;
  task->progress.total_bytes = total_bytes;
  snprintf(task->src, sizeof(task->src), "%s", src);
  snprintf(task->dst, sizeof(task->dst), "%s", dst);
  ftp_compact_path(src, task->src_notify, sizeof(task->src_notify));
  ftp_compact_path(dst, task->dst_notify, sizeof(task->dst_notify));

  return task;
}

static const char *
ftp_bg_op_name(ftp_bg_op_t op) {
  return op == FTP_BG_MOVE ? "Move" : "Copy";
}

static void
ftp_copy_format_bytes(double bytes, const char *const *units, size_t unit_count,
                      char *out, size_t out_size) {
  size_t unit = 0;
  double value = bytes;

  if(!out || out_size == 0) {
    return;
  }

  if(value < 0.0) {
    value = 0.0;
  }

  while(value >= 1024.0 && unit + 1 < unit_count) {
    value /= 1024.0;
    unit += 1;
  }

  if(unit == 0 || value >= 100.0) {
    snprintf(out, out_size, "%.0f %s", value, units[unit]);
  } else if(value >= 10.0) {
    snprintf(out, out_size, "%.1f %s", value, units[unit]);
  } else {
    snprintf(out, out_size, "%.2f %s", value, units[unit]);
  }
}

static void
ftp_copy_format_size(uintmax_t bytes, char *out, size_t out_size) {
  static const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};

  ftp_copy_format_bytes((double)bytes, units,
                        sizeof(units) / sizeof(units[0]), out, out_size);
}

static void
ftp_copy_format_speed(double bytes_per_sec, char *out, size_t out_size) {
  static const char *units[] = {"B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"};

  ftp_copy_format_bytes(bytes_per_sec, units,
                        sizeof(units) / sizeof(units[0]), out, out_size);
}

static int
ftp_copy_total_for_stat(const char *path, const struct stat *st,
                        uintmax_t *total_out) {
  uintmax_t total = 0;

  if(!path || !st || !total_out) {
    errno = EINVAL;
    return -1;
  }

  if(S_ISREG(st->st_mode) || S_ISLNK(st->st_mode)) {
    total = (uintmax_t)st->st_size;
  } else if(S_ISDIR(st->st_mode)) {
    if(ftp_dir_size(path, &total)) {
      return -1;
    }
  } else {
    errno = EINVAL;
    return -1;
  }

  *total_out = total;
  return 0;
}

static unsigned
ftp_copy_progress_percent(const ftp_copy_task_t *task) {
  if(!task) {
    return 0;
  }

  if(task->progress.total_bytes == 0) {
    return 100;
  }

  uintmax_t copied = task->progress.copied_bytes;
  if(copied > task->progress.total_bytes) {
    copied = task->progress.total_bytes;
  }

  return (unsigned)((copied * 100) / task->progress.total_bytes);
}

static void
ftp_copy_notify_start(ftp_copy_task_t *task) {
  struct timespec now;

  if(!task) {
    return;
  }

  ftp_now(&now);
  task->progress.last_notify_ts = now;
  task->progress.has_last_notify_ts = 1;
  task->progress.last_notify_bytes = task->progress.copied_bytes;
  task->progress.next_check_bytes =
    ftp_saturating_add(task->progress.copied_bytes,
                       FTP_COPY_NOTIFY_CHECK_BYTES);
  notify("%s started: %s -> %s",
         ftp_bg_op_name(task->op), task->src_notify, task->dst_notify);
}

static void
ftp_copy_notify_progress(ftp_copy_task_t *task) {
  struct timespec now;
  double elapsed;
  double bytes_per_sec;
  uintmax_t bytes_delta;
  uintmax_t copied;
  uintmax_t total;
  char copied_str[32];
  char total_str[32];
  char speed[32];

  if(!task) {
    return;
  }

  ftp_now(&now);
  if(!task->progress.has_last_notify_ts) {
    task->progress.last_notify_ts = now;
    task->progress.has_last_notify_ts = 1;
    task->progress.last_notify_bytes = task->progress.copied_bytes;
    task->progress.next_check_bytes =
      ftp_saturating_add(task->progress.copied_bytes,
                         FTP_COPY_NOTIFY_CHECK_BYTES);
    return;
  }

  elapsed = ftp_elapsed_seconds(&task->progress.last_notify_ts, &now);
  if(elapsed < 10.0) {
    task->progress.next_check_bytes =
      ftp_saturating_add(task->progress.copied_bytes,
                         FTP_COPY_NOTIFY_CHECK_BYTES);
    return;
  }

  bytes_delta = task->progress.copied_bytes - task->progress.last_notify_bytes;
  bytes_per_sec = elapsed > 0.0 ? (double)bytes_delta / elapsed : 0.0;
  copied = task->progress.copied_bytes;
  total = task->progress.total_bytes;
  if(total > 0 && copied > total) {
    copied = total;
  }

  ftp_copy_format_size(copied, copied_str, sizeof(copied_str));
  ftp_copy_format_size(total, total_str, sizeof(total_str));
  ftp_copy_format_speed(bytes_per_sec, speed, sizeof(speed));

  task->progress.last_notify_ts = now;
  task->progress.last_notify_bytes = task->progress.copied_bytes;
  task->progress.next_check_bytes =
    ftp_saturating_add(task->progress.copied_bytes,
                       FTP_COPY_NOTIFY_CHECK_BYTES);
  notify("%s %u%% (%s / %s) - %s",
         ftp_bg_op_name(task->op),
         ftp_copy_progress_percent(task), copied_str, total_str, speed);
}

static void
ftp_copy_progress_add(ftp_copy_task_t *task, uintmax_t amount) {
  if(!task || amount == 0) {
    return;
  }

  task->progress.copied_bytes =
    ftp_saturating_add(task->progress.copied_bytes, amount);

  if(task->progress.copied_bytes < task->progress.next_check_bytes) {
    return;
  }

  ftp_copy_notify_progress(task);
}

static void
ftp_copy_notify_result(const ftp_copy_task_t *task, int rc, int err) {
  unsigned pct = rc ? ftp_copy_progress_percent(task) : 100;

  if(rc) {
    if(err == 0) {
      err = EIO;
    }
    if(err == FTP_BG_OP_CANCELLED_ERR) {
      notify("%s stopped %u%%: %s -> %s",
             ftp_bg_op_name(task->op), pct,
             task->src_notify, task->dst_notify);
      return;
    }
    notify("%s failed %u%%: %s -> %s (%s)",
           ftp_bg_op_name(task->op), pct,
           task->src_notify, task->dst_notify, strerror(err));
    return;
  }

  notify("%s finished %u%%: %s -> %s (OK)",
         ftp_bg_op_name(task->op), pct, task->src_notify, task->dst_notify);
}

static int
ftp_copy_start_task(ftp_env_t *env, ftp_copy_task_t *task) {
  int thread_rc;

  if(!ftp_server_bg_op_acquire()) {
    free(task);
    return ftp_active_printf(env, "450 Background file operation in progress\r\n");
  }

  pthread_mutex_lock(&env->copy_mutex);
  env->copy_in_progress = 1;
  env->copy_thread_valid = 1;
  pthread_mutex_unlock(&env->copy_mutex);

  thread_rc = pthread_create(&env->copy_thread, NULL, ftp_copy_thread, task);
  if(thread_rc != 0) {
    pthread_mutex_lock(&env->copy_mutex);
    env->copy_in_progress = 0;
    env->copy_thread_valid = 0;
    pthread_mutex_unlock(&env->copy_mutex);
    ftp_server_bg_op_release();
    free(task);
    errno = thread_rc;
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "250 %s started in background\r\n",
                           ftp_bg_op_name(task->op));
}

static int
ftp_move_remove_source(ftp_copy_task_t *task) {
  if(!task || task->op != FTP_BG_MOVE) {
    return 0;
  }
  if(ftp_server_bg_op_cancelled()) {
    errno = FTP_BG_OP_CANCELLED_ERR;
    return -1;
  }

  switch(task->kind) {
    case FTP_COPY_REG:
      if(unlink(task->src) != 0) {
        return -1;
      }
      return 0;
    case FTP_COPY_SYMLINK:
      if(unlink(task->src) != 0) {
        return -1;
      }
      return 0;
    case FTP_COPY_DIR:
      {
        int err = 0;

        if(ftp_rmda_delete_dir(task->src, &err, NULL) != 0) {
          if(err) {
            errno = err;
          }
          return -1;
        }
      }
      return 0;
  }

  errno = EINVAL;
  return -1;
}

static int
ftp_move_start_background(ftp_env_t *env, ftp_bg_op_t op,
                          const char *src_path, const char *dst_path,
                          const struct stat *src_st,
                          int create_parent_dirs) {
  ftp_copy_task_t *task;
  struct stat st;
  uintmax_t total_bytes;

  if(!env || !src_path || !dst_path || !src_st) {
    errno = EINVAL;
    return -1;
  }

  ftp_copy_thread_cleanup(env);
  ftp_delete_thread_cleanup(env);
  if(ftp_server_bg_op_busy()) {
    return ftp_active_printf(env,
                             "450 Background file operation in progress\r\n");
  }

  if(S_ISREG(src_st->st_mode)) {
    if(lstat(dst_path, &st) == 0) {
      if(S_ISDIR(st.st_mode)) {
        return ftp_active_printf(env, "550 Target is a directory\r\n");
      }
    } else if(errno != ENOENT) {
      return ftp_perror(env);
    }
    if(ftp_copy_probe_destination(dst_path, 0, create_parent_dirs) != 0) {
      return ftp_perror(env);
    }
    if(ftp_copy_prepare_total(src_path, src_st, dst_path, 0,
                              &total_bytes) != 0) {
      return ftp_perror(env);
    }

    task = ftp_copy_create_task(env, op, FTP_COPY_REG,
                                src_path, dst_path, total_bytes);
    if(!task) {
      return ftp_perror(env);
    }
    return ftp_copy_start_task(env, task);
  }

  if(S_ISDIR(src_st->st_mode)) {
    size_t src_len = strlen(src_path);

    if(strncmp(dst_path, src_path, src_len) == 0 &&
       (dst_path[src_len] == '/' || dst_path[src_len] == '\0')) {
      return ftp_active_printf(env, "553 Cannot move into itself\r\n");
    }
    if(lstat(dst_path, &st) == 0) {
      int empty;

      if(!S_ISDIR(st.st_mode)) {
        return ftp_active_printf(env, "550 Not a directory\r\n");
      }
      empty = ftp_dir_is_empty(dst_path);
      if(empty < 0) {
        return ftp_perror(env);
      }
      if(!empty) {
        return ftp_active_printf(env, "550 Target already exists\r\n");
      }
    } else if(errno != ENOENT) {
      return ftp_perror(env);
    }
    if(ftp_copy_probe_destination(dst_path, 1, create_parent_dirs) != 0) {
      return ftp_perror(env);
    }
    if(ftp_copy_prepare_total(src_path, src_st, dst_path, 1,
                              &total_bytes) != 0) {
      return ftp_perror(env);
    }

    task = ftp_copy_create_task(env, op, FTP_COPY_DIR,
                                src_path, dst_path, total_bytes);
    if(!task) {
      return ftp_perror(env);
    }
    return ftp_copy_start_task(env, task);
  }

  if(S_ISLNK(src_st->st_mode)) {
    if(lstat(dst_path, &st) == 0) {
      if(S_ISDIR(st.st_mode)) {
        return ftp_active_printf(env, "550 Target is a directory\r\n");
      }
    } else if(errno != ENOENT) {
      return ftp_perror(env);
    }
    if(ftp_copy_probe_destination(dst_path, 0, create_parent_dirs) != 0) {
      return ftp_perror(env);
    }
    if(ftp_copy_prepare_total(src_path, src_st, dst_path, 0,
                              &total_bytes) != 0) {
      return ftp_perror(env);
    }

    task = ftp_copy_create_task(env, op, FTP_COPY_SYMLINK,
                                src_path, dst_path, total_bytes);
    if(!task) {
      return ftp_perror(env);
    }
    return ftp_copy_start_task(env, task);
  }

  return ftp_active_printf(env, "550 Unsupported file type\r\n");
}

/**
 * Copy file metadata (mode, owner, group, timestamps) from src to dst.
 **/
static int
ftp_copy_metadata(const char *src_path, const char *dst_path) {
  struct stat st;
  if(stat(src_path, &st)) {
    return -1;
  }
  if(chmod(dst_path, st.st_mode & 07777)) {
    if(errno != EPERM) {
      return -1;
    }
  }
  if(chown(dst_path, st.st_uid, st.st_gid)) {
    if(errno != EPERM) {
      return -1;
    }
  }
  struct utimbuf times;
  times.actime = st.st_atime;
  times.modtime = st.st_mtime;
  if(utime(dst_path, &times)) {
    if(errno != EPERM) {
      return -1;
    }
  }
  return 0;
}

/**
 * Copy symlink metadata (owner/group and timestamps) when supported.
 **/
static void
ftp_copy_symlink_metadata(const char *src_path, const char *dst_path) {
#if defined(__linux__)
  struct stat st;
  if(lstat(src_path, &st) != 0) {
    return;
  }
  if(lchown(dst_path, st.st_uid, st.st_gid) != 0 && errno != EPERM) {
    return;
  }
#ifdef UTIME_OMIT
  struct timespec ts[2];
  ts[0].tv_sec = st.st_atime;
  ts[0].tv_nsec = 0;
  ts[1].tv_sec = st.st_mtime;
  ts[1].tv_nsec = 0;
  (void)utimensat(AT_FDCWD, dst_path, ts, AT_SYMLINK_NOFOLLOW);
#endif
#else
  (void)src_path;
  (void)dst_path;
#endif
}

/**
 * Create parent directories for a path.
 **/
static int
ftp_mkdirs_parent(const char *path) {
  if(!path || !*path) {
    errno = EINVAL;
    return -1;
  }

  char tmp[PATH_MAX];
  size_t len = strlen(path);
  if(len >= sizeof(tmp)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  memcpy(tmp, path, len + 1);

  char *slash = strrchr(tmp, '/');
  if(!slash || slash == tmp) {
    return 0;
  }
  *slash = '\0';

  for(char *p = tmp + 1; *p; p++) {
    if(*p == '/') {
      *p = '\0';
      if(mkdir(tmp, 0777)) {
        if(errno != EEXIST) {
          return -1;
        }
      }
      *p = '/';
    }
  }

  if(mkdir(tmp, 0777)) {
    if(errno != EEXIST) {
      return -1;
    }
  }
  return 0;
}

/**
 * Copy a regular file from src to dst.
 **/
static int
ftp_copy_file(const char *src_path, const char *dst_path,
              void *buf, size_t bufsize, ftp_copy_task_t *task) {
  char tmp_path[PATH_MAX];
#ifdef O_CLOEXEC
  int src_flags = O_RDONLY | O_CLOEXEC;
#else
  int src_flags = O_RDONLY;
#endif
#ifdef O_NOFOLLOW
  src_flags |= O_NOFOLLOW;
#endif
  int src_fd = -1;
  int dst_fd = -1;
  int tmp_created = 0;
  int free_buf = 0;
  int saved_errno = 0;
  void *tmp = buf;
  size_t tmp_size = bufsize;

  if(ftp_server_bg_op_cancelled()) {
    errno = FTP_BG_OP_CANCELLED_ERR;
    return -1;
  }

  src_fd = open(src_path, src_flags, 0);
  if(src_fd < 0) {
    return -1;
  }

  if(ftp_make_temp_path(dst_path, tmp_path, sizeof(tmp_path)) != 0) {
    saved_errno = errno;
    goto fail;
  }

  dst_fd = mkstemp(tmp_path);
  if(dst_fd < 0) {
    saved_errno = errno;
    goto fail;
  }
  tmp_created = 1;

  if(!tmp || !tmp_size) {
    tmp = malloc(IO_COPY_BUFSIZE);
    tmp_size = IO_COPY_BUFSIZE;
    free_buf = 1;
    if(!tmp) {
      saved_errno = errno;
      goto fail;
    }
  }

  for(;;) {
    if(ftp_server_bg_op_cancelled()) {
      saved_errno = FTP_BG_OP_CANCELLED_ERR;
      goto fail;
    }
    ssize_t r = read(src_fd, tmp, tmp_size);
    if(r < 0) {
      if(errno == EINTR) {
        continue;
      }
      saved_errno = errno;
      goto fail;
    }
    if(r == 0) {
      break;
    }
    if(io_nwrite(dst_fd, tmp, (size_t)r)) {
      saved_errno = errno;
      goto fail;
    }
    ftp_copy_progress_add(task, (uintmax_t)r);
  }

  if(ftp_server_bg_op_cancelled()) {
    saved_errno = FTP_BG_OP_CANCELLED_ERR;
    goto fail;
  }

  if(free_buf) {
    free(tmp);
    tmp = NULL;
    free_buf = 0;
  }

  if(close(dst_fd) != 0) {
    saved_errno = errno;
    dst_fd = -1;
    goto fail;
  }
  dst_fd = -1;

  if(ftp_server_bg_op_cancelled()) {
    saved_errno = FTP_BG_OP_CANCELLED_ERR;
    goto fail;
  }

  if(ftp_copy_metadata(src_path, tmp_path)) {
    saved_errno = errno;
    goto fail;
  }

  if(ftp_server_bg_op_cancelled()) {
    saved_errno = FTP_BG_OP_CANCELLED_ERR;
    goto fail;
  }

  if(rename(tmp_path, dst_path) != 0) {
    saved_errno = errno;
    goto fail;
  }
  tmp_created = 0;

  close(src_fd);
  return 0;

fail:
  if(!saved_errno) {
    saved_errno = errno;
  }
  if(free_buf && tmp) {
    free(tmp);
  }
  if(src_fd >= 0) {
    close(src_fd);
  }
  if(dst_fd >= 0) {
    close(dst_fd);
  }
  if(tmp_created) {
    unlink(tmp_path);
  }
  errno = saved_errno;
  return -1;
}

/**
 * Copy a directory tree from src to dst.
 **/
static int
ftp_copy_dir(const char *src_dir, const char *dst_dir,
             void *buf, size_t bufsize, ftp_copy_task_t *task) {
  DIR *dir = NULL;
  struct dirent *ent = NULL;
  struct stat st;
  int res = 0;
  int saved_errno = 0;

  if(ftp_server_bg_op_cancelled()) {
    errno = FTP_BG_OP_CANCELLED_ERR;
    return -1;
  }

  if(lstat(dst_dir, &st) == 0) {
    if(!S_ISDIR(st.st_mode)) {
      errno = ENOTDIR;
      return -1;
    }
  } else if(errno == ENOENT) {
    if(mkdir(dst_dir, 0777)) {
      return -1;
    }
  } else {
    return -1;
  }

  dir = opendir(src_dir);
  if(!dir) {
    return -1;
  }

  for(;;) {
    if(ftp_server_bg_op_cancelled()) {
      saved_errno = FTP_BG_OP_CANCELLED_ERR;
      res = -1;
      break;
    }
    int rc = ftp_dir_next_entry(dir, &ent);
    if(rc <= 0) {
      if(rc < 0) {
        saved_errno = errno;
        res = -1;
      }
      break;
    }

    char src_path[PATH_MAX];
    char dst_path[PATH_MAX];
    if(ftp_join_path(src_path, sizeof(src_path), src_dir, ent->d_name) != 0 ||
       ftp_join_path(dst_path, sizeof(dst_path), dst_dir, ent->d_name) != 0) {
      saved_errno = errno;
      res = -1;
      break;
    }

    if(ftp_dir_child_lstat(dir, src_dir, ent->d_name, &st) != 0) {
      saved_errno = errno;
      res = -1;
      break;
    }
    if(S_ISDIR(st.st_mode)) {
      if(ftp_copy_dir(src_path, dst_path, buf, bufsize, task)) {
        saved_errno = errno;
        res = -1;
        break;
      }
    } else if(S_ISREG(st.st_mode)) {
      if(ftp_copy_file(src_path, dst_path, buf, bufsize, task)) {
        saved_errno = errno;
        res = -1;
        break;
      }
    } else if(S_ISLNK(st.st_mode)) {
      if(ftp_copy_symlink(src_path, dst_path)) {
        saved_errno = errno;
        res = -1;
        break;
      }
      ftp_copy_symlink_metadata(src_path, dst_path);
      ftp_copy_progress_add(task, (uintmax_t)st.st_size);
    } else {
      errno = EINVAL;
      saved_errno = errno;
      res = -1;
      break;
    }
  }

  if(closedir(dir) && !saved_errno) {
    saved_errno = errno;
    res = -1;
  }
  if(saved_errno) {
    errno = saved_errno;
  }
  if(res == 0) {
    if(ftp_server_bg_op_cancelled()) {
      errno = FTP_BG_OP_CANCELLED_ERR;
      return -1;
    }
    if(ftp_copy_metadata(src_dir, dst_dir)) {
      return -1;
    }
  }
  return res;
}

/**
 * Join finished copy thread if needed.
 **/
static void
ftp_copy_thread_cleanup(ftp_env_t *env) {
  pthread_t thread;
  int should_join = 0;

  pthread_mutex_lock(&env->copy_mutex);
  if(env->copy_thread_valid && !env->copy_in_progress) {
    thread = env->copy_thread;
    env->copy_thread_valid = 0;
    should_join = 1;
  }
  pthread_mutex_unlock(&env->copy_mutex);

  if(should_join) {
    pthread_join(thread, NULL);
  }
}

/**
 * Background copy worker.
 **/
static void*
ftp_copy_thread(void *arg) {
  ftp_copy_task_t *task = (ftp_copy_task_t *)arg;
  ftp_env_t *env = task->env;
  int rc = 0;
  int saved_errno = 0;
  void *buf = NULL;
  size_t bufsize = 0;

  ftp_copy_notify_start(task);

  if(task->kind == FTP_COPY_REG || task->kind == FTP_COPY_DIR) {
    bufsize = IO_COPY_BUFSIZE;
    buf = malloc(bufsize);
    if(!buf) {
      rc = -1;
      errno = ENOMEM;
    }
  }

  if(!rc) {
    switch(task->kind) {
      case FTP_COPY_REG:
        rc = ftp_copy_file(task->src, task->dst, buf, bufsize, task);
        break;
      case FTP_COPY_DIR:
        rc = ftp_copy_dir(task->src, task->dst, buf, bufsize, task);
        break;
      case FTP_COPY_SYMLINK:
        rc = ftp_copy_symlink(task->src, task->dst);
        if(!rc) {
          struct stat st;
          if(lstat(task->src, &st) == 0) {
            ftp_copy_progress_add(task, (uintmax_t)st.st_size);
          }
          ftp_copy_symlink_metadata(task->src, task->dst);
        }
        break;
    }
  }

  if(rc) {
    saved_errno = errno;
  }

  if(!rc && ftp_move_remove_source(task) != 0) {
    rc = -1;
    saved_errno = errno;
  }

  if(buf) {
    free(buf);
  }

  ftp_copy_notify_result(task, rc, saved_errno);

  pthread_mutex_lock(&env->copy_mutex);
  env->copy_in_progress = 0;
  pthread_mutex_unlock(&env->copy_mutex);
  ftp_server_bg_op_release();

  free(task);
  return NULL;
}

/**
 * Copy a file previously specified by CPFR to a new location.
 **/
int
ftp_cmd_CPTO(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  char argbuf[PATH_MAX + 1];
  struct stat src_st;
  struct stat st;
  const char *path_arg = NULL;
  uintmax_t total_bytes = 0;

  ftp_copy_thread_cleanup(env);
  ftp_delete_thread_cleanup(env);
  if(ftp_server_bg_op_busy()) {
    return ftp_active_printf(env, "450 Background file operation in progress\r\n");
  }

  path_arg = ftp_copy_path_arg(arg, argbuf, sizeof(argbuf));
  if(!path_arg) {
    return ftp_active_printf(env, "501 Usage: CPTO <PATH>\r\n");
  }
  if(!env->copy_ready) {
    return ftp_active_printf(env, "503 Bad sequence of commands\r\n");
  }
  env->copy_ready = 0;

  if(lstat(env->copy_path, &src_st)) {
    return ftp_perror(env);
  }

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), path_arg)) {
    return ftp_perror(env);
  }
  if(strcmp(env->copy_path, pathbuf) == 0) {
    return ftp_active_printf(env, "553 Source and destination are the same\r\n");
  }

  if(S_ISREG(src_st.st_mode)) {
    ftp_copy_task_t *task;

    if(lstat(pathbuf, &st) == 0) {
      if(S_ISDIR(st.st_mode)) {
        return ftp_active_printf(env, "550 Target is a directory\r\n");
      }
    } else if(errno != ENOENT) {
      return ftp_perror(env);
    }
    if(ftp_copy_probe_destination(pathbuf, 0, 1) != 0) {
      return ftp_perror(env);
    }
    if(ftp_copy_prepare_total(env->copy_path, &src_st, pathbuf, 0,
                              &total_bytes) != 0) {
      return ftp_perror(env);
    }

    task = ftp_copy_create_task(env, FTP_BG_COPY, FTP_COPY_REG,
                                env->copy_path, pathbuf, total_bytes);
    if(!task) {
      return ftp_perror(env);
    }
    return ftp_copy_start_task(env, task);
  }

  if(S_ISDIR(src_st.st_mode)) {
    ftp_copy_task_t *task;

    size_t src_len = strlen(env->copy_path);
    if(strncmp(pathbuf, env->copy_path, src_len) == 0 &&
       (pathbuf[src_len] == '/' || pathbuf[src_len] == '\0')) {
      return ftp_active_printf(env, "553 Cannot copy into itself\r\n");
    }
    if(lstat(pathbuf, &st) == 0) {
      if(!S_ISDIR(st.st_mode)) {
        return ftp_active_printf(env, "550 Not a directory\r\n");
      }
    } else if(errno != ENOENT) {
      return ftp_perror(env);
    }
    if(ftp_copy_probe_destination(pathbuf, 1, 1) != 0) {
      return ftp_perror(env);
    }
    if(ftp_copy_prepare_total(env->copy_path, &src_st, pathbuf, 1,
                              &total_bytes) != 0) {
      return ftp_perror(env);
    }

    task = ftp_copy_create_task(env, FTP_BG_COPY, FTP_COPY_DIR,
                                env->copy_path, pathbuf, total_bytes);
    if(!task) {
      return ftp_perror(env);
    }
    return ftp_copy_start_task(env, task);
  }

  if(S_ISLNK(src_st.st_mode)) {
    ftp_copy_task_t *task;

    if(lstat(pathbuf, &st) == 0) {
      if(S_ISDIR(st.st_mode)) {
        return ftp_active_printf(env, "550 Target is a directory\r\n");
      }
    } else if(errno != ENOENT) {
      return ftp_perror(env);
    }
    if(ftp_copy_probe_destination(pathbuf, 0, 1) != 0) {
      return ftp_perror(env);
    }
    if(ftp_copy_prepare_total(env->copy_path, &src_st, pathbuf, 0,
                              &total_bytes) != 0) {
      return ftp_perror(env);
    }
    task = ftp_copy_create_task(env, FTP_BG_COPY, FTP_COPY_SYMLINK,
                                env->copy_path, pathbuf, total_bytes);
    if(!task) {
      return ftp_perror(env);
    }
    return ftp_copy_start_task(env, task);
  }

  return ftp_active_printf(env, "550 Unsupported file type\r\n");
}

/**
 * Copy a path on the server (COPY <FROM> <TO>).
 **/
int
ftp_cmd_COPY(ftp_env_t *env, const char* arg) {
  char src_arg[PATH_MAX + 1];
  char dst_arg[PATH_MAX + 1];
  char src_path[PATH_MAX];
  char dst_path[PATH_MAX];
  struct stat src_st;
  struct stat st;
  uintmax_t total_bytes = 0;

  ftp_copy_thread_cleanup(env);
  ftp_delete_thread_cleanup(env);
  if(ftp_server_bg_op_busy()) {
    return ftp_active_printf(env, "450 Background file operation in progress\r\n");
  }

  if(ftp_split_copy_args(arg, src_arg, sizeof(src_arg),
                         dst_arg, sizeof(dst_arg))) {
    return ftp_active_printf(env, "501 Usage: COPY <FROM> <TO>\r\n");
  }

  if(ftp_abspath(env, src_path, sizeof(src_path), src_arg)) {
    return ftp_perror(env);
  }
  if(ftp_abspath(env, dst_path, sizeof(dst_path), dst_arg)) {
    return ftp_perror(env);
  }
  if(strcmp(src_path, dst_path) == 0) {
    return ftp_active_printf(env, "553 Source and destination are the same\r\n");
  }

  if(lstat(src_path, &src_st)) {
    return ftp_perror(env);
  }

  if(S_ISREG(src_st.st_mode)) {
    ftp_copy_task_t *task;

    if(lstat(dst_path, &st) == 0) {
      if(S_ISDIR(st.st_mode)) {
        return ftp_active_printf(env, "550 Target is a directory\r\n");
      }
    } else if(errno != ENOENT) {
      return ftp_perror(env);
    }
    if(ftp_copy_probe_destination(dst_path, 0, 1) != 0) {
      return ftp_perror(env);
    }
    if(ftp_copy_prepare_total(src_path, &src_st, dst_path, 0,
                              &total_bytes) != 0) {
      return ftp_perror(env);
    }

    task = ftp_copy_create_task(env, FTP_BG_COPY, FTP_COPY_REG,
                                src_path, dst_path, total_bytes);
    if(!task) {
      return ftp_perror(env);
    }
    return ftp_copy_start_task(env, task);
  }

  if(S_ISDIR(src_st.st_mode)) {
    ftp_copy_task_t *task;

    size_t src_len = strlen(src_path);
    if(strncmp(dst_path, src_path, src_len) == 0 &&
       (dst_path[src_len] == '/' || dst_path[src_len] == '\0')) {
      return ftp_active_printf(env, "553 Cannot copy into itself\r\n");
    }
    if(lstat(dst_path, &st) == 0) {
      if(!S_ISDIR(st.st_mode)) {
        return ftp_active_printf(env, "550 Not a directory\r\n");
      }
    } else if(errno != ENOENT) {
      return ftp_perror(env);
    }
    if(ftp_copy_probe_destination(dst_path, 1, 1) != 0) {
      return ftp_perror(env);
    }
    if(ftp_copy_prepare_total(src_path, &src_st, dst_path, 1,
                              &total_bytes) != 0) {
      return ftp_perror(env);
    }

    task = ftp_copy_create_task(env, FTP_BG_COPY, FTP_COPY_DIR,
                                src_path, dst_path, total_bytes);
    if(!task) {
      return ftp_perror(env);
    }
    return ftp_copy_start_task(env, task);
  }

  if(S_ISLNK(src_st.st_mode)) {
    ftp_copy_task_t *task;

    if(lstat(dst_path, &st) == 0) {
      if(S_ISDIR(st.st_mode)) {
        return ftp_active_printf(env, "550 Target is a directory\r\n");
      }
    } else if(errno != ENOENT) {
      return ftp_perror(env);
    }
    if(ftp_copy_probe_destination(dst_path, 0, 1) != 0) {
      return ftp_perror(env);
    }
    if(ftp_copy_prepare_total(src_path, &src_st, dst_path, 0,
                              &total_bytes) != 0) {
      return ftp_perror(env);
    }
    task = ftp_copy_create_task(env, FTP_BG_COPY, FTP_COPY_SYMLINK,
                                src_path, dst_path, total_bytes);
    if(!task) {
      return ftp_perror(env);
    }
    return ftp_copy_start_task(env, task);
  }

  return ftp_active_printf(env, "550 Unsupported file type\r\n");
}


/**
 * Obtain the size of a given file or directory.
 **/
int
ftp_cmd_DSIZ(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat st;
  uintmax_t size = 0;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: DSIZ <PATH>\r\n");
  }

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_active_printf(env, "550 %s: %s.\r\n", arg, strerror(errno));
  }

  if(stat(pathbuf, &st)) {
    return ftp_active_printf(env, "550 %s: %s.\r\n", arg, strerror(errno));
  }

  if(S_ISREG(st.st_mode)) {
    return ftp_active_printf(env, "550 %s: Is a file.\r\n", arg);
  }
  if(!S_ISDIR(st.st_mode)) {
    return ftp_active_printf(env, "550 %s: Not a directory.\r\n", arg);
  }

  if(ftp_dir_size(pathbuf, &size)) {
    return ftp_active_printf(env, "550 %s: %s.\r\n", arg, strerror(errno));
  }

  return ftp_active_printf(env, "213 %" PRIuMAX "\r\n", size);
}

/**
 * Obtain the size of a given file.
 **/
int
ftp_cmd_SIZE(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat st = {0};

  if(env->type == 'A') {
    return ftp_active_printf(env, "504 SIZE not supported in ASCII mode\r\n");
  }

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: SIZE <FILENAME>\r\n");
  }

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }

  if(env->self2elf) {
    size_t elf_size = self_get_elfsize(pathbuf);
    if(elf_size && ftp_set_stat_size(&st, elf_size) != 0) {
      return ftp_perror(env);
    }
  }

  if(!st.st_size) {
    if(stat(pathbuf, &st)) {
      return ftp_perror(env);
    }
  }

  return ftp_active_printf(env, "213 %"  PRIu64 "\r\n", st.st_size);
}

 
/**
 * Store recieved data in a given file.
 **/
int
ftp_cmd_STOR(ftp_env_t *env, const char* arg) {
  off_t off = env->data_offset;
  int is_rest = env->data_offset_is_rest;
  char pathbuf[PATH_MAX];
  void *readbuf = env->xfer_buf;
  size_t bufsize = env->xfer_buf_size;
  int err = 0;
  int active = 0;
  int free_buf = 0;
  ssize_t len = 0;
  struct stat st;
  int flags = O_WRONLY;
#ifdef O_CLOEXEC
  flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
  int fd;

  env->data_offset = 0;
  env->data_offset_is_rest = 0;
  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: STOR <FILENAME>\r\n");
  }

  if(env->type == 'A' && off != 0 && is_rest) {
    env->data_offset = 0;
    return ftp_active_printf(env, "504 REST not supported in ASCII mode\r\n");
  }

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }
  // Reject symlinks and non-regular files as upload targets.
  // (If you want to allow symlinks, remove the lstat() block below.)
#ifdef S_IFLNK
  {
    struct stat lst;
    if(lstat(pathbuf, &lst) == 0) {
      if(S_ISLNK(lst.st_mode)) {
        return ftp_active_printf(env, "550 Symlinks are not allowed\r\n");
      }
    } else if(errno != ENOENT) {
      return ftp_perror(env);
    }
  }
#endif
  if(stat(pathbuf, &st) == 0) {
    if(!S_ISREG(st.st_mode)) {
      return ftp_active_printf(env, "550 Not a regular file\r\n");
    }
  } else if(errno != ENOENT) {
    return ftp_perror(env);
  }

  int precheck = ftp_data_precheck(env);
  if(precheck) {
    return precheck < 0 ? precheck : 0;
  }

  if(off == 0) {
    flags |= O_CREAT | O_TRUNC;
  }

  if((fd = open(pathbuf, flags, 0777)) < 0) {
    return ftp_perror(env);
  }

  if(off > 0) {
    if(fstat(fd, &st)) {
      err = ftp_perror(env);
      close(fd);
      return err;
    }
    if(!S_ISREG(st.st_mode)) {
      close(fd);
      return ftp_active_printf(env, "550 Not a regular file\r\n");
    }
    if(off > st.st_size) {
      close(fd);
      return ftp_active_printf(env, "551 Restart point beyond EOF\r\n");
    }
  }

  if(lseek(fd, off, SEEK_SET) < 0) {
    err = ftp_perror(env);
    close(fd);
    return err;
  }

  int open_err = ftp_data_xfer_start(env, 1);
  if(open_err) {
    close(fd);
    return open_err < 0 ? open_err : 0;
  }
  kstuff_autopause_active_begin();
  active = 1;

  if(!readbuf || !bufsize) {
    size_t alloc_size = IO_COPY_BUFSIZE;
#if defined(IO_USE_AIO)
    if(env->type != 'A' && alloc_size < IO_AIO_CHUNK_SIZE) {
      alloc_size = IO_AIO_CHUNK_SIZE;
    }
#endif
    readbuf = malloc(alloc_size);
    bufsize = alloc_size;
    free_buf = 1;
    if(!readbuf) {
      err = ftp_perror(env);
      ftp_data_close(env);
      close(fd);
      goto out;
    }
  }

  if(env->type == 'A') {
    if(ftp_copy_ascii_in(env, fd, &off)) {
      err = ftp_data_xfer_error_reply(env);
      ftp_data_close(env);
      if(free_buf) {
        free(readbuf);
      }
      close(fd);
      goto out;
    }
  } else {
#if defined(IO_USE_AIO)
    return ftp_cmd_STOR_binary_aio(env, fd, readbuf, bufsize, free_buf, off);
#else
    while((len = ftp_data_read(env, readbuf, bufsize)) > 0) {
      if(io_nwrite(fd, readbuf, (size_t)len)) {
        err = ftp_perror(env);
        ftp_data_close(env);
        if(free_buf) {
          free(readbuf);
        }
        close(fd);
        goto out;
      }
      off += len;
    }
#endif
  }

  if(env->type != 'A' && len < 0) {
    err = ftp_data_xfer_error_reply(env);
    ftp_data_close(env);
    if(free_buf) {
      free(readbuf);
    }
    close(fd);
    goto out;
  }

  if(free_buf) {
    free(readbuf);
  }

  if(ftruncate(fd, off)) {
    err = ftp_perror(env);
    ftp_data_close(env);
    close(fd);
    goto out;
  }

  close(fd);
  if(ftp_data_close(env)) {
    err = ftp_perror(env);
    goto out;
  }

  err = ftp_active_printf(env, "226 Data transfer complete\r\n");

out:
  if(active) {
    kstuff_autopause_active_end();
  }
  return err;
}


/**
 * Append to an existing file.
 **/
int
ftp_cmd_APPE(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat statbuf;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: APPE <FILENAME>\r\n");
  }

  env->data_offset = 0;
  env->data_offset_is_rest = 0;

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }

#ifdef S_IFLNK
  {
    struct stat lst;
    if(lstat(pathbuf, &lst) == 0) {
      if(S_ISLNK(lst.st_mode)) {
        return ftp_active_printf(env, "550 Symlinks are not allowed\r\n");
      }
    } else if(errno != ENOENT) {
      return ftp_perror(env);
    }
  }
#endif

  if(stat(pathbuf, &statbuf) == 0) {
    if(!S_ISREG(statbuf.st_mode)) {
      return ftp_active_printf(env, "550 Not a regular file\r\n");
    }
    env->data_offset = statbuf.st_size;
  } else {
    if(errno != ENOENT) {
      return ftp_perror(env);
    }
    env->data_offset = 0;
  }

  return ftp_cmd_STOR(env, arg);
}


/**
 * Return system type.
 **/
int
ftp_cmd_SYST(ftp_env_t *env, const char* arg) {
  (void)arg;
  return ftp_active_printf(env, "215 UNIX Type: L8\r\n");
}


/**
 * Sets the transfer mode (ASCII or Binary).
 **/
int
ftp_cmd_TYPE(ftp_env_t *env, const char* arg) {
  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: TYPE <TYPE>\r\n");
  }
  switch(arg[0]) {
#ifdef DISABLE_ASCII_MODE
  case 'A':
  case 'I':
    env->type = 'I';
    return ftp_active_printf(env, "200 Type set to I\r\n");
#else
  case 'A':
    env->data_offset = 0;
    env->type = 'A';
    return ftp_active_printf(env, "200 Type set to %c\r\n", env->type);
  case 'I':
    env->type = 'I';
    return ftp_active_printf(env, "200 Type set to %c\r\n", env->type);
#endif
  default:
    return ftp_active_printf(env, "504 Type not supported\r\n");
  }
}


/**
 * Authenticate user.
 **/
int
ftp_cmd_USER(ftp_env_t *env, const char* arg) {
  (void)arg;
  return ftp_active_printf(env, "230 User logged in\r\n");
}

/**
 * Specify user password.
 **/
int
ftp_cmd_PASS(ftp_env_t *env, const char *arg) {
  (void)arg;
  return ftp_active_printf(env, "230 User logged in\r\n");
}

/**
 * Feature list.
 **/
int
ftp_cmd_FEAT(ftp_env_t *env, const char *arg) {
  (void)arg;
  return ftp_active_printf(env,
                           "211-Features:\r\n"
                           " MLST type*;unique*;size*;modify*;unix.mode*;"
                           "unix.uid*;unix.gid*;\r\n"
                           " AVBL\r\n"
                           " XQUOTA\r\n"
                           " MLSD\r\n"
                           " MDTM\r\n"
                           " SIZE\r\n"
                           " DSIZ\r\n"
                           " RMDA\r\n"
                           " EPSV\r\n"
                           " EPRT\r\n"
                           " KILL\r\n"
                           " MTRW\r\n"
                           " COMP\r\n"
                           " STOP\r\n"
                           " SELF\r\n"
                           " SCHK\r\n"
                           " SITE CHMOD\r\n"
                           " SITE UMASK\r\n"
                           " SITE SYMLINK\r\n"
                           " SITE RMDIR\r\n"
                           " SITE CPFR\r\n"
                           " SITE CPTO\r\n"
                           " SITE COPY\r\n"
                           " SITE MOVE\r\n"
                           " SITE LOWER\r\n"
                           " SITE UPPER\r\n"
                           " SITE STOP\r\n"
                           " SITE AUTHID\r\n"
                           " SITE COMP\r\n"
                           " UTF8\r\n"
                           " REST STREAM\r\n"
                           "211 End\r\n");
}

/**
 * Set options.
 **/
int
ftp_cmd_OPTS(ftp_env_t *env, const char *arg) {
  char opt[16];
  char val[16];
  size_t len = 0;

  if(!*arg) {
    return ftp_active_printf(env, "501 Usage: OPTS UTF8 ON\r\n");
  }

  len = strcspn(arg, " ");
  if(len >= sizeof(opt)) {
    len = sizeof(opt) - 1;
  }
  memcpy(opt, arg, len);
  opt[len] = '\0';
  arg += len;
  arg += strspn(arg, " ");

  len = strcspn(arg, " ");
  if(len >= sizeof(val)) {
    len = sizeof(val) - 1;
  }
  memcpy(val, arg, len);
  val[len] = '\0';

  if(!strcasecmp(opt, "UTF8")) {
    if(!val[0] || !strcasecmp(val, "ON")) {
      return ftp_active_printf(env, "200 UTF8 enabled\r\n");
    }
    if(!strcasecmp(val, "OFF")) {
      return ftp_active_printf(env, "200 UTF8 disabled\r\n");
    }
    return ftp_active_printf(env, "501 Usage: OPTS UTF8 ON\r\n");
  }

  return ftp_active_printf(env, "504 Option not supported\r\n");
}

/**
 * Return modification time.
 **/
int
ftp_cmd_MDTM(ftp_env_t *env, const char *arg) {
  char pathbuf[PATH_MAX];
  char timebuf[32];
  struct stat st;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: MDTM <FILENAME>\r\n");
  }

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }
  if(stat(pathbuf, &st)) {
    return ftp_perror(env);
  }
  if(ftp_format_mdtm(st.st_mtime, timebuf, sizeof(timebuf))) {
    return ftp_active_printf(env, "550 MDTM failed\r\n");
  }

  return ftp_active_printf(env, "213 %s\r\n", timebuf);
}

/**
 * Return machine-readable info for one path.
 **/
int
ftp_cmd_MLST(ftp_env_t *env, const char *arg) {
  char pathbuf[PATH_MAX];
  char namebuf[PATH_MAX + 1];
  char *typebuf = NULL;
  char *linebuf = NULL;
  struct stat st;
  const char *name = NULL;
  const char *type = "type=unknown;";
  char uniquebuf[64];
  const char *unique = "unique=;";
  uintmax_t size = 0;
  unsigned mode_bits = 0;
  uintmax_t uid = 0;
  uintmax_t gid = 0;
  const char *path_arg = ftp_copy_path_arg(arg, namebuf, sizeof(namebuf));

  if(path_arg) {
    if(ftp_abspath(env, pathbuf, sizeof(pathbuf), path_arg)) {
      return ftp_perror(env);
    }
    name = path_arg;
  } else {
    if(ftp_normpath(env->cwd, pathbuf, sizeof(pathbuf))) {
      return ftp_perror(env);
    }
    name = pathbuf;
  }

  if(lstat(pathbuf, &st)) {
    return ftp_perror(env);
  }

  typebuf = malloc(PATH_MAX + 1);
  if(!typebuf) {
    return ftp_perror(env);
  }
  linebuf = malloc(PATH_MAX * 3);
  if(!linebuf) {
    free(typebuf);
    return ftp_perror(env);
  }
  type = ftp_mlst_type_fact(typebuf, PATH_MAX + 1, name, &st, pathbuf);
  unique = ftp_mlst_unique_fact(uniquebuf, sizeof(uniquebuf), &st);

  if(env->self2elf && S_ISREG(st.st_mode)) {
    size_t elf_size = self_is_valid(pathbuf);
    size = elf_size ? (uintmax_t)elf_size : (uintmax_t)st.st_size;
  } else {
    size = (uintmax_t)st.st_size;
  }
  mode_bits = (unsigned)(st.st_mode & 07777);
  uid = (uintmax_t)st.st_uid;
  gid = (uintmax_t)st.st_gid;

  if(ftp_mlst_format_line(linebuf, PATH_MAX * 3, 1, type, unique, size,
                          st.st_mtime, mode_bits, uid, gid, name)) {
    free(typebuf);
    free(linebuf);
    return ftp_active_printf(env, "550 MLST failed\r\n");
  }

  if(name[0] == '/' && name[1] == '\0') {
    name = "/";
  }

  if(ftp_active_printf(env, "250-Listing\r\n")) {
    free(typebuf);
    free(linebuf);
    return -1;
  }
  if(ftp_active_printf(env, "%s", linebuf)) {
    free(typebuf);
    free(linebuf);
    return -1;
  }
  free(typebuf);
  free(linebuf);
  return ftp_active_printf(env, "250 End\r\n");
}

/**
 * Status info.
 **/
int
ftp_cmd_STAT(ftp_env_t *env, const char *arg) {
  (void)arg;
  if(ftp_active_printf(env, "211-FTP server status:\r\n")) {
    return -1;
  }
  if(ftp_active_printf(env, " CWD %s\r\n", env->cwd)) {
    return -1;
  }
  return ftp_active_printf(env, "211 End\r\n");
}

/**
 * Help.
 **/
int
ftp_cmd_HELP(ftp_env_t *env, const char *arg) {
  (void)arg;
  return ftp_active_printf(env,
                           "214-Commands:\r\n"
                           " USER PASS PWD CWD CDUP TYPE SIZE DSIZ MDTM AVBL\r\n"
                           " LIST NLST MLSD MLST RETR STOR APPE\r\n"
                           " DELE RMD RMDA MKD RNFR RNTO REST LOWER UPPER STOP XQUOTA COMP\r\n"
                           " PASV PORT EPSV EPRT SYST NOOP QUIT\r\n"
                           " SITE CHMOD UMASK SYMLINK RMDIR CPFR CPTO COPY MOVE LOWER UPPER STOP AUTHID COMP\r\n"
                           "214 End\r\n");
}

/**
 * Transfer mode.
 **/
int
ftp_cmd_MODE(ftp_env_t *env, const char *arg) {
  (void)env;
  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: MODE S\r\n");
  }
  if(arg[0] == 'S' || arg[0] == 's') {
    return ftp_active_printf(env, "200 Mode set to S\r\n");
  }
  return ftp_active_printf(env, "504 MODE not supported\r\n");
}

/**
 * File structure.
 **/
int
ftp_cmd_STRU(ftp_env_t *env, const char *arg) {
  (void)env;
  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: STRU F\r\n");
  }
  if(arg[0] == 'F' || arg[0] == 'f') {
    return ftp_active_printf(env, "200 Structure set to F\r\n");
  }
  return ftp_active_printf(env, "504 STRU not supported\r\n");
}

/**
 * Allocate storage (no-op).
 **/
int
ftp_cmd_ALLO(ftp_env_t *env, const char *arg) {
  (void)arg;
  return ftp_active_printf(env, "200 ALLO OK\r\n");
}

/**
 * Abort transfer.
 **/
int
ftp_cmd_ABOR(ftp_env_t *env, const char *arg) {
  (void)arg;
  if(env->data_fd >= 0) {
    ftp_data_close(env);
    env->data_offset = 0;
    if(ftp_active_printf(env,
                         "426 Data connection closed; transfer aborted\r\n")) {
      return -1;
    }
    return ftp_active_printf(env, "226 Abort successful\r\n");
  }

  env->data_offset = 0;
  return ftp_active_printf(env, "225 No transfer to abort\r\n");
}

/**
 * Stop the current background file operation.
 **/
int
ftp_cmd_STOP(ftp_env_t *env, const char *arg) {
  int state;

  (void)arg;

  state = ftp_server_bg_op_cancel();
  if(state == 0) {
    return ftp_active_printf(env,
                             "225 No background file operation to stop\r\n");
  }
  if(state == 1) {
    notify("Background file operation stop requested");
  }
  return ftp_active_printf(env,
                           "200 Background file operation stop %s\r\n",
                           state == 2 ? "already requested" : "requested");
}

/**
 * Custom command that terminates the server.
 **/
int
ftp_cmd_KILL(ftp_env_t *env, const char* arg) {
  (void)env;
  (void)arg;
  FTP_LOG_PUTS("Server killed");
  exit(EXIT_SUCCESS);
  return -1;
}



/**
 * Custom command to toggle SELF transfer mode.
 **/
int
ftp_cmd_SELF(ftp_env_t *env, const char* arg) {
  (void)arg;
  env->self2elf = !env->self2elf;

  if(env->self2elf) {
    return ftp_active_printf(env, "200 SELF transfer mode enabled\r\n");
  } else {
    return ftp_active_printf(env, "200 SELF transfer mode disabled\r\n");
  }
}

/**
 * Toggle SELF digest verification.
 **/
int
ftp_cmd_SELFCHK(ftp_env_t *env, const char *arg) {
  if(arg[0]) {
    if(arg[1] || (arg[0] != '0' && arg[0] != '1')) {
      return ftp_active_printf(env, "501 Usage: SCHK <0|1>\r\n");
    }
    env->self_verify = arg[0] == '1';
  } else {
    env->self_verify = !env->self_verify;
  }

  if(env->self_verify) {
    return ftp_active_printf(env, "200 SELF digest verification enabled\r\n");
  } else {
    return ftp_active_printf(env, "200 SELF digest verification disabled\r\n");
  }
}

/**
 * Unsupported command.
 **/
int
ftp_cmd_unavailable(ftp_env_t *env, const char* arg) {
  (void)arg;
  return ftp_active_printf(env, "502 Command not implemented\r\n");
}


/**
 * Unknown command.
 **/
int
ftp_cmd_unknown(ftp_env_t *env, const char* arg) {
  (void)arg;
  return ftp_active_printf(env, "502 Command not recognized\r\n");
}


/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/
