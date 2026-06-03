/* Copyright (C) 2026

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

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if !defined(__PROSPERO__)
#error "cmd-proc.c is PS5/Prospero-only"
#endif

#include <sys/sysctl.h>
#include <sys/user.h>
#include <ps5/kernel.h>

#include "cmd-proc.h"
#include "io.h"
#include "kstuff_autopause.h"

#ifndef FTP_PROC_OUTBUF_SIZE
#define FTP_PROC_OUTBUF_SIZE (256 * 1024)
#endif

typedef struct {
  ftp_env_t *env;
  char *buf;
  size_t cap;
  size_t len;
  int free_buf;
  int failed;
} ftp_proc_xfer_t;

typedef struct {
  pid_t pid;
  pid_t ppid;
  pid_t pgid;
  pid_t sid;
  uid_t uid;
  uint32_t app_id;
  uint64_t rss_bytes;
  uint64_t vsize_bytes;
  time_t start_time;
  char state[16];
  char title_id[16];
  char command[256];
  char cmdline[512];
} ftp_proc_info_t;

static int
ftp_proc_errno_is_timeout(int e) {
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

static int
ftp_proc_data_xfer_error_reply(ftp_env_t *env) {
  int e = errno;
  if(e == EPIPE
#ifdef ECONNRESET
     || e == ECONNRESET
#endif
  ) {
    return ftp_active_printf(env, "426 Data connection closed\r\n");
  }
  if(ftp_proc_errno_is_timeout(e)) {
    return ftp_active_printf(env, "426 Data connection timed out\r\n");
  }
  errno = e;
  return ftp_perror(env);
}

static int
ftp_proc_data_open_error_reply(ftp_env_t *env) {
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

static int
ftp_proc_data_precheck(ftp_env_t *env) {
  if(!env->data_addr.sin_port && env->passive_fd < 0) {
    errno = ENOTCONN;
    int err = ftp_proc_data_open_error_reply(env);
    if(err < 0) {
      return -1;
    }
    return 1;
  }
  return 0;
}

static int
ftp_proc_xfer_start(ftp_env_t *env, ftp_proc_xfer_t *x) {
  memset(x, 0, sizeof(*x));
  x->env = env;
  x->buf = env->xfer_buf;
  x->cap = env->xfer_buf_size;

  if(!x->buf || !x->cap) {
    x->cap = FTP_PROC_OUTBUF_SIZE;
    x->buf = malloc(x->cap);
    x->free_buf = 1;
    if(!x->buf) {
      int err = ftp_perror(env);
      return err < 0 ? -1 : 1;
    }
  }

  int precheck = ftp_proc_data_precheck(env);
  if(precheck) {
    if(x->free_buf) {
      free(x->buf);
    }
    return precheck < 0 ? -1 : 1;
  }
  if(ftp_active_printf(env, "150 Opening data transfer\r\n")) {
    if(x->free_buf) {
      free(x->buf);
    }
    return -1;
  }
  if(ftp_data_open(env)) {
    int err = ftp_proc_data_open_error_reply(env);
    if(x->free_buf) {
      free(x->buf);
    }
    return err < 0 ? -1 : 1;
  }

  kstuff_autopause_active_begin();
  return 0;
}

static void
ftp_proc_xfer_release(ftp_proc_xfer_t *x) {
  if(x->free_buf && x->buf) {
    free(x->buf);
  }
  x->buf = NULL;
  x->cap = 0;
  x->len = 0;
  x->free_buf = 0;
}

static int
ftp_proc_xfer_write_raw(ftp_proc_xfer_t *x, const void *data, size_t len) {
  if(x->failed) {
    return -1;
  }
  if(io_nwrite(x->env->data_fd, data, len)) {
    (void)ftp_proc_data_xfer_error_reply(x->env);
    x->failed = 1;
    return -1;
  }
  return 0;
}

static int
ftp_proc_xfer_flush(ftp_proc_xfer_t *x) {
  if(x->failed) {
    return -1;
  }
  if(x->len && ftp_proc_xfer_write_raw(x, x->buf, x->len)) {
    return -1;
  }
  x->len = 0;
  return 0;
}

static int
ftp_proc_xfer_vprintf(ftp_proc_xfer_t *x, const char *fmt, va_list ap) {
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
      return -1;
    }
    if((size_t)n < rem) {
      x->len += (size_t)n;
      return 0;
    }
    if(ftp_proc_xfer_flush(x)) {
      return -1;
    }
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

      int wr = ftp_proc_xfer_write_raw(x, tmp, (size_t)m);
      free(tmp);
      return wr;
    }
  }
}

static int
ftp_proc_xfer_printf(ftp_proc_xfer_t *x, const char *fmt, ...) {
  int rc;
  va_list ap;

  va_start(ap, fmt);
  rc = ftp_proc_xfer_vprintf(x, fmt, ap);
  va_end(ap);
  return rc;
}

static int
ftp_proc_xfer_finish(ftp_env_t *env, ftp_proc_xfer_t *x) {
  if(!x->failed) {
    (void)ftp_proc_xfer_flush(x);
  }
  if(ftp_data_close(env)) {
    (void)ftp_perror(env);
    x->failed = 1;
  }

  ftp_proc_xfer_release(x);
  kstuff_autopause_active_end();

  if(x->failed) {
    return 0;
  }
  return ftp_active_printf(env, "226 Transfer complete\r\n");
}

static const char *
ftp_proc_copy_path_arg(const char *arg, char *buf, size_t bufsize) {
  const char *p = arg;
  if(!buf || bufsize < 2 || !p) {
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

static const char *
ftp_proc_list_path_arg(const char *arg, char *buf, size_t bufsize) {
  const char *p = arg;
  if(!buf || bufsize < 2) {
    return NULL;
  }

  p += strspn(p, " ");
  if(!*p) {
    return NULL;
  }
  if(*p != '-') {
    return ftp_proc_copy_path_arg(p, buf, bufsize);
  }

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
  return ftp_proc_copy_path_arg(p, buf, bufsize);
}

int
ftp_proc_resolve_arg(ftp_env_t *env, const char *arg, int allow_opts,
                     char *path, size_t pathsz) {
  char argbuf[PATH_MAX + 1];
  const char *path_arg;

  path_arg = allow_opts
               ? ftp_proc_list_path_arg(arg, argbuf, sizeof(argbuf))
               : ftp_proc_copy_path_arg(arg, argbuf, sizeof(argbuf));
  if(path_arg) {
    return ftp_abspath(env, path, pathsz, path_arg);
  }

  if(snprintf(path, pathsz, "%s", env->cwd) >= (int)pathsz) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

static int
ftp_proc_format_mdtm(time_t t, char *buf, size_t bufsize) {
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

static int
ftp_proc_format_list_time(time_t t, char *buf, size_t bufsize) {
  struct tm tm;
  time_t now;
  static const char *mon[] = {"Jan","Feb","Mar","Apr","May","Jun",
                              "Jul","Aug","Sep","Oct","Nov","Dec"};

  if(!buf || bufsize < 14) {
    return -1;
  }
  if(!localtime_r(&t, &tm)) {
    (void)snprintf(buf, bufsize, "Jan  1  1970");
    return 0;
  }

  now = time(NULL);
  long long diff = (long long)now - (long long)t;
  const long long six_months = 180LL * 24LL * 60LL * 60LL;
  const char *mname = mon[(tm.tm_mon >= 0 && tm.tm_mon < 12) ? tm.tm_mon : 0];

  if(diff < 0 || diff > six_months) {
    (void)snprintf(buf, bufsize, "%s %2d  %4d", mname, tm.tm_mday,
                   tm.tm_year + 1900);
  } else {
    (void)snprintf(buf, bufsize, "%s %2d %02d:%02d", mname, tm.tm_mday,
                   tm.tm_hour, tm.tm_min);
  }
  return 0;
}

int
ftp_proc_is_root_path(const char *path) {
  return path && strcmp(path, "/proc") == 0;
}

static int
ftp_proc_is_all_path(const char *path) {
  return path && strcmp(path, "/proc/_all_") == 0;
}

int
ftp_proc_is_path(const char *path) {
  return ftp_proc_is_root_path(path) ||
         (path && strncmp(path, "/proc/", 6) == 0);
}

static int
ftp_proc_parse_pid_path(const char *path, pid_t *pid_out) {
  const char *p;
  char *end = NULL;
  long pid;

  if(!path || strncmp(path, "/proc/", 6) != 0) {
    errno = ENOENT;
    return -1;
  }
  if(ftp_proc_is_all_path(path)) {
    errno = EISDIR;
    return -1;
  }

  p = path + 6;
  if(!*p || strchr(p, '/')) {
    errno = ENOENT;
    return -1;
  }

  errno = 0;
  pid = strtol(p, &end, 10);
  if(errno || end == p || (*end && *end != '_') || pid < 0) {
    errno = ENOENT;
    return -1;
  }

  if(pid_out) {
    *pid_out = (pid_t)pid;
  }
  return 0;
}

int
ftp_proc_is_root_listing(const char *dir_path) {
  return dir_path && dir_path[0] == '/' && dir_path[1] == '\0';
}

int
ftp_proc_hide_real_proc_entry(const char *dir_path, const char *name) {
  return ftp_proc_is_root_listing(dir_path) && name &&
         strcmp(name, "proc") == 0;
}

int
ftp_proc_format_root_list_line(char *buf, size_t bufsz) {
  char timebuf[32];

  if(ftp_proc_format_list_time(time(NULL), timebuf, sizeof(timebuf))) {
    return -1;
  }
  if(snprintf(buf, bufsz, "dr-xr-xr-x 1 0 0 0 %s proc\r\n",
              timebuf) >= (int)bufsz) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

int
ftp_proc_format_root_mlsd_line(char *buf, size_t bufsz) {
  char timebuf[32];

  if(ftp_proc_format_mdtm(time(NULL), timebuf, sizeof(timebuf))) {
    return -1;
  }
  if(snprintf(buf, bufsz,
              "modify=%s;type=dir;size=0;perm=el;unique=proc-root; proc\r\n",
              timebuf) >= (int)bufsz) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

static uint64_t
ftp_proc_page_size(void) {
#ifdef _SC_PAGESIZE
  long page_size = sysconf(_SC_PAGESIZE);
  if(page_size > 0) {
    return (uint64_t)page_size;
  }
#endif
  return 4096;
}

static double
ftp_proc_mib(uint64_t bytes) {
  return (double)bytes / (1024.0 * 1024.0);
}

static int
ftp_proc_cmp_desc(const void *a, const void *b) {
  const ftp_proc_info_t *pa = (const ftp_proc_info_t *)a;
  const ftp_proc_info_t *pb = (const ftp_proc_info_t *)b;

  if(pa->pid < pb->pid) {
    return 1;
  }
  if(pa->pid > pb->pid) {
    return -1;
  }
  return 0;
}

static int
ftp_proc_append(ftp_proc_info_t **items, size_t *count, size_t *cap,
                const ftp_proc_info_t *info) {
  ftp_proc_info_t *tmp;
  size_t new_cap;

  if(*count == *cap) {
    new_cap = *cap ? (*cap * 2) : 64;
    tmp = realloc(*items, new_cap * sizeof(**items));
    if(!tmp) {
      return -1;
    }
    *items = tmp;
    *cap = new_cap;
  }

  (*items)[(*count)++] = *info;
  return 0;
}

static const char *
ftp_proc_title_or_default(const ftp_proc_info_t *info) {
  return info->title_id[0] ? info->title_id : "0000";
}

static void
ftp_proc_sanitize_name_part(const char *src, char *dst, size_t dstsz) {
  size_t i;
  size_t pos = 0;

  if(!dst || dstsz == 0) {
    return;
  }
  if(!src || !*src) {
    snprintf(dst, dstsz, "-");
    return;
  }

  for(i=0; src[i] && pos + 1 < dstsz; i++) {
    unsigned char c = (unsigned char)src[i];
    if(c <= ' ' || c == '/' || c == '\\' || c == ':' || c == ';') {
      if(pos > 0 && dst[pos - 1] == '_') {
        continue;
      }
      dst[pos++] = '_';
      continue;
    }
    dst[pos++] = (char)c;
  }

  while(pos > 1 && dst[pos - 1] == '_') {
    pos--;
  }
  dst[pos] = '\0';
}

static void
ftp_proc_format_entry_name(const ftp_proc_info_t *info, char *dst,
                           size_t dstsz) {
  char title[32];
  char command[128];

  ftp_proc_sanitize_name_part(ftp_proc_title_or_default(info), title,
                              sizeof(title));
  ftp_proc_sanitize_name_part(info->command[0] ? info->command : "-",
                              command, sizeof(command));
  snprintf(dst, dstsz, "%jd_%s_%s", (intmax_t)info->pid, title, command);
}

typedef struct {
  uint32_t app_id;
  uint64_t unknown1;
  char title_id[14];
  char unknown2[0x3c];
} ftp_proc_app_info_t;

int sceKernelGetAppInfo(pid_t pid, ftp_proc_app_info_t *info);

static const char *
ftp_proc_bsd_state(int state) {
  static const char *names[] = {
    "", "START", "RUN", "SLEEP", "STOP", "ZOMB", "WAIT", "LOCK"
  };

  if(state >= 0 && state < (int)(sizeof(names) / sizeof(names[0])) &&
     names[state][0]) {
    return names[state];
  }
  return "?";
}

static void
ftp_proc_fill_app_info(pid_t pid, ftp_proc_info_t *info) {
  ftp_proc_app_info_t app_info;

  memset(&app_info, 0, sizeof(app_info));
  if(sceKernelGetAppInfo(pid, &app_info) == 0) {
    info->app_id = app_info.app_id;
    snprintf(info->title_id, sizeof(info->title_id), "%.*s",
             (int)sizeof(app_info.title_id), app_info.title_id);
  }
}

static int
ftp_proc_collect(ftp_proc_info_t **items_out, size_t *count_out) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
  char *buf = NULL;
  char *ptr;
  char *end;
  size_t len = 0;
  ftp_proc_info_t *items = NULL;
  size_t count = 0;
  size_t cap = 0;
  uint64_t page_size = ftp_proc_page_size();

  if(!items_out || !count_out) {
    errno = EINVAL;
    return -1;
  }

  for(;;) {
    if(sysctl(mib, 4, NULL, &len, NULL, 0) < 0) {
      return -1;
    }
    buf = malloc(len);
    if(!buf) {
      return -1;
    }
    if(sysctl(mib, 4, buf, &len, NULL, 0) == 0) {
      break;
    }
    free(buf);
    buf = NULL;
    if(errno != ENOMEM) {
      return -1;
    }
  }

  ptr = buf;
  end = buf + len;
  while(ptr < end) {
    struct kinfo_proc *ki = (struct kinfo_proc *)ptr;
    ftp_proc_info_t info;

    if(ki->ki_structsize <= 0 ||
       ptr + ki->ki_structsize > end) {
      break;
    }

    memset(&info, 0, sizeof(info));
    info.pid = ki->ki_pid;
    info.ppid = ki->ki_ppid;
    info.pgid = ki->ki_pgid;
    info.sid = ki->ki_sid;
    info.uid = ki->ki_ruid;
    info.rss_bytes = (uint64_t)ki->ki_rssize * page_size;
    info.vsize_bytes = (uint64_t)ki->ki_size;
    info.start_time = ki->ki_start.tv_sec;
    snprintf(info.state, sizeof(info.state), "%s",
             ftp_proc_bsd_state(ki->ki_stat));
    snprintf(info.command, sizeof(info.command), "%s", ki->ki_comm);
    ftp_proc_fill_app_info(info.pid, &info);

    if(ftp_proc_append(&items, &count, &cap, &info)) {
      int saved_errno = errno;
      free(buf);
      free(items);
      errno = saved_errno;
      return -1;
    }

    ptr += ki->ki_structsize;
  }

  free(buf);
  qsort(items, count, sizeof(*items), ftp_proc_cmp_desc);
  *items_out = items;
  *count_out = count;
  return 0;
}

static int
ftp_proc_find(pid_t pid, ftp_proc_info_t *info_out) {
  ftp_proc_info_t *items = NULL;
  size_t count = 0;
  size_t i;

  if(ftp_proc_collect(&items, &count)) {
    return -1;
  }

  for(i=0; i<count; i++) {
    if(items[i].pid == pid) {
      if(info_out) {
        *info_out = items[i];
      }
      free(items);
      return 0;
    }
  }

  free(items);
  errno = ESRCH;
  return -1;
}

static int
ftp_proc_format_table_header(ftp_proc_xfer_t *x) {
  return ftp_proc_xfer_printf(x,
                              "%8s %9s %8s %8s %8s %10s %6s  %-10s %13s  %s\r\n",
                              "PID", "PPID", "PGID", "SID", "UID", "State",
                              "AppId", "TitleId", "Memory (MiB)", "Command");
}

static int
ftp_proc_format_table_row(ftp_proc_xfer_t *x, const ftp_proc_info_t *info) {
  return ftp_proc_xfer_printf(x,
                              "%8jd %9jd %8jd %8jd %8ju %10s   %04x  %-10s %6.1f / %6.1f  %s\r\n",
                              (intmax_t)info->pid,
                              (intmax_t)info->ppid,
                              (intmax_t)info->pgid,
                              (intmax_t)info->sid,
                              (uintmax_t)info->uid,
                              info->state,
                              (unsigned)info->app_id & 0xffff,
                              info->title_id,
                              ftp_proc_mib(info->rss_bytes),
                              ftp_proc_mib(info->vsize_bytes),
                              info->command[0] ? info->command : "-");
}

static int
ftp_proc_detail_snprintf(char *buf, size_t bufsz,
                         const ftp_proc_info_t *info) {
  char startbuf[32] = "-";

  if(info->start_time > 0) {
    (void)ftp_proc_format_mdtm(info->start_time, startbuf, sizeof(startbuf));
  }

  return snprintf(buf, bufsz,
                  "PID: %jd\r\n"
                  "PPID: %jd\r\n"
                  "PGID: %jd\r\n"
                  "SID: %jd\r\n"
                  "UID: %ju\r\n"
                  "State: %s\r\n"
                  "AppId: %04x\r\n"
                  "TitleId: %s\r\n"
                  "StartTime: %s\r\n"
                  "RSS: %.1f MiB\r\n"
                  "VirtualSize: %.1f MiB\r\n"
                  "Command: %s\r\n"
                  "Cmdline: %s\r\n",
                  (intmax_t)info->pid,
                  (intmax_t)info->ppid,
                  (intmax_t)info->pgid,
                  (intmax_t)info->sid,
                  (uintmax_t)info->uid,
                  info->state,
                  (unsigned)info->app_id & 0xffff,
                  info->title_id[0] ? info->title_id : "-",
                  startbuf,
                  ftp_proc_mib(info->rss_bytes),
                  ftp_proc_mib(info->vsize_bytes),
                  info->command[0] ? info->command : "-",
                  info->cmdline[0] ? info->cmdline : "-");
}

static size_t
ftp_proc_detail_size(const ftp_proc_info_t *info) {
  char buf[2048];
  int n = ftp_proc_detail_snprintf(buf, sizeof(buf), info);

  if(n < 0) {
    return 0;
  }
  if((size_t)n >= sizeof(buf)) {
    return sizeof(buf) - 1;
  }
  return (size_t)n;
}

static int
ftp_proc_write_detail(ftp_proc_xfer_t *x, const ftp_proc_info_t *info) {
  char buf[2048];
  int n = ftp_proc_detail_snprintf(buf, sizeof(buf), info);

  if(n < 0) {
    return -1;
  }
  if((size_t)n >= sizeof(buf)) {
    n = (int)sizeof(buf) - 1;
  }
  return ftp_proc_xfer_write_raw(x, buf, (size_t)n);
}

static int
ftp_proc_table_size(const ftp_proc_info_t *items, size_t count,
                    size_t *size_out) {
  size_t total = 0;
  size_t i;
  char line[512];
  int n;

  n = snprintf(line, sizeof(line),
               "%8s %9s %8s %8s %8s %10s %6s  %-10s %13s  %s\r\n",
               "PID", "PPID", "PGID", "SID", "UID", "State",
               "AppId", "TitleId", "Memory (MiB)", "Command");
  if(n > 0) {
    total += (size_t)n;
  }
  for(i=0; i<count; i++) {
    n = snprintf(line, sizeof(line),
                 "%8jd %9jd %8jd %8jd %8ju %10s   %04x  %-10s %6.1f / %6.1f  %s\r\n",
                 (intmax_t)items[i].pid,
                 (intmax_t)items[i].ppid,
                 (intmax_t)items[i].pgid,
                 (intmax_t)items[i].sid,
                 (uintmax_t)items[i].uid,
                 items[i].state,
                 (unsigned)items[i].app_id & 0xffff,
                 items[i].title_id,
                 ftp_proc_mib(items[i].rss_bytes),
                 ftp_proc_mib(items[i].vsize_bytes),
                 items[i].command[0] ? items[i].command : "-");
    if(n > 0) {
      total += (size_t)n;
    }
  }

  *size_out = total;
  return 0;
}

static int
ftp_proc_calc_table_size(size_t *size_out) {
  ftp_proc_info_t *items = NULL;
  size_t count = 0;
  int ret;

  if(ftp_proc_collect(&items, &count)) {
    return -1;
  }

  ret = ftp_proc_table_size(items, count, size_out);
  free(items);
  return ret;
}

static int
ftp_proc_format_all_list_line(char *buf, size_t bufsz, size_t table_size) {
  char timebuf[32];

  if(ftp_proc_format_list_time(time(NULL), timebuf, sizeof(timebuf))) {
    return -1;
  }
  if(snprintf(buf, bufsz, "-r--r--r-- 1 0 0 %ju %s _all_\r\n",
              (uintmax_t)table_size, timebuf) >= (int)bufsz) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

static int
ftp_proc_format_all_mlsd_line(char *buf, size_t bufsz, size_t table_size,
                              int leading_space) {
  char timebuf[32];

  if(ftp_proc_format_mdtm(time(NULL), timebuf, sizeof(timebuf))) {
    return -1;
  }
  if(snprintf(buf, bufsz,
              "%smodify=%s;type=file;size=%ju;perm=rd;unique=proc-all; _all_\r\n",
              leading_space ? " " : "", timebuf, (uintmax_t)table_size) >=
     (int)bufsz) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

int
ftp_proc_cmd_DELE(ftp_env_t *env, const char *path) {
  pid_t pid;

  if(ftp_proc_is_root_path(path) || ftp_proc_is_all_path(path)) {
    return ftp_active_printf(env, "550 Not a regular file\r\n");
  }
  if(ftp_proc_parse_pid_path(path, &pid)) {
    return ftp_active_printf(env, "550 No such process\r\n");
  }
  if(pid <= 0) {
    return ftp_active_printf(env, "550 Refusing to kill PID 0\r\n");
  }
  if(kill(pid, SIGKILL)) {
    return ftp_perror(env);
  }
  return ftp_active_printf(env, "250 Process killed\r\n");
}

static int
ftp_proc_cmd_TEXT(ftp_env_t *env, const char *path) {
  ftp_proc_info_t *items = NULL;
  ftp_proc_info_t info;
  size_t count = 0;
  size_t i;
  ftp_proc_xfer_t x;
  int err;
  pid_t pid;

  if(!ftp_proc_is_root_path(path) && !ftp_proc_is_all_path(path) &&
     ftp_proc_parse_pid_path(path, &pid)) {
    return ftp_active_printf(env, "550 No such process\r\n");
  }

  err = ftp_proc_xfer_start(env, &x);
  if(err) {
    return err < 0 ? err : 0;
  }

  if(ftp_proc_is_root_path(path) || ftp_proc_is_all_path(path)) {
    if(ftp_proc_collect(&items, &count)) {
      (void)ftp_perror(env);
      x.failed = 1;
    } else {
      (void)ftp_proc_format_table_header(&x);
      for(i=0; i<count && !x.failed; i++) {
        (void)ftp_proc_format_table_row(&x, &items[i]);
      }
      free(items);
    }
  } else {
    if(ftp_proc_find(pid, &info)) {
      (void)ftp_perror(env);
      x.failed = 1;
    } else {
      (void)ftp_proc_write_detail(&x, &info);
    }
  }

  return ftp_proc_xfer_finish(env, &x);
}

int
ftp_proc_cmd_LIST(ftp_env_t *env, const char *path) {
  ftp_proc_info_t *items = NULL;
  ftp_proc_info_t info;
  size_t table_size = 0;
  size_t count = 0;
  size_t i;
  ftp_proc_xfer_t x;
  char all_line[128];
  int err;
  pid_t pid;

  if(ftp_proc_is_all_path(path)) {
    if(ftp_proc_calc_table_size(&table_size)) {
      return ftp_perror(env);
    }
    err = ftp_proc_xfer_start(env, &x);
    if(err) {
      return err < 0 ? err : 0;
    }
    if(ftp_proc_format_all_list_line(all_line, sizeof(all_line), table_size) == 0) {
      (void)ftp_proc_xfer_printf(&x, "%s", all_line);
    }
    return ftp_proc_xfer_finish(env, &x);
  }
  if(!ftp_proc_is_root_path(path) && ftp_proc_parse_pid_path(path, &pid)) {
    return ftp_active_printf(env, "550 No such process\r\n");
  }

  err = ftp_proc_xfer_start(env, &x);
  if(err) {
    return err < 0 ? err : 0;
  }

  if(ftp_proc_is_root_path(path)) {
    if(ftp_proc_collect(&items, &count)) {
      (void)ftp_perror(env);
      x.failed = 1;
    } else {
      if(ftp_proc_table_size(items, count, &table_size) == 0 &&
         ftp_proc_format_all_list_line(all_line, sizeof(all_line),
                                       table_size) == 0) {
        (void)ftp_proc_xfer_printf(&x, "%s", all_line);
      }
      for(i=0; i<count && !x.failed; i++) {
        char timebuf[32];
        char name[PATH_MAX];

        if(ftp_proc_format_list_time(items[i].start_time ? items[i].start_time : time(NULL),
                                     timebuf, sizeof(timebuf))) {
          continue;
        }
        ftp_proc_format_entry_name(&items[i], name, sizeof(name));
        (void)ftp_proc_xfer_printf(&x,
                                   "-r--r--r-- 1 %ju 0 %ju %s %s\r\n",
                                   (uintmax_t)items[i].uid,
                                   (uintmax_t)ftp_proc_detail_size(&items[i]),
                                   timebuf, name);
      }
      free(items);
    }
  } else {
    if(ftp_proc_find(pid, &info)) {
      (void)ftp_perror(env);
      x.failed = 1;
    } else {
      char timebuf[32];
      char name[PATH_MAX];

      if(!ftp_proc_format_list_time(info.start_time ? info.start_time : time(NULL),
                                    timebuf, sizeof(timebuf))) {
        ftp_proc_format_entry_name(&info, name, sizeof(name));
        (void)ftp_proc_xfer_printf(&x,
                                   "-r--r--r-- 1 %ju 0 %ju %s %s\r\n",
                                   (uintmax_t)info.uid,
                                   (uintmax_t)ftp_proc_detail_size(&info),
                                   timebuf, name);
      }
    }
  }

  return ftp_proc_xfer_finish(env, &x);
}

int
ftp_proc_cmd_NLST(ftp_env_t *env, const char *path) {
  ftp_proc_info_t *items = NULL;
  ftp_proc_info_t info;
  int have_single = 0;
  size_t count = 0;
  size_t i;
  ftp_proc_xfer_t x;
  int err;
  pid_t pid;

  if(ftp_proc_is_root_path(path)) {
    if(ftp_proc_collect(&items, &count)) {
      return ftp_perror(env);
    }
  } else if(ftp_proc_is_all_path(path)) {
    have_single = 1;
  } else if(ftp_proc_parse_pid_path(path, &pid) == 0) {
    if(ftp_proc_find(pid, &info)) {
      return ftp_perror(env);
    }
    have_single = 1;
  } else {
    return ftp_active_printf(env, "550 No such process\r\n");
  }

  err = ftp_proc_xfer_start(env, &x);
  if(err) {
    free(items);
    return err < 0 ? err : 0;
  }

  if(items) {
    if(ftp_proc_is_root_path(path)) {
      (void)ftp_proc_xfer_printf(&x, "_all_\r\n");
    }
    for(i=0; i<count && !x.failed; i++) {
      char name[PATH_MAX];

      ftp_proc_format_entry_name(&items[i], name, sizeof(name));
      (void)ftp_proc_xfer_printf(&x, "%s\r\n", name);
    }
    free(items);
  } else if(ftp_proc_is_all_path(path)) {
    (void)ftp_proc_xfer_printf(&x, "_all_\r\n");
  } else if(have_single) {
    char name[PATH_MAX];

    ftp_proc_format_entry_name(&info, name, sizeof(name));
    (void)ftp_proc_xfer_printf(&x, "%s\r\n", name);
  }

  return ftp_proc_xfer_finish(env, &x);
}

static int
ftp_proc_mlsd_line(char *buf, size_t bufsz, const ftp_proc_info_t *info,
                   int leading_space) {
  char timebuf[32];
  char name[PATH_MAX];
  time_t mtime = info->start_time ? info->start_time : time(NULL);

  if(ftp_proc_format_mdtm(mtime, timebuf, sizeof(timebuf))) {
    return -1;
  }
  ftp_proc_format_entry_name(info, name, sizeof(name));
  if(snprintf(buf, bufsz,
              "%smodify=%s;type=file;size=%ju;perm=rd;unique=proc-%jd; %s\r\n",
              leading_space ? " " : "",
              timebuf, (uintmax_t)ftp_proc_detail_size(info),
              (intmax_t)info->pid, name) >= (int)bufsz) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

int
ftp_proc_cmd_MLSD(ftp_env_t *env, const char *path) {
  ftp_proc_info_t *items = NULL;
  size_t count = 0;
  size_t i;
  ftp_proc_xfer_t x;
  int err;
  char line[PATH_MAX + 256];

  if(!ftp_proc_is_root_path(path)) {
    return ftp_active_printf(env, "550 Not a directory\r\n");
  }
  if(ftp_proc_collect(&items, &count)) {
    return ftp_perror(env);
  }

  err = ftp_proc_xfer_start(env, &x);
  if(err) {
    free(items);
    return err < 0 ? err : 0;
  }

  {
    size_t table_size = 0;

    if(ftp_proc_table_size(items, count, &table_size) == 0 &&
       ftp_proc_format_all_mlsd_line(line, sizeof(line), table_size, 0) == 0) {
      (void)ftp_proc_xfer_printf(&x, "%s", line);
    }
  }

  for(i=0; i<count && !x.failed; i++) {
    if(ftp_proc_mlsd_line(line, sizeof(line), &items[i], 0)) {
      continue;
    }
    (void)ftp_proc_xfer_printf(&x, "%s", line);
  }

  free(items);
  return ftp_proc_xfer_finish(env, &x);
}

int
ftp_proc_cmd_MLST(ftp_env_t *env, const char *path) {
  ftp_proc_info_t info;
  pid_t pid;
  time_t now = time(NULL);
  char timebuf[32];
  char line[PATH_MAX + 256];

  if(ftp_proc_format_mdtm(now, timebuf, sizeof(timebuf))) {
    return ftp_active_printf(env, "550 MLST failed\r\n");
  }

  if(ftp_proc_is_root_path(path)) {
    if(snprintf(line, sizeof(line),
                " modify=%s;type=dir;size=0;perm=el;unique=proc-root; /proc\r\n",
                timebuf) >= (int)sizeof(line)) {
      return ftp_active_printf(env, "550 MLST failed\r\n");
    }
  } else if(ftp_proc_is_all_path(path)) {
    size_t size = 0;

    if(ftp_proc_calc_table_size(&size)) {
      return ftp_perror(env);
    }
    if(ftp_proc_format_all_mlsd_line(line, sizeof(line), size, 1)) {
      return ftp_active_printf(env, "550 MLST failed\r\n");
    }
  } else if(ftp_proc_parse_pid_path(path, &pid) == 0) {
    if(ftp_proc_find(pid, &info)) {
      return ftp_perror(env);
    }
    if(ftp_proc_mlsd_line(line, sizeof(line), &info, 1)) {
      return ftp_active_printf(env, "550 MLST failed\r\n");
    }
  } else {
    return ftp_active_printf(env, "550 No such process\r\n");
  }

  if(ftp_active_printf(env, "250-Listing\r\n")) {
    return -1;
  }
  if(ftp_active_printf(env, "%s", line)) {
    return -1;
  }
  return ftp_active_printf(env, "250 End\r\n");
}

int
ftp_proc_cmd_RETR(ftp_env_t *env, const char *path) {
  return ftp_proc_cmd_TEXT(env, path);
}

int
ftp_proc_cmd_SIZE(ftp_env_t *env, const char *path) {
  ftp_proc_info_t info;
  size_t size = 0;
  pid_t pid;

  if(ftp_proc_is_root_path(path) || ftp_proc_is_all_path(path)) {
    if(ftp_proc_calc_table_size(&size)) {
      return ftp_perror(env);
    }
    return ftp_active_printf(env, "213 %ju\r\n", (uintmax_t)size);
  }

  if(ftp_proc_parse_pid_path(path, &pid)) {
    return ftp_active_printf(env, "550 No such process\r\n");
  }
  if(ftp_proc_find(pid, &info)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "213 %ju\r\n",
                           (uintmax_t)ftp_proc_detail_size(&info));
}

int
ftp_proc_cmd_MDTM(ftp_env_t *env, const char *path) {
  pid_t pid;
  ftp_proc_info_t info;
  time_t mtime = time(NULL);
  char timebuf[32];

  if(!ftp_proc_is_root_path(path) && !ftp_proc_is_all_path(path)) {
    if(ftp_proc_parse_pid_path(path, &pid)) {
      return ftp_active_printf(env, "550 No such process\r\n");
    }
    if(ftp_proc_find(pid, &info)) {
      return ftp_perror(env);
    }
    if(info.start_time > 0) {
      mtime = info.start_time;
    }
  }

  if(ftp_proc_format_mdtm(mtime, timebuf, sizeof(timebuf))) {
    return ftp_active_printf(env, "550 MDTM failed\r\n");
  }
  return ftp_active_printf(env, "213 %s\r\n", timebuf);
}
