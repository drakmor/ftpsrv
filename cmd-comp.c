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
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cmd.h"

#if defined(__PROSPERO__) || defined(__ORBIS__)

#ifndef SCE_KERNEL_SET_REGULAR_FILE
#define SCE_KERNEL_SET_REGULAR_FILE 0
#endif

#ifndef SCE_KERNEL_SET_COMPRESS_FILE
#define SCE_KERNEL_SET_COMPRESS_FILE 1
#endif

#ifndef SCE_KERNEL_COMPRESS_FILE_MAGIC
#define SCE_KERNEL_COMPRESS_FILE_MAGIC 0x43534650U
#endif

#define SCE_KERNEL_ERROR_EBADF  (-2147352567)
#define SCE_KERNEL_ERROR_EPERM  (-2147352562)
#define SCE_KERNEL_ERROR_EIO    (-2147352571)
#define SCE_KERNEL_ERROR_EINVAL (-2147352554)
#define SCE_KERNEL_ERROR_ENOTTY (-2147352551)
#define SCE_KERNEL_ERROR_ENODEV (-2147352557)

extern int sceKernelSetCompressionAttribute(int fd, int flag);

static int
ftp_parse_comp_args(const char *arg, int *flag, const char **path) {
  const char *p = arg;
  size_t len;

  if(!arg || !flag || !path) {
    return -1;
  }

  p += strspn(p, " ");
  if(!*p) {
    return -1;
  }

  len = strcspn(p, " ");
  if(!len) {
    return -1;
  }

  if((len == 2 && !strncasecmp(p, "ON", len)) ||
     (len == 1 && p[0] == '1')) {
    *flag = SCE_KERNEL_SET_COMPRESS_FILE;
  } else if((len == 3 && !strncasecmp(p, "OFF", len)) ||
            (len == 1 && p[0] == '0')) {
    *flag = SCE_KERNEL_SET_REGULAR_FILE;
  } else {
    return -1;
  }

  p += len;
  p += strspn(p, " ");
  if(!*p) {
    return -1;
  }

  *path = p;
  return 0;
}

static int
ftp_comp_set_errno(int ret) {
  switch(ret) {
  case SCE_KERNEL_ERROR_EBADF:
    errno = EBADF;
    break;
  case SCE_KERNEL_ERROR_EPERM:
    errno = EPERM;
    break;
  case SCE_KERNEL_ERROR_EIO:
    errno = EIO;
    break;
  case SCE_KERNEL_ERROR_EINVAL:
    errno = EINVAL;
    break;
  case SCE_KERNEL_ERROR_ENOTTY:
    errno = ENOTTY;
    break;
  case SCE_KERNEL_ERROR_ENODEV:
    errno = ENODEV;
    break;
  default:
    errno = EIO;
    break;
  }

  return -1;
}

static int
ftp_comp_check_magic(int fd) {
  uint32_t magic = 0;

  if(read(fd, &magic, sizeof(magic)) != (ssize_t)sizeof(magic)) {
    if(errno == 0) {
      errno = EINVAL;
    }
    return -1;
  }
  if(magic != SCE_KERNEL_COMPRESS_FILE_MAGIC) {
    errno = EINVAL;
    return -1;
  }
  if(lseek(fd, 0, SEEK_SET) < 0) {
    return -1;
  }

  return 0;
}

int
ftp_cmd_COMP(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  const char *path = NULL;
  struct stat st;
  int fd;
  int flag = 0;
  int ret;
  int oflags = O_RDONLY;
#ifdef O_CLOEXEC
  oflags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
  oflags |= O_NOFOLLOW;
#endif

  if(ftp_parse_comp_args(arg, &flag, &path) != 0) {
    return ftp_active_printf(env, "501 Usage: COMP <ON|OFF> <PATH>\r\n");
  }
  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), path) != 0) {
    return ftp_perror(env);
  }
  if(lstat(pathbuf, &st) != 0) {
    return ftp_perror(env);
  }
  if(!S_ISREG(st.st_mode)) {
    return ftp_active_printf(env, "550 Not a regular file\r\n");
  }
  if(flag == SCE_KERNEL_SET_COMPRESS_FILE &&
     (st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH))) {
    if(chmod(pathbuf, st.st_mode & ~(S_IWUSR | S_IWGRP | S_IWOTH)) != 0) {
      return ftp_perror(env);
    }
  }

  fd = open(pathbuf, oflags);
  if(fd < 0) {
    return ftp_perror(env);
  }

  if(flag == SCE_KERNEL_SET_COMPRESS_FILE && ftp_comp_check_magic(fd) != 0) {
    close(fd);
    return ftp_active_printf(env,
                             "550 File does not have PFS compression magic\r\n");
  }

  ret = sceKernelSetCompressionAttribute(fd, flag);
  close(fd);
  if(ret != 0) {
    ftp_comp_set_errno(ret);
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "200 Compression attribute %s for %s\r\n",
                           flag ? "enabled" : "disabled", pathbuf);
}

#else

int
ftp_cmd_COMP(ftp_env_t *env, const char* arg) {
  return ftp_cmd_unavailable(env, arg);
}

#endif


/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/
