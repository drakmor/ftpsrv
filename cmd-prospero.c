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
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/_iovec.h>
#include <sys/mount.h>

#include <ps5/kernel.h>

#include "cmd.h"
#include "self.h"


/**
 * Convenient macros for nmount.
 **/
#define IOVEC_SIZE(x) (sizeof(x) / sizeof(struct iovec))
#define IOVEC_ENTRY(x) {x ? x : 0, x ? strlen(x)+1 : 0}

/**
 * Parse "<hex_authid>" into an unsigned 64-bit value.
 **/
static int
ftp_parse_authid(const char *arg, uint64_t *out) {
  const char *p = arg;
  uintmax_t authid = 0;
  char *end = NULL;
  size_t digits = 0;

  if(!arg || !out) {
    return -1;
  }

  p += strspn(p, " ");
  if(!*p) {
    return -1;
  }

  if(p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
    p += 2;
  }

  digits = strspn(p, "0123456789abcdefABCDEF");
  if(!digits || digits > 16) {
    return -1;
  }
  if(p[digits] != '\0' && p[digits] != ' ') {
    return -1;
  }

  errno = 0;
  authid = strtoumax(p, &end, 16);
  if(errno == ERANGE || end != p + digits || authid > UINT64_MAX) {
    return -1;
  }

  p = end;
  p += strspn(p, " ");
  if(*p) {
    return -1;
  }

  *out = (uint64_t)authid;

  return 0;
}


/**
 * Remount read-only mount points with write permissions.
 **/
int
ftp_cmd_MTRW(ftp_env_t *env, const char* arg) {
  struct iovec iov_sys[] = {
    IOVEC_ENTRY("from"),      IOVEC_ENTRY("/dev/ssd0.system"),
    IOVEC_ENTRY("fspath"),    IOVEC_ENTRY("/system"),
    IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
    IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
    IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
    IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
    IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
  };

  struct iovec iov_sysex[] = {
    IOVEC_ENTRY("from"),      IOVEC_ENTRY("/dev/ssd0.system_ex"),
    IOVEC_ENTRY("fspath"),    IOVEC_ENTRY("/system_ex"),
    IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
    IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
    IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
    IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
    IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
  };

  if(nmount(iov_sys, IOVEC_SIZE(iov_sys), MNT_UPDATE)) {
    return ftp_perror(env);
  }

  if(nmount(iov_sysex, IOVEC_SIZE(iov_sysex), MNT_UPDATE)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "200 /system and /system_ex remounted\r\n");
}

/**
 * Change current process authid.
 **/
int
ftp_cmd_AUTHID(ftp_env_t *env, const char* arg) {
  uint64_t authid = 0;
  pid_t pid = getpid();

  if(ftp_parse_authid(arg, &authid)) {
    return ftp_active_printf(env, "501 Usage: AUTHID <HEX_AUTHID>\r\n");
  }

  if(kernel_set_ucred_authid(pid, authid)) {
    if(errno == 0) {
      errno = EPERM;
    }
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "200 AuthID set to 0x%016" PRIx64 "\r\n",
                           authid);
}


/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/
