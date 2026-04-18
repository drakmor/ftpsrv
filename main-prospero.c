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

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/sysctl.h>
#include <sys/syscall.h>

#include <ps5/kernel.h>

#include "kstuff_autopause.h"
#include "main-common.h"
#include "srv.h"
#include "log.h"


/**
 * Find the pid of a process with the given name.
 **/
static pid_t
find_pid(const char* name) {
  int mib[4] = {1, 14, 8, 0};
  pid_t mypid = getpid();
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    FTP_LOG_PERROR("sysctl");
    return -1;
  }

  if(!(buf=malloc(buf_size))) {
    FTP_LOG_PERROR("malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    FTP_LOG_PERROR("sysctl");
    free(buf);
    return -1;
  }

  for(uint8_t *ptr=buf; ptr<(buf+buf_size);) {
    int ki_structsize = *(int*)ptr;
    pid_t ki_pid = *(pid_t*)&ptr[72];
    char *ki_tdname = (char*)&ptr[447];

    ptr += ki_structsize;
    if(!strcmp(name, ki_tdname) && ki_pid != mypid) {
      pid = ki_pid;
    }
  }

  free(buf);

  return pid;
}


/**
 * Launch payload.
 **/
int
main(int argc, char* argv[]) {
  uint16_t port = 2121;
  int notify_user = 1;
  int rc;
  pid_t pid;
  int c;

  syscall(SYS_thr_set_name, -1, "ftpsrv.elf");

  while((c=getopt(argc, argv, "p:h")) != -1) {
    switch(c) {
    case 'p':
      if(ftp_parse_port_arg(optarg, &port) != 0) {
        ftp_print_usage(argv[0]);
        return EXIT_FAILURE;
      }
      break;

    case 'h':
      ftp_print_usage(argv[0]);
      return EXIT_SUCCESS;

    default:
      ftp_print_usage(argv[0]);
      return EXIT_FAILURE;
    }
  }

  while((pid=find_pid("ftpsrv.elf")) > 0) {
    if(kill(pid, SIGKILL)) {
      FTP_LOG_PERROR("kill");
      return EXIT_FAILURE;
    }
    sleep(1);
  }

  signal(SIGPIPE, SIG_IGN);

  // change authid so certain character devices can be read, e.g.,
  // /dev/sflash0
  pid = getpid();
  if(kernel_set_ucred_authid(pid, 0x4801000000000013L)) {
    FTP_LOG_PUTS("Unable to change AuthID");
    return EXIT_FAILURE;
  }

#ifdef KSTUFF_AUTOPAUSE
  kstuff_autopause_init();
#endif

  while(1) {
    rc = ftp_serve(port, notify_user);
    if(rc == FTP_SERVE_BIND_FAILED) {
      return EXIT_FAILURE;
    }
    notify_user = 0;
    sleep(3);
  }

  return EXIT_SUCCESS;
}


/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/
