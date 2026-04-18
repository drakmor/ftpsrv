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
#include <unistd.h>

#include "log.h"
#include "main-common.h"
#include "srv.h"

int
main(int argc, char* argv[]) {
  uint16_t port = 2121;
  int notify_user = 1;
  int rc;
  int c;

  while((c=getopt(argc, argv, "p:h")) != -1) {
    switch(c) {
    case 'p':
      if(ftp_parse_port_arg(optarg, &port) != 0) {
        ftp_print_usage(argv[0]);
        return 1;
      }
      break;

    case 'h':
      ftp_print_usage(argv[0]);
      return 0;

    default:
      ftp_print_usage(argv[0]);
      return 1;
    }
  }

  signal(SIGPIPE, SIG_IGN);

  while(1) {
    rc = ftp_serve(port, notify_user);
    if(rc == FTP_SERVE_BIND_FAILED) {
      return 1;
    }
    notify_user = 0;
    sleep(3);
  }

  return 0;
}


/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/
