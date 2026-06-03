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

#pragma once

#include <stddef.h>

#include "cmd.h"

int ftp_proc_is_root_path(const char *path);
int ftp_proc_is_path(const char *path);
int ftp_proc_is_root_listing(const char *dir_path);
int ftp_proc_hide_real_proc_entry(const char *dir_path, const char *name);

int ftp_proc_resolve_arg(ftp_env_t *env, const char *arg, int allow_opts,
                         char *path, size_t pathsz);
int ftp_proc_format_root_list_line(char *buf, size_t bufsz);
int ftp_proc_format_root_mlsd_line(char *buf, size_t bufsz);

int ftp_proc_cmd_DELE(ftp_env_t *env, const char *path);
int ftp_proc_cmd_LIST(ftp_env_t *env, const char *path);
int ftp_proc_cmd_NLST(ftp_env_t *env, const char *path);
int ftp_proc_cmd_MLSD(ftp_env_t *env, const char *path);
int ftp_proc_cmd_MLST(ftp_env_t *env, const char *path);
int ftp_proc_cmd_RETR(ftp_env_t *env, const char *path);
int ftp_proc_cmd_SIZE(ftp_env_t *env, const char *path);
int ftp_proc_cmd_MDTM(ftp_env_t *env, const char *path);
