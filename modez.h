#pragma once

#include <stddef.h>
#include <sys/types.h>

struct ftp_env;

#ifndef FTP_MODE_Z_LEVEL_DEFAULT
#define FTP_MODE_Z_LEVEL_DEFAULT 1
#endif

void ftp_mode_z_session_init(struct ftp_env *env);
int ftp_mode_z_xfer_start(struct ftp_env *env, int is_send);
int ftp_mode_z_xfer_finish(struct ftp_env *env, int success);
ssize_t ftp_mode_z_read(struct ftp_env *env, void *buf, size_t count);
int ftp_mode_z_write(struct ftp_env *env, const void *buf, size_t count);
