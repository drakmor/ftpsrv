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

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "io.h"
#include "self.h"
#include "sha256.h"

#define SELF_FSELF_KEY_TYPE 0x101u
#define SELF_FSELF_ATTRS 0x12u
#define SELF_FSELF_FLAGS 0x22u
#define SELF_APP_KEY_TYPE 0x10000301u
#define SELF_APP_ATTRS 0x32u
#define SELF_APP_FLAGS 0x52u
#define PT_SCE_DYNLIBDATA 0x61000000u
#define PT_SCE_RELRO 0x61000010u
#define PT_SCE_COMMENT 0x6fffff00u
#define PT_SCE_VERSION 0x6fffff01u

#ifndef MAP_ANON
#define MAP_ANON MAP_ANONYMOUS
#endif

/**
 * This global lock is used to address race conditions that may occur when
 * threads atempt to read several SELF files at the same time.
 **/
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

static int
self_is_fself_header(const self_head_t *head) {
  if(!head) {
    return 0;
  }
  if(head->key_type == SELF_FSELF_KEY_TYPE) {
    return 1;
  }
  if(head->attrs == SELF_FSELF_ATTRS && head->flags == SELF_FSELF_FLAGS) {
    return 1;
  }
  if(head->key_type == SELF_APP_KEY_TYPE) {
    return 1;
  }
  if(head->attrs == SELF_APP_ATTRS && head->flags == SELF_APP_FLAGS) {
    return 1;
  }
  return 0;
}

static int
self_require_decryptable(const self_head_t *head) {
  if(self_is_fself_header(head)) {
    return 0;
  }
  errno = EACCES;
  return -1;
}

static int
self_phdr_is_copyable(const Elf64_Phdr *phdr) {
  if(!phdr || !phdr->p_filesz) {
    return 0;
  }
  switch(phdr->p_type) {
  case PT_LOAD:
  case PT_SCE_DYNLIBDATA:
  case PT_SCE_RELRO:
  case PT_SCE_COMMENT:
    return 1;
  default:
    break;
  }
  return 0;
}

static int
self_phdr_is_version(const Elf64_Phdr *phdr) {
  return phdr && phdr->p_type == PT_SCE_VERSION;
}

static int
self_ext_eq(const char *ext, const char *want) {
  if(!ext || !want) {
    return 0;
  }
  return strcasecmp(ext, want) == 0;
}

static int
self_decode_elf_buffer(int self_fd, uint8_t **out_buf, size_t *out_size,
                       int verify) {
  self_exinfo_t extinfo;
  self_entry_t *entries = NULL;
  Elf64_Phdr *phdrs = NULL;
  self_head_t head;
  Elf64_Ehdr ehdr;
  uint8_t *buf = MAP_FAILED;
  size_t elf_size = 0;
  size_t map_size = 0;
  int version_index = -1;
  off_t elf_off;
  off_t extinfo_off;
  struct stat st;
  int err = -1;

  if(!out_buf || !out_size) {
    errno = EINVAL;
    return -1;
  }
  *out_buf = NULL;
  *out_size = 0;

  if(lseek(self_fd, 0, SEEK_SET) < 0) {
    return -1;
  }

  if(io_nread(self_fd, &head, sizeof(head))) {
    return -1;
  }
  if(head.magic != SELF_PS4_MAGIC && head.magic != SELF_PS5_MAGIC) {
    errno = ENOEXEC;
    return -1;
  }
  if(self_require_decryptable(&head)) {
    return -1;
  }

  if(!(entries=calloc(head.num_entries, sizeof(self_entry_t)))) {
    goto cleanup;
  }
  if(io_nread(self_fd, entries, head.num_entries * sizeof(self_entry_t))) {
    goto cleanup;
  }

  if((elf_off=lseek(self_fd, 0, SEEK_CUR)) < 0) {
    goto cleanup;
  }

  if(io_nread(self_fd, &ehdr, sizeof(ehdr))) {
    goto cleanup;
  }
  if(ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' ||
     ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F') {
    errno = ENOEXEC;
    goto cleanup;
  }

  if(lseek(self_fd, elf_off + ehdr.e_phoff, SEEK_SET) < 0) {
    goto cleanup;
  }

  if(!(phdrs=calloc(ehdr.e_phnum, sizeof(Elf64_Phdr)))) {
    goto cleanup;
  }
  for(int i=0; i<ehdr.e_phnum; i++) {
    uint64_t end;
    if(io_nread(self_fd, &phdrs[i], sizeof(phdrs[i]))) {
      goto cleanup;
    }
    end = phdrs[i].p_offset + phdrs[i].p_filesz;
    if(end > SIZE_MAX) {
      errno = EOVERFLOW;
      goto cleanup;
    }
    if(end > elf_size) {
      elf_size = (size_t)end;
    }
    if(self_phdr_is_version(&phdrs[i])) {
      version_index = i;
    }
  }

  if(!elf_size) {
    errno = EIO;
    goto cleanup;
  }

  buf = mmap(NULL, elf_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANON, -1, 0);
  if(buf == MAP_FAILED) {
    goto cleanup;
  }
  map_size = elf_size;

  for(int i=0; i<ehdr.e_phnum; i++) {
    Elf64_Phdr *phdr = &phdrs[i];
    self_entry_t *entry = NULL;
    int is_enc = 0;
    int is_comp = 0;
    uint64_t end;

    if(!self_phdr_is_copyable(phdr)) {
      continue;
    }

    for(int j=0; j<head.num_entries; j++) {
      if(entries[j].props.segment_index == i &&
         entries[j].props.has_blocks) {
        entry = &entries[j];
        is_enc = entry->props.is_encrypted ? 1 : 0;
        is_comp = entry->props.is_compressed ? 1 : 0;
        break;
      }
    }
    if(!entry) {
      continue;
    }

    end = phdr->p_offset + phdr->p_filesz;
    if(end > elf_size) {
      errno = EIO;
      goto cleanup;
    }

    if(is_enc || is_comp) {
      uint8_t *data = MAP_FAILED;

      pthread_mutex_lock(&g_mutex);
      data = self_map_segment(self_fd, phdr, (size_t)i);
      if(data == MAP_FAILED) {
        pthread_mutex_unlock(&g_mutex);
        goto cleanup;
      }
      if(phdr->p_filesz && mlock(data, phdr->p_filesz)) {
        if(errno == ENOMEM
#ifdef EPERM
           || errno == EPERM
#endif
#ifdef EACCES
           || errno == EACCES
#endif
        ) {
          errno = EACCES;
        }
        munmap(data, phdr->p_filesz);
        pthread_mutex_unlock(&g_mutex);
        goto cleanup;
      }
      memcpy(buf + (size_t)phdr->p_offset, data, phdr->p_filesz);
      if(phdr->p_filesz) {
        (void)munlock(data, phdr->p_filesz);
      }
      munmap(data, phdr->p_filesz);
      pthread_mutex_unlock(&g_mutex);
    } else {
      if(io_pread(self_fd, buf + (size_t)phdr->p_offset, phdr->p_filesz,
                  (off_t)entry->offset)) {
        goto cleanup;
      }
    }
  }

  if(version_index >= 0) {
    Elf64_Phdr *phdr = &phdrs[version_index];
    if(phdr->p_filesz) {
      off_t self_off;
      if(!fstat(self_fd, &st)) {
        self_off = st.st_size - (off_t)phdr->p_filesz;
        if(self_off >= 0) {
          (void)io_pread(self_fd, buf + (size_t)phdr->p_offset, phdr->p_filesz,
                         self_off);
        }
      }
    }
  }

  memcpy(buf, &ehdr, sizeof(ehdr));
  {
    size_t phdrs_size = (size_t)ehdr.e_phnum * sizeof(phdrs[0]);
    if(ehdr.e_phoff + phdrs_size > elf_size) {
      errno = EIO;
      goto cleanup;
    }
    memcpy(buf + (size_t)ehdr.e_phoff, phdrs, phdrs_size);
  }

  if(verify) {
    uint8_t hash[SHA256_BLOCK_SIZE];
    SHA256_CTX sha;

    extinfo_off = elf_off + (off_t)ehdr.e_phoff +
                  (off_t)ehdr.e_phnum * (off_t)sizeof(Elf64_Phdr);
    extinfo_off = (extinfo_off + (0x10 - 1)) & ~(off_t)(0x10 - 1);
    if(io_pread(self_fd, &extinfo, sizeof(extinfo), extinfo_off)) {
      goto cleanup;
    }
    sha256_init(&sha);
    sha256_update(&sha, buf, elf_size);
    sha256_final(&sha, hash);
    if(memcmp(hash, extinfo.digest, sizeof(hash))) {
      errno = EBADMSG;
      goto cleanup;
    }
  }

  *out_buf = buf;
  *out_size = elf_size;
  buf = MAP_FAILED;
  err = 0;

cleanup:
  if(buf != MAP_FAILED) {
    munmap(buf, map_size);
  }
  free(entries);
  free(phdrs);
  return err;
}

int
self_decode_elf(int self_fd, uint8_t **out_buf, size_t *out_size, int verify) {
  return self_decode_elf_buffer(self_fd, out_buf, out_size, verify);
}

static size_t
self_get_elfsize_fd(int fd) {
  self_head_t head;
  Elf64_Ehdr ehdr;
  Elf64_Phdr phdr;
  off_t elf_off;
  size_t size = 0;
 
  if(io_nread(fd, &head, sizeof(head))) {
    return 0;
  }
 
  if(head.magic != SELF_PS4_MAGIC && head.magic != SELF_PS5_MAGIC) {
    return 0;
  }
 
  if(lseek(fd, head.num_entries * sizeof(self_entry_t), SEEK_CUR) < 0) {
    return 0;
  }
 
  elf_off = lseek(fd, 0, SEEK_CUR);
  if(io_nread(fd, &ehdr, sizeof(ehdr))) {
    return 0;
  }
 
  if(ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' ||
     ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F') {
    return 0;
  }
 
  if(lseek(fd, elf_off + ehdr.e_phoff, SEEK_SET) < 0) {
    return 0;
  }
 
  for(int i=0; i<ehdr.e_phnum; i++) {
    if(io_nread(fd, &phdr, sizeof(phdr))) {
      return 0;
    }
    if(phdr.p_offset + phdr.p_filesz > size) {
      size = phdr.p_offset + phdr.p_filesz;
    }
  }
 
  return size;
}
 
 
size_t
self_get_elfsize(const char* path) {
  size_t size;
  int fd;
 
  if((fd=open(path, O_RDONLY, 0)) < 0) {
    return 0;
  }
 
  size = self_get_elfsize_fd(fd);
  close(fd);
 
  return size;
}
 
size_t
self_is_valid(const char* path) {
  const char* dot = strrchr(path, '.');

  if(!dot) {
    return 0;
  }

  if(!(self_ext_eq(dot, ".bin") || self_ext_eq(dot, ".elf")
       || self_ext_eq(dot, ".sprx") || self_ext_eq(dot, ".prx")
       || self_ext_eq(dot, ".self"))) {
    return 0;
  }

  return self_get_elfsize(path);
}

/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/
