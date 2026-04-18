/* Copyright (C) 2026 John Törnblom

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

#ifdef KSTUFF_AUTOPAUSE

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>

#include <ps5/kernel.h>

#include "kstuff_autopause.h"
#include "log.h"

#ifndef KSTUFF_AUTOPAUSE_IDLE_SEC
#define KSTUFF_AUTOPAUSE_IDLE_SEC 5
#endif

#ifndef KSTUFF_AUTOPAUSE_OPTION
#define KSTUFF_AUTOPAUSE_OPTION 2
#endif

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  intptr_t sysentvec;
  intptr_t sysentvec_ps4;
  struct timespec last_command_ts;
  int initialized;
  int available;
  int managing;
  int enabled;
  int have_last_command;
  int active_depth;
  int required_depth;
} kstuff_autopause_state_t;

static kstuff_autopause_state_t g_state = {
  .mutex = PTHREAD_MUTEX_INITIALIZER,
  .cond = PTHREAD_COND_INITIALIZER,
  .enabled = 1,
};

static int
kstuff_autopause_timespec_cmp(const struct timespec *lhs,
                              const struct timespec *rhs) {
  if(lhs->tv_sec != rhs->tv_sec) {
    return lhs->tv_sec < rhs->tv_sec ? -1 : 1;
  }
  if(lhs->tv_nsec != rhs->tv_nsec) {
    return lhs->tv_nsec < rhs->tv_nsec ? -1 : 1;
  }
  return 0;
}

static void
kstuff_autopause_deadline_from_last(const struct timespec *last,
                                    struct timespec *deadline) {
  *deadline = *last;
  deadline->tv_sec += KSTUFF_AUTOPAUSE_IDLE_SEC;
}

static void
kstuff_autopause_now(struct timespec *ts) {
  clock_gettime(CLOCK_REALTIME, ts);
}

static void
kstuff_autopause_signal_locked(void) {
  pthread_cond_signal(&g_state.cond);
}

static int
kstuff_autopause_read_actual_locked(void) {
  uint16_t ps5 = 0;
  uint16_t ps4 = 0;

  if(KSTUFF_AUTOPAUSE_OPTION == 1) {
    if(!g_state.sysentvec) {
      errno = EINVAL;
      return -1;
    }
    ps5 = (uint16_t)kernel_getshort(g_state.sysentvec + 14);
    if(ps5 == 0xdeb7) {
      return 1;
    }
    if(ps5 == 0xffff) {
      return 0;
    }
    errno = EINVAL;
    return -1;
  }

  if(KSTUFF_AUTOPAUSE_OPTION == 2) {
    if(!g_state.sysentvec_ps4) {
      errno = EINVAL;
      return -1;
    }
    ps4 = (uint16_t)kernel_getshort(g_state.sysentvec_ps4 + 14);
    if(ps4 == 0xdeb7) {
      return 1;
    }
    if(ps4 == 0xffff) {
      return 0;
    }
    errno = EINVAL;
    return -1;
  }

  if(KSTUFF_AUTOPAUSE_OPTION == 3) {
    if(!g_state.sysentvec || !g_state.sysentvec_ps4) {
      errno = EINVAL;
      return -1;
    }
    ps5 = (uint16_t)kernel_getshort(g_state.sysentvec + 14);
    ps4 = (uint16_t)kernel_getshort(g_state.sysentvec_ps4 + 14);
    if(ps5 == 0xdeb7 && ps4 == 0xdeb7) {
      return 1;
    }
    if(ps5 == 0xffff && ps4 == 0xffff) {
      return 0;
    }
    errno = EINVAL;
    return -1;
  }

  errno = EINVAL;
  return -1;
}

static void
kstuff_autopause_detach_locked(int actual_enabled) {
  g_state.managing = 0;
  g_state.have_last_command = 0;
  g_state.active_depth = 0;
  g_state.required_depth = 0;
  g_state.enabled = actual_enabled ? 1 : 0;
  kstuff_autopause_signal_locked();
}

static int
kstuff_autopause_sync_locked(void) {
  int actual_enabled;

  if(!g_state.available || !g_state.managing) {
    return 0;
  }

  actual_enabled = kstuff_autopause_read_actual_locked();
  if(actual_enabled < 0) {
    kstuff_autopause_detach_locked(g_state.enabled);
    return -1;
  }
  if(actual_enabled != g_state.enabled) {
    kstuff_autopause_detach_locked(actual_enabled);
    return -1;
  }

  return 0;
}

static int
kstuff_autopause_apply_locked(int enabled) {
  intptr_t addr = 0;
  intptr_t value = enabled ? 0xdeb7 : 0xffff;
  intptr_t old_value = g_state.enabled ? 0xdeb7 : 0xffff;

  if(!g_state.available || !g_state.managing) {
    return 0;
  }
  if(g_state.enabled == enabled) {
    return 0;
  }

  if(KSTUFF_AUTOPAUSE_OPTION == 1) {
    addr = g_state.sysentvec;
    if(!addr) {
      errno = EINVAL;
      return -1;
    }
    if(kernel_setshort(addr + 14, value) != 0) {
      return -1;
    }
  } else if(KSTUFF_AUTOPAUSE_OPTION == 2) {
    addr = g_state.sysentvec_ps4;
    if(!addr) {
      errno = EINVAL;
      return -1;
    }
    if(kernel_setshort(addr + 14, value) != 0) {
      return -1;
    }
  } else if(KSTUFF_AUTOPAUSE_OPTION == 3) {
    if(!g_state.sysentvec || !g_state.sysentvec_ps4) {
      errno = EINVAL;
      return -1;
    }
    if(kernel_setshort(g_state.sysentvec + 14, value) != 0) {
      return -1;
    }
    if(kernel_setshort(g_state.sysentvec_ps4 + 14, value) != 0) {
      (void)kernel_setshort(g_state.sysentvec + 14, old_value);
      return -1;
    }
  } else {
    errno = EINVAL;
    return -1;
  }

  g_state.enabled = enabled;
  if(enabled) {
    FTP_LOG_PUTS("kstuff enabled");
  } else {
    FTP_LOG_PUTS("kstuff disabled");
  }
  return 0;
}

static int
kstuff_autopause_detach_after_apply_failure_locked(void) {
  int actual_enabled = kstuff_autopause_read_actual_locked();

  if(actual_enabled < 0) {
    actual_enabled = g_state.enabled;
  }

  kstuff_autopause_detach_locked(actual_enabled);
  return -1;
}

static int
kstuff_autopause_apply_or_detach_locked(int enabled) {
  if(kstuff_autopause_apply_locked(enabled) == 0) {
    return 0;
  }

  return kstuff_autopause_detach_after_apply_failure_locked();
}

static void
kstuff_autopause_mark_command_locked(int disable_when_possible) {
  if(!g_state.available || !g_state.managing) {
    return;
  }
  if(kstuff_autopause_sync_locked() != 0) {
    return;
  }

  kstuff_autopause_now(&g_state.last_command_ts);
  g_state.have_last_command = 1;

  if(disable_when_possible && g_state.required_depth == 0) {
    (void)kstuff_autopause_apply_or_detach_locked(0);
  }

  kstuff_autopause_signal_locked();
}

static void
kstuff_autopause_refresh_locked(void) {
  struct timespec now;
  struct timespec deadline;
  int should_enable = 1;

  if(!g_state.available || !g_state.managing) {
    return;
  }
  if(kstuff_autopause_sync_locked() != 0) {
    return;
  }

  if(g_state.required_depth > 0) {
    should_enable = 1;
  } else if(g_state.active_depth > 0) {
    should_enable = 0;
  } else if(g_state.have_last_command) {
    kstuff_autopause_now(&now);
    kstuff_autopause_deadline_from_last(&g_state.last_command_ts, &deadline);
    should_enable = kstuff_autopause_timespec_cmp(&now, &deadline) >= 0;
    if(should_enable) {
      g_state.have_last_command = 0;
    }
  }

  (void)kstuff_autopause_apply_or_detach_locked(should_enable);
}

static void*
kstuff_autopause_thread(void *arg) {
  (void)arg;

  pthread_mutex_lock(&g_state.mutex);
  for(;;) {
    struct timespec deadline;

    kstuff_autopause_refresh_locked();

    if(!g_state.managing) {
      break;
    }
    if(g_state.required_depth > 0 ||
       g_state.active_depth > 0 ||
       !g_state.have_last_command) {
      pthread_cond_wait(&g_state.cond, &g_state.mutex);
      continue;
    }

    kstuff_autopause_deadline_from_last(&g_state.last_command_ts, &deadline);
    pthread_cond_timedwait(&g_state.cond, &g_state.mutex, &deadline);
  }

  pthread_mutex_unlock(&g_state.mutex);
  return NULL;
}

static int
kstuff_autopause_resolve_sysentvec(void) {
  switch(kernel_get_fw_version() & 0xffff0000) {
  case 0x1000000:
  case 0x1010000:
  case 0x1020000:
  case 0x1050000:
  case 0x1100000:
  case 0x1110000:
  case 0x1120000:
  case 0x1130000:
  case 0x1140000:
  case 0x2000000:
  case 0x2200000:
  case 0x2250000:
  case 0x2260000:
  case 0x2300000:
  case 0x2500000:
  case 0x2700000:
    errno = ENOSYS;
    return -1;

  case 0x3000000:
  case 0x3100000:
  case 0x3200000:
  case 0x3210000:
    g_state.sysentvec = KERNEL_ADDRESS_DATA_BASE + 0xca0cd8;
    g_state.sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xca0e50;
    break;

  case 0x4000000:
  case 0x4020000:
  case 0x4030000:
  case 0x4500000:
  case 0x4510000:
    g_state.sysentvec = KERNEL_ADDRESS_DATA_BASE + 0xd11bb8;
    g_state.sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xd11d30;
    break;

  case 0x5000000:
  case 0x5020000:
  case 0x5100000:
  case 0x5500000:
    g_state.sysentvec = KERNEL_ADDRESS_DATA_BASE + 0xe00be8;
    g_state.sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xe00d60;
    break;

  case 0x6000000:
  case 0x6020000:
  case 0x6500000:
    g_state.sysentvec = KERNEL_ADDRESS_DATA_BASE + 0xe210a8;
    g_state.sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xe21220;
    break;

  case 0x7000000:
  case 0x7010000:
    g_state.sysentvec = KERNEL_ADDRESS_DATA_BASE + 0xe21ab8;
    g_state.sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xe21c30;
    break;

  case 0x7200000:
  case 0x7400000:
  case 0x7600000:
  case 0x7610000:
    g_state.sysentvec = KERNEL_ADDRESS_DATA_BASE + 0xe21b78;
    g_state.sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xe21cf0;
    break;

  case 0x8000000:
  case 0x8200000:
  case 0x8400000:
  case 0x8600000:
    g_state.sysentvec = KERNEL_ADDRESS_DATA_BASE + 0xe21ca8;
    g_state.sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xe21e20;
    break;

  case 0x9000000:
  case 0x9050000:
  case 0x9200000:
  case 0x9400000:
  case 0x9600000:
    g_state.sysentvec = KERNEL_ADDRESS_DATA_BASE + 0xdba648;
    g_state.sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xdba7c0;
    break;

  case 0x10000000:
  case 0x10010000:
  case 0x10200000:
  case 0x10400000:
  case 0x10600000:
    g_state.sysentvec = KERNEL_ADDRESS_DATA_BASE + 0xdba6d8;
    g_state.sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xdba850;
    break;

  case 0x11000000:
  case 0x11200000:
    g_state.sysentvec = KERNEL_ADDRESS_DATA_BASE + 0xdcbc78;
    g_state.sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xdcbdf0;
    break;

  case 0x11400000:
  case 0x11600000:
    g_state.sysentvec = KERNEL_ADDRESS_DATA_BASE + 0xdcbc98;
    g_state.sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xdcbe10;
    break;

  case 0x12000000:
  case 0x12020000:
  case 0x12200000:
  case 0x12400000:
  case 0x12600000:
    g_state.sysentvec = KERNEL_ADDRESS_DATA_BASE + 0xdcc978;
    g_state.sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xdccaf0;
    break;

  default:
    errno = ENOTSUP;
    return -1;
  }

  return 0;
}

void
kstuff_autopause_init(void) {
  int err;
  pthread_t thread;

  pthread_mutex_lock(&g_state.mutex);
  if(g_state.initialized) {
    pthread_mutex_unlock(&g_state.mutex);
    return;
  }

  g_state.initialized = 1;
  err = kstuff_autopause_resolve_sysentvec();
  if(err == 0) {
    g_state.available = 1;
    err = kstuff_autopause_read_actual_locked();
    if(err != 1) {
      g_state.managing = 0;
      g_state.enabled = 0;
    } else {
      g_state.managing = 1;
    }
    if(g_state.managing) {
      if(pthread_create(&thread, NULL, kstuff_autopause_thread, NULL) == 0) {
        pthread_detach(thread);
      } else {
        kstuff_autopause_detach_locked(1);
      }
    }
  }
  pthread_mutex_unlock(&g_state.mutex);
}

void
kstuff_autopause_command_received(void) {
  pthread_mutex_lock(&g_state.mutex);
  kstuff_autopause_mark_command_locked(1);
  pthread_mutex_unlock(&g_state.mutex);
}

void
kstuff_autopause_command_received_required(void) {
  pthread_mutex_lock(&g_state.mutex);
  kstuff_autopause_mark_command_locked(0);
  pthread_mutex_unlock(&g_state.mutex);
}

void
kstuff_autopause_active_begin(void) {
  pthread_mutex_lock(&g_state.mutex);
  if(!g_state.managing) {
    pthread_mutex_unlock(&g_state.mutex);
    return;
  }
  if(kstuff_autopause_sync_locked() != 0) {
    pthread_mutex_unlock(&g_state.mutex);
    return;
  }
  g_state.active_depth += 1;
  if(g_state.required_depth == 0) {
    (void)kstuff_autopause_apply_or_detach_locked(0);
  }
  kstuff_autopause_signal_locked();
  pthread_mutex_unlock(&g_state.mutex);
}

void
kstuff_autopause_active_end(void) {
  pthread_mutex_lock(&g_state.mutex);
  if(!g_state.managing) {
    pthread_mutex_unlock(&g_state.mutex);
    return;
  }
  if(g_state.active_depth > 0) {
    g_state.active_depth -= 1;
  }
  kstuff_autopause_refresh_locked();
  kstuff_autopause_signal_locked();
  pthread_mutex_unlock(&g_state.mutex);
}

void
kstuff_autopause_required_begin(void) {
  pthread_mutex_lock(&g_state.mutex);
  if(!g_state.managing) {
    pthread_mutex_unlock(&g_state.mutex);
    return;
  }
  if(kstuff_autopause_sync_locked() != 0) {
    pthread_mutex_unlock(&g_state.mutex);
    return;
  }
  g_state.required_depth += 1;
  (void)kstuff_autopause_apply_or_detach_locked(1);
  kstuff_autopause_signal_locked();
  pthread_mutex_unlock(&g_state.mutex);
}

void
kstuff_autopause_required_end(void) {
  pthread_mutex_lock(&g_state.mutex);
  if(!g_state.managing) {
    pthread_mutex_unlock(&g_state.mutex);
    return;
  }
  if(g_state.required_depth > 0) {
    g_state.required_depth -= 1;
  }
  kstuff_autopause_refresh_locked();
  kstuff_autopause_signal_locked();
  pthread_mutex_unlock(&g_state.mutex);
}

#endif
