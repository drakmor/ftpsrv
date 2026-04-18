#pragma once

#ifdef KSTUFF_AUTOPAUSE
void kstuff_autopause_init(void);
void kstuff_autopause_command_received(void);
void kstuff_autopause_command_received_required(void);
void kstuff_autopause_active_begin(void);
void kstuff_autopause_active_end(void);
void kstuff_autopause_required_begin(void);
void kstuff_autopause_required_end(void);
#else
static inline void
kstuff_autopause_init(void) {
}

static inline void
kstuff_autopause_command_received(void) {
}

static inline void
kstuff_autopause_command_received_required(void) {
}

static inline void
kstuff_autopause_active_begin(void) {
}

static inline void
kstuff_autopause_active_end(void) {
}

static inline void
kstuff_autopause_required_begin(void) {
}

static inline void
kstuff_autopause_required_end(void) {
}
#endif
