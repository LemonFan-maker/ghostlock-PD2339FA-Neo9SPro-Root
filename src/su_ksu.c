#define KSU_INSTALL_MAGIC1 0xDEADBEEFu
#define KSU_INSTALL_MAGIC2 0xCAFEBABEu

#define KSU_IOCTL_GRANT_ROOT 0x00004b01u

#define __NR_reboot 142
#define __NR_ioctl 29
#define __NR_execve 221
#define __NR_exit 93
#define __NR_exit_group 94

typedef unsigned int __u32;
typedef long ssize_t;
typedef unsigned long size_t;

static long sys4(long n, long a1, long a2, long a3, long a4) {
  register long x8 __asm__("x8") = n;
  register long x0 __asm__("x0") = a1;
  register long x1 __asm__("x1") = a2;
  register long x2 __asm__("x2") = a3;
  register long x3 __asm__("x3") = a4;
  __asm__ volatile("svc 0"
                   : "+r"(x0)
                   : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                   : "memory", "cc");
  return x0;
}

static long sys3(long n, long a1, long a2, long a3) {
  return sys4(n, a1, a2, a3, 0);
}

static void fdputs(int fd, const char *s) {
  size_t len = 0;
  while (s[len]) {
    len++;
  }
  ssize_t off = 0;
  while ((size_t)off < len) {
    ssize_t n = sys3(64 , fd, (long)(s + off), len - (size_t)off);
    if (n <= 0) {
      return;
    }
    off += n;
  }
}

static void fdputdec(int fd, long v) {
  char buf[24];
  int i = (int)sizeof(buf);
  unsigned long u = (v < 0) ? (unsigned long)-(v + 1) + 1UL
                            : (unsigned long)v;
  do {
    buf[--i] = (char)('0' + (u % 10UL));
    u /= 10UL;
  } while (u);
  if (v < 0) {
    buf[--i] = '-';
  }
  fdputs(fd, buf + i);
}

static int streq(const char *a, const char *b) {
  while (*a && *a == *b) {
    a++;
    b++;
  }
  return *a == *b;
}

static int ksu_main(int argc, char **argv, char **envp) {
  const char *cmd = 0;
  if (argc >= 3 && streq(argv[1], "-c")) {
    cmd = argv[2];
  } else if (argc >= 2) {
    cmd = argv[1];
  }
  if (cmd == 0) {
    fdputs(2, "usage: su_ksu -c '<shell command>'\n");
    return 1;
  }

  int fd = 0;
  long r = sys4(__NR_reboot, (long)KSU_INSTALL_MAGIC1,
                (long)KSU_INSTALL_MAGIC2, 0, (long)&fd);
  if (fd <= 0) {
    fdputs(2, "su_ksu: supercall failed errno=");
    fdputdec(2, (r < 0) ? -r : 0);
    fdputs(2, "\n");
    return 1;
  }

  r = sys3(__NR_ioctl, fd, (long)KSU_IOCTL_GRANT_ROOT, 0);
  if (r < 0) {
    fdputs(2, "su_ksu: grant root failed errno=");
    fdputdec(2, -r);
    fdputs(2, "\n");
    return 1;
  }

  char *sh_argv[4];
  sh_argv[0] = (char *)"sh";
  sh_argv[1] = (char *)"-c";
  sh_argv[2] = (char *)cmd;
  sh_argv[3] = 0;
  r = sys3(__NR_execve, (long)"/system/bin/sh", (long)sh_argv, (long)envp);
  fdputs(2, "su_ksu: exec /system/bin/sh failed errno=");
  fdputdec(2, -r);
  fdputs(2, "\n");
  return 127;
}

__asm__(".text\n"
        ".globl _start\n"
        ".type _start, %function\n"
        "_start:\n"
        "  mov x0, sp\n"
        "  b ksu_start\n");

void ksu_start(long *sp) {
  long argc = sp[0];
  char **argv = (char **)(sp + 1);
  char **envp = argv + argc + 1;
  int code = ksu_main((int)argc, argv, envp);
  sys3(__NR_exit_group, code, 0, 0);
  sys3(__NR_exit, code, 0, 0);
  for (;;) {
  }
}
