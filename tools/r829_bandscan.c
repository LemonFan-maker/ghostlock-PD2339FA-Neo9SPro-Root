/* r829_bandscan.c - measure the physical-page landscape the B-round L-gate depends on.
 *
 * The L-gate accepts only when the leaked order-3 page lands in a low-PA band
 * (observed: PA 520-643MB, i.e. dist 482-605MB from glk PA ~36.5MB).
 * That band is a *physical* property of where the buddy freelist hands out
 * order-3 blocks. This tool reads /proc/kpageflags (needs CAP_SYS_ADMIN -> root)
 * and reports, per PA window, how many free (KPF_BUDDY) pages and free order-3
 * aligned blocks exist. Read-only. Never writes anything.
 *
 * Build: aarch64-linux-android21-clang -static -O2
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>

#define PAGE_SHIFT 12
#define KB(x) ((x) * 1024ULL)

/* /proc/kpageflags bits (linux/kernel-page-flags.h) */
#define KPF_BUDDY 10

static uint64_t g_min_free = UINT64_MAX, g_max_free = 0;
static uint64_t g_free_total = 0;

/* order-3 (32KB = 8 pages) aligned block is free iff all 8 consecutive PFNs are free */
static uint64_t o3_aligned_free_in(uint64_t lo_pfn, uint64_t hi_pfn, const uint64_t *flags,
                                   uint64_t base_pfn, uint64_t n) {
    uint64_t cnt = 0;
    uint64_t start = (lo_pfn + 7) & ~7ULL;      /* first order-3 aligned PFN >= lo */
    for (uint64_t p = start; p + 8 <= hi_pfn; p += 8) {
        if (p < base_pfn || p + 8 > base_pfn + n) continue;
        uint64_t off = p - base_pfn;
        int all = 1;
        for (int i = 0; i < 8; i++) {
            if (!(flags[off + i] & (1ULL << KPF_BUDDY))) { all = 0; break; }
        }
        if (all) cnt++;
    }
    return cnt;
}

int main(int argc, char **argv) {
    /* PA windows in MB; default: 0-256, 256-512, 512-768 ("band"), 768-1024, ... */
    uint64_t max_mb = (argc > 1) ? strtoull(argv[1], NULL, 10) : 2048;

    int fd = open("/proc/kpageflags", O_RDONLY);
    if (fd < 0) { perror("open /proc/kpageflags (needs root)"); return 1; }

    uint64_t n = max_mb * 1024ULL * 1024ULL / 4096ULL;   /* pages to read */
    uint64_t *flags = calloc(n, sizeof(uint64_t));
    if (!flags) { perror("calloc"); return 1; }

    uint64_t got = 0;
    while (got < n) {
        ssize_t r = pread(fd, flags + got, (n - got) * sizeof(uint64_t), got * sizeof(uint64_t));
        if (r <= 0) { if (errno == 0 || r == 0) break; perror("pread"); break; }
        got += r / sizeof(uint64_t);
    }
    close(fd);
    printf("scanned_pages=%llu (PA 0..%lluMB)\n", (unsigned long long)got,
           (unsigned long long)(got * 4ULL / 1024ULL));

    for (uint64_t i = 0; i < got; i++) {
        if (flags[i] & (1ULL << KPF_BUDDY)) {
            if (i < g_min_free) g_min_free = i;
            if (i > g_max_free) g_max_free = i;
            g_free_total++;
        }
    }
    printf("free_pages_total=%llu (%lluMB)  first_free_pfn=%llu (PA %lluMB)  last_free_pfn=%llu (PA %lluMB)\n",
           (unsigned long long)g_free_total, (unsigned long long)(g_free_total * 4ULL / 1024ULL),
           (unsigned long long)(g_min_free == UINT64_MAX ? 0 : g_min_free),
           (unsigned long long)(g_min_free == UINT64_MAX ? 0 : g_min_free * 4ULL / 1024ULL),
           (unsigned long long)g_max_free, (unsigned long long)(g_max_free * 4ULL / 1024ULL));

    /* 64MB-grained free-page histogram over the scanned range */
    printf("\nPA window (MB)      free_pages   free_MB   free_O3_blocks\n");
    for (uint64_t mb = 0; mb < got * 4ULL / 1024ULL; mb += 64) {
        uint64_t lo = mb * 1024ULL / 4ULL, hi = (mb + 64) * 1024ULL / 4ULL;
        if (hi > got) hi = got;
        uint64_t c = 0;
        for (uint64_t p = lo; p < hi; p++) if (flags[p] & (1ULL << KPF_BUDDY)) c++;
        uint64_t o3 = o3_aligned_free_in(lo, hi, flags, 0, got);
        printf("%6llu-%-6llu %12llu %9llu %14llu%s\n",
               (unsigned long long)mb, (unsigned long long)(mb + 64),
               (unsigned long long)c, (unsigned long long)(c * 4ULL / 1024ULL),
               (unsigned long long)o3,
               (mb >= 512 && mb < 768) ? "   <== L-gate band" : "");
    }
    free(flags);
    return 0;
}
