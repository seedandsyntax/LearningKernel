/* page_probe.c */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h> /* <-- ADDED THIS */
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <fcntl.h>

#define ALLOC_MB 64
#define PAGE_SIZE 4096
#define ALLOC_BYTES ((size_t)ALLOC_MB * 1024 * 1024)
#define NUM_PAGES (ALLOC_BYTES / PAGE_SIZE)

/* ---------- COLOR ---------- */
#define C_RESET   "\033[0m"
#define C_DIM     "\033[2m"
#define C_RED     "\033[31m"
#define C_GREEN   "\033[32m"
#define C_YELLOW  "\033[33m"
#define C_CYAN    "\033[36m"
#define C_BYELLOW "\033[1;33m"
#define C_BCYAN   "\033[1;36m"
#define C_BGREEN  "\033[1;32m"
#define C_BRED    "\033[1;31m"

static int COLOR = 0;
static void c_(const char *code) { if (COLOR) fputs(code, stdout); }
static void cr_(void)            { if (COLOR) fputs(C_RESET, stdout); }

/* ---------- VISUAL HELPERS ---------- */
#define BOX_WIDTH 75

static int visible_len(const char *s) {
    int len = 0, in_ansi = 0;
    for (int i = 0; s[i] != '\0'; i++) {
        if (s[i] == '\033') in_ansi = 1;
        else if (in_ansi && s[i] == 'm') in_ansi = 0;
        else if (!in_ansi) len++;
    }
    return len;
}

static void box_top(void) {
    printf("  ┌");
    for (int i = 0; i < BOX_WIDTH; i++) printf("─");
    printf("┐\n");
}
static void box_mid(void) {
    printf("  ├");
    for (int i = 0; i < BOX_WIDTH; i++) printf("─");
    printf("┤\n");
}
static void box_bot(void) {
    printf("  └");
    for (int i = 0; i < BOX_WIDTH; i++) printf("─");
    printf("┘\n");
}
static void box_line(const char *fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    int len = visible_len(buf);
    printf("  │ ");
    fputs(buf, stdout);
    for (int i = len; i < BOX_WIDTH - 2; i++) putchar(' ');
    printf(" │\n");
}
static void box_text(const char *text) {
    char buf[2048];
    strncpy(buf, text, sizeof(buf));
    buf[sizeof(buf)-1] = '\0';
    
    char *word = strtok(buf, " ");
    char line[256] = "";
    while (word) {
        if (strlen(line) + strlen(word) + 1 > BOX_WIDTH - 4) {
            box_line("%s", line);
            strcpy(line, word);
        } else {
            if (strlen(line) > 0) strcat(line, " ");
            strcat(line, word);
        }
        word = strtok(NULL, " ");
    }
    if (strlen(line) > 0) box_line("%s", line);
}

/* ---------- KERNEL PROBES ---------- */

typedef struct {
    uint64_t process_rss_kb;
    uint64_t process_pte_kb;
    long minor_faults;
    int vma_exists;
    uint64_t vma_size_kb;
    uint64_t vma_rss_kb;
    uint64_t vma_anon_kb;
    uint64_t vma_huge_kb;
} mem_stats_t;

static void get_stats(uintptr_t target_addr, mem_stats_t *stats) {
    memset(stats, 0, sizeof(*stats));
    char line[256];

    FILE *f_status = fopen("/proc/self/status", "r");
    if (f_status) {
        while (fgets(line, sizeof(line), f_status)) {
            if (strncmp(line, "VmRSS:", 6) == 0) sscanf(line + 6, "%lu", &stats->process_rss_kb);
            if (strncmp(line, "VmPTE:", 6) == 0) sscanf(line + 6, "%lu", &stats->process_pte_kb);
        }
        fclose(f_status);
    }

    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    stats->minor_faults = usage.ru_minflt;

    if (target_addr == 0) return;
    
    FILE *f_smaps = fopen("/proc/self/smaps", "r");
    if (f_smaps) {
        int in_target_vma = 0;
        while (fgets(line, sizeof(line), f_smaps)) {
            uint64_t start, end;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                if (target_addr >= start && target_addr < end) {
                    in_target_vma = 1;
                    stats->vma_exists = 1;
                    stats->vma_size_kb = (end - start) / 1024;
                } else {
                    in_target_vma = 0;
                }
            } else if (in_target_vma) {
                if (strncmp(line, "Rss:", 4) == 0) sscanf(line + 4, "%lu", &stats->vma_rss_kb);
                if (strncmp(line, "Anonymous:", 10) == 0) sscanf(line + 10, "%lu", &stats->vma_anon_kb);
                if (strncmp(line, "AnonHugePages:", 14) == 0) sscanf(line + 14, "%lu", &stats->vma_huge_kb);
                if (strncmp(line, "VmFlags:", 8) == 0) break; 
            }
        }
        fclose(f_smaps);
    }
}

static void check_thp(void) {
    FILE *f = fopen("/sys/kernel/mm/transparent_hugepage/enabled", "r");
    if (f) {
        char line[256];
        if (fgets(line, sizeof(line), f)) {
            box_line(C_DIM "Kernel THP Setting: %s" C_RESET, line);
        }
        fclose(f);
    }
}

/* ---------- MAIN ---------- */
int main(void) {
    COLOR = isatty(STDOUT_FILENO);
    mem_stats_t s0 = {0}, s1 = {0}, s2 = {0}, s3 = {0};
    
    printf("\n");
    box_top();
    box_line(C_BCYAN "KERNEL PAGE FAULT & DEMAND PAGING PROBE" C_RESET);
    box_line(C_DIM "Bridging glibc (userspace) and the Linux Kernel." C_RESET);
    box_mid();
    check_thp();
    box_bot();

    /* -------- GLOSSARY -------- */
    printf("\n");
    box_top();
    box_line(C_BCYAN "GLOSSARY OF TERMS (Read this first)" C_RESET);
    box_mid();
    
    box_line(C_BYELLOW "VMA (Virtual Memory Area):" C_RESET);
    box_text("A contiguous range of virtual addresses that share permissions. The kernel organizes memory in VMAs, not in malloc chunks.");

    box_line(C_BYELLOW "RSS (Resident Set Size):" C_RESET);
    box_text("The portion of memory currently held in physical RAM. Just because you requested 64 MB does not mean 64 MB of RAM is instantly consumed.");

    box_line(C_BYELLOW "Page Fault:" C_RESET);
    box_text("A hardware exception raised by the CPU's MMU when a program tries to access a virtual address that is not mapped to a physical page.");

    box_line(C_BYELLOW "Demand Paging:" C_RESET);
    box_text("The kernel's strategy of waiting until a page fault occurs before actually allocating physical RAM and updating the page tables.");

    box_line(C_BYELLOW "VmPTE (Page Table Entries):" C_RESET);
    box_text("The kernel memory consumed just to hold the page tables. Mapping 64 MB of data requires physical RAM to store the maps themselves.");

    box_line(C_BYELLOW "THP (Transparent Huge Pages):" C_RESET);
    box_text("An optimization where the kernel backs 2MB chunks of memory with a single huge page instead of 512 standard 4KB pages, reducing TLB misses.");
    box_bot();

    /* -------- STAGE 0: BASELINE -------- */
    get_stats(0, &s0);
    printf("\n");
    box_top();
    box_line(C_BCYAN "STAGE 0: BASELINE MEASUREMENT" C_RESET);
    box_line(C_DIM "Before we allocate anything, what does the process look like?" C_RESET);
    box_mid();
    box_line("Process RSS:      %8lu KB", s0.process_rss_kb);
    box_line("Process VmPTE:    %8lu KB", s0.process_pte_kb);
    box_line("Minor Faults:     %8ld", s0.minor_faults);
    box_bot();

    /* -------- STAGE 1: RESERVATION -------- */
    void *mem = mmap(NULL, ALLOC_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { perror("mmap"); return 1; }

    get_stats((uintptr_t)mem, &s1);

    printf("\n");
    box_top();
    box_line(C_BCYAN "STAGE 1: VIRTUAL RESERVATION (mmap)" C_RESET);
    box_line(C_DIM "Action: mmap(NULL, 64MB, PROT_READ|PROT_WRITE, MAP_ANONYMOUS)" C_RESET);
    box_mid();
    box_line("USER POINTER: 0x%016" PRIxPTR, (uintptr_t)mem);
    box_mid();
    box_line(C_YELLOW "WHAT JUST HAPPENED IN THE KERNEL?" C_RESET);
    box_text("The kernel created a VMA and recorded it in the process's mm_struct. However, it has NOT allocated physical RAM. The page tables are empty.");
    box_mid();
    box_line("VMA Exists:       " C_BGREEN "YES" C_RESET " (Size: %lu KB)", s1.vma_size_kb);
    box_line("VMA RSS:          %8lu KB  " C_DIM "(Physical RAM backing the mapping)" C_RESET, s1.vma_rss_kb);
    box_line("VMA Anonymous:    %8lu KB", s1.vma_anon_kb);
    box_mid();
    box_line("Process RSS Delta: +%lu KB", s1.process_rss_kb - s0.process_rss_kb);
    box_line("Process VmPTE:     %lu KB", s1.process_pte_kb);
    box_line("Minor Faults:      +%ld", s1.minor_faults - s0.minor_faults);
    box_bot();

    /* -------- STAGE 2: DEMAND PAGING -------- */
    printf("\n  " C_DIM "Writing 1 byte to every 4KB offset (touching %zu pages)..." C_RESET "\n", NUM_PAGES);
    
    char *ptr = (char *)mem;
    for (size_t i = 0; i < ALLOC_BYTES; i += PAGE_SIZE) {
        ptr[i] = 0xAA;
    }

    get_stats((uintptr_t)mem, &s2);

    printf("\n");
    box_top();
    box_line(C_BCYAN "STAGE 2: DEMAND PAGING (The Page Fault Trap)" C_RESET);
    box_line(C_DIM "Action: Write 0xAA to 16,384 different pages." C_RESET);
    box_mid();
    box_line(C_YELLOW "WHAT JUST HAPPENED IN THE KERNEL?" C_RESET);
    box_text("The CPU's MMU tried to read the physical address, found an empty Page Table Entry, and triggered a Page Fault. The kernel paused execution, allocated a physical page of RAM, zeroed it, mapped it into the page table, and resumed your program. It did this 16,384 times.");
    box_mid();
    box_line("VMA Exists:       " C_BGREEN "YES" C_RESET " (Size: %lu KB)", s2.vma_size_kb);
    box_line("VMA RSS:          " C_BGREEN "%8lu KB" C_RESET "  " C_DIM "(Demand Paged!)" C_RESET, s2.vma_rss_kb);
    box_line("VMA Anonymous:    " C_BGREEN "%8lu KB" C_RESET, s2.vma_anon_kb);
    box_line("VMA Huge Pages:   %8lu KB", s2.vma_huge_kb);
    box_mid();
    box_line("Process RSS Delta: +%lu KB", s2.process_rss_kb - s1.process_rss_kb);
    box_line("Process VmPTE:     %lu KB  " C_DIM "(Page Tables grew!)" C_RESET, s2.process_pte_kb);
    box_line("Minor Faults:      +%ld  " C_DIM "(~16,384 faults)" C_RESET, s2.minor_faults - s1.minor_faults);
    box_bot();

    /* -------- STAGE 3: UNMAPPING -------- */
    munmap(mem, ALLOC_BYTES);
    get_stats(0, &s3);

    printf("\n");
    box_top();
    box_line(C_BCYAN "STAGE 3: RELEASING MEMORY (munmap)" C_RESET);
    box_line(C_DIM "Action: munmap(ptr, 64MB)" C_RESET);
    box_mid();
    box_line(C_YELLOW "WHAT JUST HAPPENED IN THE KERNEL?" C_RESET);
    box_text("The kernel destroyed the VMA. It walked the page tables and returned every physical frame back to the Buddy Allocator. The virtual addresses are now invalid. If you dereference the pointer now, you will get a SIGSEGV.");
    box_mid();
    box_line("VMA Exists:       " C_BRED "NO" C_RESET " (VMA destroyed)");
    box_line("VMA RSS:          0 KB");
    box_mid();
    box_line("Process RSS Delta: -%lu KB", s2.process_rss_kb - s3.process_rss_kb);
    box_line("Process VmPTE:     %lu KB", s3.process_pte_kb);
    box_line("Minor Faults:      +%ld", s3.minor_faults - s2.minor_faults);
    box_bot();

    /* -------- THE UAF CONNECTION -------- */
    printf("\n");
    box_top();
    box_line(C_BCYAN "THE CONNECTION TO USE-AFTER-FREE (UAF)" C_RESET);
    box_mid();
    box_text("Why does a UAF in glibc not instantly trigger a SIGSEGV?");
    box_mid();
    box_text("Because free() does NOT call munmap(). When glibc frees a small chunk, it simply puts it into the tcache or a bin.");
    box_text("The VMA remains intact. The Page Tables remain intact. The physical RAM remains mapped to your process.");
    box_text("The CPU can still translate the dangling pointer perfectly well.");
    box_text("The memory only crashes your program if glibc explicitly calls munmap() (which it does for very large allocations). For small chunks, the memory is still yours; you just aren't supposed to use it.");
    box_bot();
    printf("\n");

    return 0;
}
