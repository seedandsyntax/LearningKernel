/* chunk_inspect_v19.c */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdarg.h>

/* Linker symbols for exact section boundaries */
extern char __data_start;
extern char _edata;
extern char __bss_start;
extern char _end;

/* ---------- CONFIG ---------- */
static unsigned char FILL_BYTE         = 0xAA;       // Lives in .data
static size_t        DISPLAY_MAX_BYTES = 64;
static int           FREE_AT_END       = 1;

static size_t REQUESTED_BYTES[] = {
    100, 1000, 127999, 140000, 120000, 110000, 200, 999888444
};

/* ---------- RUNTIME GLOBALS ---------- */
#define MAX_N 64
static int    N;
static void  *P[MAX_N];
static size_t REQ[MAX_N];
static int    IS_MMAPPED_ARR[MAX_N];

static uint64_t HEAP_BASE = 0;
static uint64_t HEAP_TOP  = 0; // Highest allocated chunk end

/* ---------- COLOR ---------- */
#define C_RESET   "\033[0m"
#define C_DIM     "\033[2m"
#define C_RED     "\033[31m"
#define C_GREEN   "\033[32m"
#define C_YELLOW  "\033[33m"
#define C_BLUE    "\033[34m"
#define C_CYAN    "\033[36m"
#define C_GRAY    "\033[90m"
#define C_BRED    "\033[1;31m"
#define C_BGREEN  "\033[1;32m"
#define C_BYELLOW "\033[1;33m"
#define C_BBLUE   "\033[1;34m"
#define C_BMAG    "\033[1;35m"
#define C_BCYAN   "\033[1;36m"

static int COLOR = 0;
static void c_(const char *code) { if (COLOR) fputs(code, stdout); }
static void cr_(void)            { if (COLOR) fputs(C_RESET, stdout); }

/* ---------- HELPERS ---------- */
static void rule_heavy(void) {
    c_(C_DIM);
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    cr_();
}

static void field_label(const char *label) {
    printf("     ");
    c_(C_DIM); printf("%-10s", label); cr_();
}

static void field_addr(const char *label, uint64_t a) {
    field_label(label);
    c_(C_DIM); printf("0x%" PRIx64 "\n", a); cr_();
}

static void field_memory(const char *label, uint64_t v) {
    field_label(label);
    if (!COLOR) printf("%016" PRIx64, v);
    else {
        for (int i = 0; i < 8; i++) {
            uint8_t b = (v >> (8*i)) & 0xff;
            if (b == FILL_BYTE && b != 0) fputs(C_BMAG, stdout);
            else if (b == 0)              fputs(C_GRAY, stdout);
            else                          fputs(C_CYAN, stdout);
            printf("%02x ", b);
            cr_();
        }
    }
    c_(C_DIM); printf("  (memory order)\n"); cr_();
}

static void print_bit(int number, const char *name, int value,
                      const char *meaning_1, const char *meaning_0, int highlight_zero) {
    printf("     bit %d ", number);
    if (value)                 c_(C_BGREEN);
    else if (highlight_zero)   c_(C_BYELLOW);
    else                       c_(C_GRAY);
    printf("[%d]", value); cr_();
    printf(" ");
    c_(C_CYAN); printf("%-14s", name); cr_();
    printf("  %s\n", value ? meaning_1 : meaning_0);
}

static void format_size(uint64_t bytes, char *out, size_t max) {
    if (bytes < 1024) {
        snprintf(out, max, "%lu bytes", bytes);
    } else {
        snprintf(out, max, "%lu bytes (%.3f KiB)", bytes, bytes / 1024.0);
    }
}

/* ---------- VIRTUAL MEMORY MAP GENERATOR ---------- */

#define BOX_WIDTH 64

static int visible_len(const char *s) {
    int len = 0;
    int in_ansi = 0;
    for (int i = 0; s[i] != '\0'; i++) {
        if (s[i] == '\033') in_ansi = 1;
        else if (in_ansi && s[i] == 'm') in_ansi = 0;
        else if (!in_ansi) len++;
    }
    return len;
}

static void box_top(const char *addr_str) {
    printf("  %-18s ┌", addr_str);
    for (int i = 0; i < BOX_WIDTH + 2; i++) printf("─");
    printf("┐\n");
}

static void box_mid(const char *addr_str) {
    printf("  %-18s ├", addr_str);
    for (int i = 0; i < BOX_WIDTH + 2; i++) printf("─");
    printf("┤\n");
}

static void box_bot(const char *addr_str) {
    printf("  %-18s └", addr_str);
    for (int i = 0; i < BOX_WIDTH + 2; i++) printf("─");
    printf("┘\n");
}

static void box_line(const char *fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    int len = visible_len(buf);
    printf("  %-18s │ ", "");
    fputs(buf, stdout);
    for (int i = len; i < BOX_WIDTH; i++) putchar(' ');
    printf(" │\n");
}

static uint64_t get_process_rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    uint64_t rss = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%lu", &rss);
            break;
        }
    }
    fclose(f);
    return rss;
}

static void get_mmap_info(uint64_t *sum_bytes, uint64_t *count, uint64_t *min_addr, uint64_t *max_addr, uint64_t *rss_kb) {
    FILE *f = fopen("/proc/self/smaps", "r");
    if (!f) return;
    char line[256];
    uint64_t s, e;
    uint64_t heap_end = 0, stack_start = 0xFFFFFFFFFFFFFFFF;
    
    // First pass: find heap and stack
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "[stack]")) sscanf(line, "%lx-", &stack_start);
        if (strstr(line, "[heap]")) sscanf(line, "%lx-%lx", &s, &e), heap_end = e;
    }
    rewind(f);

    *sum_bytes = 0;
    *count = 0;
    *min_addr = 0xFFFFFFFFFFFFFFFF;
    *max_addr = 0;
    *rss_kb = 0;
    int in_target_region = 0;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%lx-%lx", &s, &e) == 2) {
            if (s >= heap_end && e <= stack_start && !strstr(line, "[vvar]") && !strstr(line, "[vdso]") && !strstr(line, "[vsyscall]")) {
                in_target_region = 1;
                *sum_bytes += (e - s);
                (*count)++;
                if (s < *min_addr) *min_addr = s;
                if (e > *max_addr) *max_addr = e;
            } else {
                in_target_region = 0;
            }
        } else if (in_target_region && strncmp(line, "Rss:", 4) == 0) {
            uint64_t rss;
            sscanf(line + 4, "%lu", &rss);
            *rss_kb += rss;
        }
    }
    fclose(f);
}

static void draw_vmem_map(void) {
    uint64_t s_start, s_end, h_start, h_end;
    uint64_t text_start = 0, text_end = 0;
    uint64_t rodata_start = 0, rodata_end = 0;

    char exe_path[512];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (len != -1) {
        exe_path[len] = '\0';
        FILE *f = fopen("/proc/self/maps", "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                uint64_t s, e;
                if (sscanf(line, "%lx-%lx", &s, &e) == 2 && strstr(line, exe_path)) {
                    if (strstr(line, "r-xp")) { text_start = s; text_end = e; }
                    if (strstr(line, "r--p")) { rodata_start = s; rodata_end = e; }
                }
            }
            fclose(f);
        }
    }

    uint64_t mmap_sum_bytes, mmap_count, mmap_min, mmap_max, mmap_rss_kb;
    get_mmap_info(&mmap_sum_bytes, &mmap_count, &mmap_min, &mmap_max, &mmap_rss_kb);
    uint64_t process_rss_kb = get_process_rss_kb();

    FILE *f = fopen("/proc/self/maps", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            uint64_t s, e;
            if (sscanf(line, "%lx-%lx", &s, &e) == 2) {
                if (strstr(line, "[stack]")) { s_start = s; s_end = e; }
                if (strstr(line, "[heap]"))  { h_start = s; h_end = e; }
            }
        }
        fclose(f);
    }

    char sz_stack[64], sz_mmap[64], sz_heap[64], sz_top[64];
    char sz_data[64], sz_bss[64], sz_rodata[64], sz_text[64];

    format_size(s_end - s_start, sz_stack, sizeof(sz_stack));
    format_size(mmap_sum_bytes, sz_mmap, sizeof(sz_mmap));
    format_size(h_end - h_start, sz_heap, sizeof(sz_heap));
    format_size(h_end - HEAP_TOP, sz_top, sizeof(sz_top));
    
    uint64_t data_start = (uint64_t)&__data_start;
    uint64_t data_end   = (uint64_t)&_edata;
    uint64_t bss_start  = (uint64_t)&__bss_start;
    uint64_t bss_end    = (uint64_t)&_end;

    format_size(data_end - data_start, sz_data, sizeof(sz_data));
    format_size(bss_end - bss_start, sz_bss, sizeof(sz_bss));
    format_size(rodata_end - rodata_start, sz_rodata, sizeof(sz_rodata));
    format_size(text_end - text_start, sz_text, sizeof(sz_text));

    printf("\n");
    rule_heavy();
    c_(C_BCYAN); printf("  LINUX x86-64 VIRTUAL ADDRESS MAP (4-LEVEL PAGING)\n"); cr_();
    c_(C_DIM); printf("  Total Process RSS: %" PRIu64 " KB (physical RAM backing mapped pages)\n", process_rss_kb); cr_();
    rule_heavy();
    printf("\n");

    box_top("0xffffffffffffffff");
    box_line(C_BRED "                       KERNEL SPACE" C_RESET);
    box_line(C_DIM "            (direct mapping, vmalloc, kernel code)" C_RESET);
    box_line(C_DIM "            [8 TiB guard hole below, omitted for scale]" C_RESET);
    box_mid("0xffff800000000000");
    
    box_line("");
    box_line(C_DIM "                   NON-CANONICAL GAP" C_RESET);
    box_line(C_DIM "          (unaddressable by 48-bit pointers)" C_RESET);
    box_line("");
    
    box_mid("0x0000800000000000");
    box_mid("0x00007fffffffffff"); 
    box_line(C_DIM "           [4 KiB guard hole at top of user space]" C_RESET);
    box_mid("0x00007ffffffff000"); 
    
    // STACK
    box_line(C_CYAN "[STACK]    local variables, function frames" C_RESET);
    box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, s_start, s_end);
    box_line("           size:  %s", sz_stack);
    box_mid(" ");
    
    box_line(C_DIM "                   UNMAPPED GAP" C_RESET);
    box_mid(" ");

    // MMAP REGION
    box_line(C_BYELLOW "[MMAP]     shared libs & large mallocs" C_RESET);
    box_line("           span:  0x%016" PRIx64 " - 0x%016" PRIx64, mmap_min, mmap_max);
    box_line("           mapped: %s across %" PRIu64 " regions", sz_mmap, mmap_count);
    box_line("           RSS:   %" PRIu64 " KB resident in physical RAM", mmap_rss_kb);
    for (int i = 0; i < N; i++) {
        if (IS_MMAPPED_ARR[i]) {
            box_line("           malloc(%6zu) -> 0x%016" PRIx64, REQ[i], (uint64_t)P[i]);
        }
    }
    box_mid(" ");
    
    box_line(C_DIM "                   UNMAPPED GAP" C_RESET);
    box_mid(" ");

    // HEAP REGION
    box_line(C_BGREEN "[HEAP]     brk region (contiguous, grows upward)" C_RESET);
    box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, h_start, h_end);
    box_line("           size:  %s", sz_heap);
    for (int i = 0; i < N; i++) {
        if (!IS_MMAPPED_ARR[i]) {
            uint64_t chunk_start = (uint64_t)P[i] - 16;
            uint64_t raw_size = *(uint64_t*)((char*)P[i] - 8);
            uint64_t nb = raw_size & ~0xfULL;
            uint64_t chunk_end = chunk_start + nb;
            box_line("           chunk [0x%016" PRIx64 " - 0x%016" PRIx64 ")", chunk_start, chunk_end);
        } else {
            box_line(C_DIM "           (mmap bypassed heap — top unchanged)" C_RESET);
        }
    }
    
    box_line(C_BGREEN "           [TOP CHUNK] free space remaining in heap" C_RESET);
    box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, HEAP_TOP, h_end);
    box_line("           size:  %s", sz_top);
    box_mid(" ");
    
    // DATA
    box_line(C_BBLUE "[DATA]     initialized writable globals" C_RESET);
    box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, data_start, data_end);
    box_line("           size:  %s", sz_data);
    box_mid(" ");

    // BSS
    box_line(C_BBLUE "[BSS]      uninitialized globals" C_RESET);
    box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, bss_start, bss_end);
    box_line("           size:  %s", sz_bss);
    box_mid(" ");

    // RODATA
    box_line(C_BBLUE "[RODATA]   read-only data (string literals, etc.)" C_RESET);
    box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, rodata_start, rodata_end);
    box_line("           size:  %s", sz_rodata);
    box_mid(" ");

    // TEXT
    box_line(C_BBLUE "[TEXT]     program machine code (executable)" C_RESET);
    box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, text_start, text_end);
    box_line("           size:  %s", sz_text);
    
    box_bot("0x0000000000000000");
    printf("\n");
}

/* ---------- DUMP ONE CHUNK ---------- */
static void dump_one(int i)
{
    void    *u  = P[i];
    size_t   rq = REQ[i];

    uint64_t raw_size  = *(uint64_t*)((char*)u - 8);
    uint64_t prev_slot = *(uint64_t*)((char*)u - 16);
    uint64_t nb        = raw_size & ~0xfULL;
    uint64_t cstart    = (uint64_t)u - 16;
    uint64_t u_addr    = (uint64_t)u;

    int p_inuse  = (raw_size >> 0) & 1;
    int mmapped  = (raw_size >> 1) & 1;

    printf("\n");
    rule_heavy();
    c_(C_BCYAN); printf("  Chunk %d of %d\n", i, N); cr_();
    rule_heavy();
    printf("\n");

    if (mmapped) {
        c_(C_BYELLOW);
        printf("  REGION: [MMAP] (isolated mapping far from the heap)\n");
        printf("  TYPE:   MMAPPED CHUNK\n");
        cr_();
        printf("  These are allocated via mmap() because they exceed the threshold.\n");
        printf("  They do NOT have neighbors. There is no 'next chunk'.\n\n");
    } else {
        c_(C_GREEN);
        printf("  REGION: [HEAP] (contiguous brk memory)\n");
        printf("  TYPE:   BRK CHUNK\n");
        cr_();
        printf("  These live on the main heap. The current heap base is 0x%" PRIx64 ".\n\n", HEAP_BASE);
    }

    if (!mmapped) {
        uint64_t in_chunk = nb - 16;
        uint64_t spill    = (rq > in_chunk) ? (rq - in_chunk) : 0;
        
        printf("  %-20s %zu\n",         "requested bytes", rq);
        printf("  %-20s %" PRIu64 "\n", "chunk size (nb)", nb);
        printf("  %-20s %" PRIu64 "\n", "in-chunk user bytes", in_chunk);
        printf("  %-20s %" PRIu64 "\n", "spill bytes", spill);

        printf("\n  ");
        c_(C_DIM); printf("── "); cr_();
        c_(C_BBLUE); printf("prev_size"); cr_();
        c_(C_DIM); printf(" (chunk_start + 0) ───────────────────────────────────────\n"); cr_();
        field_addr("address", cstart);
        field_memory("memory", prev_slot);

        if (p_inuse) {
            field_label("STATE");
            if (prev_slot == 0) {
                c_(C_BGREEN); printf("UNUSED (all zeroes)"); cr_();
            } else {
                c_(C_YELLOW); printf("IGNORED (contains spillover data)"); cr_();
            }
            printf("\n");
            c_(C_DIM);
            printf("     WHY        bit 0 of \"size\" (PREV_INUSE) is 1\n");
            printf("                → previous chunk is allocated\n");
            printf("                → glibc does not read this field as a size\n");
            if (prev_slot != 0) {
                printf("                → the bytes above are active user payload\n");
                printf("                  spilled over from the previous chunk\n");
            }
            cr_();
        } else {
            field_label("STATE");
            c_(C_BYELLOW); printf("ACTIVE (holds previous chunk size)"); cr_();
            printf("\n");
            c_(C_DIM);
            printf("     WHY        bit 0 of \"size\" (PREV_INUSE) is 0\n");
            printf("                → previous_start = 0x%" PRIx64 " - 0x%" PRIx64 " = 0x%" PRIx64 "\n",
                   cstart, prev_slot, cstart - prev_slot);
            cr_();
        }

        printf("\n  ");
        c_(C_DIM); printf("── "); cr_();
        c_(C_BBLUE); printf("size"); cr_();
        c_(C_DIM); printf(" (chunk_start + 8) ─────────────────────────────────────────\n"); cr_();
        field_addr("address", cstart + 8);
        field_memory("memory", raw_size);
        print_bit(0, "PREV_INUSE", p_inuse, "previous allocated", "previous free", 1);
        print_bit(1, "IS_MMAPPED", mmapped, "mmap", "brk", 0);
        field_label("size");
        printf("0x%" PRIx64 " = %" PRIu64 " bytes\n", nb, nb);

        printf("\n  ");
        c_(C_DIM); printf("── "); cr_();
        c_(C_BBLUE); printf("user area"); cr_();
        c_(C_DIM); printf(" (%" PRIu64 " bytes) ──────────────────────────────────────────────\n", in_chunk); cr_();
        printf("     pointer malloc returned: 0x%" PRIx64 "\n", u_addr);

        uint64_t total_rows = in_chunk / 8;
        uint64_t max_rows   = (DISPLAY_MAX_BYTES == 0) ? total_rows : (DISPLAY_MAX_BYTES / 8);
        if (max_rows == 0) max_rows = 1;

        uint64_t show_first, show_last;
        if (total_rows > max_rows) {
            show_first = max_rows / 2; if (show_first == 0) show_first = 1;
            show_last  = max_rows - show_first; if (show_last == 0) show_last = 1;
        } else {
            show_first = total_rows; show_last = 0;
        }

        for (uint64_t r = 0; r < show_first; r++) {
            uint64_t a = u_addr + r*8;
            uint64_t v = *(uint64_t*)a;
            printf("     ");
            c_(C_DIM); printf("0x%" PRIx64, a); cr_();
            printf("   ");
            if (!COLOR) printf("%016" PRIx64, v);
            else {
                for (int i = 0; i < 8; i++) {
                    uint8_t b = (v >> (8*i)) & 0xff;
                    if (b == FILL_BYTE && b != 0) fputs(C_BMAG, stdout);
                    else if (b == 0)              fputs(C_GRAY, stdout);
                    else                          fputs(C_CYAN, stdout);
                    printf("%02x ", b);
                    cr_();
                }
            }
            c_(C_DIM); printf("   as 0x%016" PRIx64 "%s\n", v, r == 0 ? "  ← user_ptr" : ""); cr_();
        }
        if (show_last > 0) {
            printf("     ");
            c_(C_DIM);
            printf("... %" PRIu64 " bytes hidden ...\n", (total_rows - show_first - show_last) * 8);
            cr_();
            for (uint64_t r = total_rows - show_last; r < total_rows; r++) {
                uint64_t a = u_addr + r*8;
                uint64_t v = *(uint64_t*)a;
                printf("     ");
                c_(C_DIM); printf("0x%" PRIx64, a); cr_();
                printf("   ");
                if (!COLOR) printf("%016" PRIx64, v);
                else {
                    for (int i = 0; i < 8; i++) {
                        uint8_t b = (v >> (8*i)) & 0xff;
                        if (b == FILL_BYTE && b != 0) fputs(C_BMAG, stdout);
                        else if (b == 0)              fputs(C_GRAY, stdout);
                        else                          fputs(C_CYAN, stdout);
                        printf("%02x ", b);
                        cr_();
                    }
                }
                c_(C_DIM); printf("   as 0x%016" PRIx64 "%s\n", v, r == total_rows - 1 ? "  ← last row" : ""); cr_();
            }
        }

        if (spill > 0) {
            printf("\n  ");
            c_(C_DIM); printf("── "); cr_();
            c_(C_BBLUE); printf("SPILL"); cr_();
            c_(C_DIM); printf(" into next chunk's prev_size ────────────────────────────\n"); cr_();
            uint64_t a = u_addr + in_chunk;
            uint64_t v = *(uint64_t*)a;
            field_addr("address", a);
            field_memory("memory", v);
            field_label("STATE");
            c_(C_BRED); printf("%" PRIu64 " byte(s) of fill pattern landed here\n", spill); cr_();
        }
        printf("\n  ");
        c_(C_DIM); printf("next chunk starts at 0x%" PRIx64 "\n", (uint64_t)u + in_chunk); cr_();
    } 
    else 
    {
        printf("  %-20s %zu\n",         "requested bytes", rq);
        printf("  %-20s %" PRIu64 "\n", "chunk size (nb)", nb);

        printf("\n  ");
        c_(C_DIM); printf("── "); cr_();
        c_(C_BBLUE); printf("prev_size"); cr_();
        c_(C_DIM); printf(" (chunk_start + 0) ───────────────────────────────────────\n"); cr_();
        field_addr("address", cstart);
        field_memory("memory", prev_slot);
        
        field_label("STATE");
        c_(C_BYELLOW); printf("OFFSET TO MMAP BASE"); cr_();
        printf("\n");
        c_(C_DIM);
        printf("     WHY        bit 1 of \"size\" (IS_MMAPPED) is 1\n");
        printf("                → there is no 'previous chunk'\n");
        printf("                → this field stores the offset from the kernel's mmap\n");
        printf("                  base to the chunk's start (so free() can munmap correctly)\n");
        printf("                → offset = 0x%" PRIx64 "\n", prev_slot);
        cr_();

        printf("\n  ");
        c_(C_DIM); printf("── "); cr_();
        c_(C_BBLUE); printf("size"); cr_();
        c_(C_DIM); printf(" (chunk_start + 8) ─────────────────────────────────────────\n"); cr_();
        field_addr("address", cstart + 8);
        field_memory("memory", raw_size);
        
        printf("     bit 0 ");
        c_(C_GRAY); printf("[%d]", p_inuse); cr_();
        printf(" PREV_INUSE      %s\n", p_inuse ? "1" : "0");

        printf("     bit 1 ");
        if (mmapped) c_(C_BYELLOW); else c_(C_GRAY);
        printf("[%d]", mmapped); cr_();
        printf(" IS_MMAPPED      ");
        if (mmapped) {
            c_(C_YELLOW); printf("1 → this chunk was mmapped, use munmap() on free\n"); cr_();
        }

        field_label("size");
        printf("0x%" PRIx64 " = %" PRIu64 " bytes (total mapping length)\n", nb, nb);
    }
}

/* ---------- MAIN ---------- */
int main(void)
{
    N = sizeof(REQUESTED_BYTES) / sizeof(REQUESTED_BYTES[0]);
    if (N > MAX_N) N = MAX_N;
    COLOR = isatty(STDOUT_FILENO);

    printf("\n");
    rule_heavy();
    c_(C_BCYAN); printf("  ALLOCATION PHASE (How glibc evaluates your requests)\n"); cr_();
    rule_heavy();
    printf("\n");
    
    for (int i = 0; i < N; i++) {
        P[i]   = malloc(REQUESTED_BYTES[i]);
        REQ[i] = REQUESTED_BYTES[i];
        if (!P[i]) { fprintf(stderr, "malloc failed\n"); N = i; break; }
        memset(P[i], FILL_BYTE, REQ[i]);
        
        uint64_t chunk_start = (uint64_t)P[i] - 16;
        uint64_t raw_size = *(uint64_t*)((char*)P[i] - 8);
        uint64_t nb = raw_size & ~0xfULL;
        int mmapped = (raw_size >> 1) & 1;
        IS_MMAPPED_ARR[i] = mmapped;
        
        printf("  malloc(%5zu)  [nb = %" PRIu64 "]\n", REQ[i], nb);
        
        if (mmapped) {
            c_(C_BYELLOW);
            printf("    [MMAP THRESHOLD EXCEEDED]\n");
            printf("    → chunk size (%" PRIu64 ") >= 128 KB initial threshold\n", nb);
            printf("    → BYPASSING [HEAP]. Requesting isolated mapping from OS via mmap().\n");
            printf("    → mapped at 0x%" PRIx64 " (Notice the 0x7f... high address)\n", chunk_start);
            printf("    → [HEAP] top is untouched at 0x%" PRIx64 "\n", HEAP_TOP);
            cr_();
        } else {
            c_(C_GREEN);
            if (HEAP_BASE == 0) {
                HEAP_BASE = chunk_start;
                printf("    [CREATING HEAP REGION]\n");
                printf("    → initialized main heap at 0x%" PRIx64 "\n", HEAP_BASE);
            }
            
            if (chunk_start == HEAP_TOP) {
                printf("    [HEAP] placed back-to-back (carved from top chunk)\n");
            } else if (chunk_start > HEAP_TOP) {
                printf("    [HEAP] heap grew (glibc called brk() to extend the top)\n");
            } else {
                printf("    [HEAP] placed at a different address (reused a free chunk)\n");
            }
            printf("    → carved %" PRIu64 " bytes starting at 0x%" PRIx64 "\n", nb, chunk_start);
            printf("    → returned pointer: 0x%" PRIx64 " (chunk_start + 16)\n", (uint64_t)P[i]);
            
            HEAP_TOP = chunk_start + nb;
            printf("    → updated [HEAP] top to 0x%" PRIx64 "\n", HEAP_TOP);
            cr_();
        }
    }

    printf("\n");
    rule_heavy();
    c_(C_BCYAN); printf("  INSPECTION PHASE\n"); cr_();
    rule_heavy();
    for (int i = 0; i < N; i++) dump_one(i);

    draw_vmem_map();

    if (FREE_AT_END) {
        printf("\n");
        rule_heavy();
        c_(C_BCYAN); printf("  FREE PHASE\n"); cr_();
        rule_heavy();
        printf("\n");
        for (int i = 0; i < N; i++) {
            printf("  free(0x%" PRIx64 ")\n", (uint64_t)P[i]);
            free(P[i]);
        }
        printf("\n  Note: mmapped chunks are immediately returned to the OS via munmap().\n");
    }

    printf("\n");
    return 0;
}
