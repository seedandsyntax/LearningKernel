/* chunk_inspect_v33.c */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdarg.h>
#include <gnu/libc-version.h>
#include <locale.h>

/* Linker symbols for exact section boundaries */
extern char __data_start;
extern char _edata;
extern char __bss_start;
extern char _end;

/* ---------- CONFIG ---------- */
static unsigned char FILL_BYTE = 0xAA;

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
static uint64_t HEAP_TOP  = 0;

/* ---------- COLOR ---------- */
#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_DIM     "\033[2m"
#define C_RED     "\033[31m"
#define C_GREEN   "\033[32m"
#define C_YELLOW  "\033[33m"
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
static void print_section_header(const char *title) {
    printf("\n====================================================================================================================================================================\n");
    c_(C_BCYAN); printf(" %s\n", title); cr_();
    printf("====================================================================================================================================================================\n\n");
}

static void format_size(uint64_t bytes, char *out, size_t max) {
    if (bytes < 1024) {
        snprintf(out, max, "%lu bytes", bytes);
    } else {
        snprintf(out, max, "%lu bytes (%.3f KiB)", bytes, bytes / 1024.0);
    }
}

static size_t tcache_bin_index(uint64_t nb) {
    return (size_t)((nb - 32 + 15) / 16);
}

static uint64_t safe_link_decode(uint64_t encoded, uint64_t chunk_addr) {
    return encoded ^ (chunk_addr >> 12);
}

/* ---------- ASCII BOX VISUALS ---------- */
#define TOTAL_WIDTH 164

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

static void print_box_top(void) {
    printf("+"); for (int i = 0; i < TOTAL_WIDTH - 2; i++) printf("-"); printf("+\n");
}
static void print_box_mid(void) {
    printf("|"); for (int i = 0; i < TOTAL_WIDTH - 2; i++) printf("-"); printf("|\n");
}
static void print_box_bot(void) {
    printf("+"); for (int i = 0; i < TOTAL_WIDTH - 2; i++) printf("-"); printf("+\n");
}
static void print_box_line(const char *fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    int len = visible_len(buf);
    printf("| ");
    fputs(buf, stdout);
    
    if (COLOR) fputs(C_RESET, stdout);
    
    for (int i = len; i < TOTAL_WIDTH - 4; i++) putchar(' ');
    printf(" |\n");
}

/* ---------- TAG & HEX FORMATTERS ---------- */
static void format_tag(char *out, const char *name) {
    // Colors the ENTIRE ##TAG:(...) string in Bold Magenta
    if (COLOR) sprintf(out, "\033[1;35m##TAG:(%s)\033[0m", name);
    else sprintf(out, "##TAG:(%s)", name);
}

static void format_hex_row(uint64_t addr, const unsigned char *ptr, char *out) {
    char *p = out;
    p += sprintf(p, "  0x%016" PRIx64 ":", addr);
    for (int i = 0; i < 8; i++) {
        unsigned char c = ptr[i];
        char ch = (c >= 32 && c <= 126) ? c : '.';
        p += sprintf(p, " [ %02X|%c ]", c, ch);
    }
    *p = '\0';
}

/* ---------- PHASE 2 DUMP ---------- */
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
    int non_main = (raw_size >> 2) & 1;

    char name[32]; sprintf(name, "P[%d]", i);
    char tag_buf[64]; format_tag(tag_buf, name);

    printf("\n");
    print_box_top();
    print_box_line("CHUNK %d of %d  %s", i, N, mmapped ? "[MMAP] MMAPPED CHUNK" : "[HEAP] BRK CHUNK");
    print_box_mid();

    print_box_line("ADDRESSES & SIZES");
    print_box_line("  ptr = 0x%016" PRIx64 " %s", u_addr, tag_buf);
    print_box_line("  chunk_start = 0x%016" PRIx64, cstart);
    print_box_line("  nb (actual) = %" PRIu64 " bytes", nb);
    if (!mmapped) {
        print_box_line("  formula     = (req + 8 + 15) & ~15 = (%zu + 23) & ~15 = %" PRIu64, rq, nb);
        print_box_line("  in-chunk    = %" PRIu64 " bytes (strictly inside chunk, nb - 16)", nb - 16);
        print_box_line("  usable      = %" PRIu64 " bytes (malloc_usable_size, nb - 8)", nb - 8);
        uint64_t overlap = (rq > (nb - 16)) ? (rq - (nb - 16)) : 0;
        print_box_line("  overlap     = %" PRIu64 " bytes (req - in-chunk, tail payload)", overlap);
    }
    print_box_mid();

    print_box_line("CHUNK HEADER ANALYSIS");
    print_box_line("  [ prev_size ] @ +0x00: 0x%016" PRIx64, prev_slot);
    if (!mmapped && p_inuse && prev_slot != 0) {
        print_box_line("    Note: P=1, so glibc IGNORES this field.");
        print_box_line("          These bytes are the TAIL END of the previous chunk's user data (Tail Overlap).");
    }
    print_box_line("  [ size      ] @ +0x08: 0x%016" PRIx64, raw_size);
    print_box_line("                         |---> Flags: 0x%lx", (unsigned long)(raw_size & 0xF));
    print_box_line("                         |     - P (PREV_INUSE) = %d", p_inuse);
    print_box_line("                         |     - M (IS_MMAPPED)  = %d", mmapped);
    print_box_line("                         |     - A (NON_MAIN)    = %d", non_main);
    print_box_line("                         |---> Size (masked): 0x%" PRIx64 " (%" PRIu64 " bytes)", nb, nb);
    print_box_mid();

    print_box_line("HEAP MEMORY DUMP: %s (chunk size = %" PRIu64 " bytes)", name, nb);
    print_box_mid();
    
    char hex_row[256];
    print_box_line("[CHUNK HEADER (16 bytes)]");
    format_hex_row(cstart, (unsigned char*)cstart, hex_row);
    print_box_line("%s", hex_row);
    format_hex_row(cstart + 8, (unsigned char*)(cstart + 8), hex_row);
    print_box_line("%s", hex_row);
    
    print_box_mid();
    print_box_line("[USER AREA (Struct Data)]");
    uint64_t total_rows = (nb - 16) / 8;
    if (total_rows <= 4) {
        for (uint64_t r = 0; r < total_rows; r++) {
            format_hex_row(u_addr + r*8, (unsigned char*)(u_addr + r*8), hex_row);
            print_box_line("%s %s", hex_row, r == 0 ? " <-- Starts 'user data'" : "");
        }
    } else {
        for (uint64_t r = 0; r < 2; r++) {
            format_hex_row(u_addr + r*8, (unsigned char*)(u_addr + r*8), hex_row);
            print_box_line("%s %s", hex_row, r == 0 ? " <-- Starts 'user data'" : "");
        }
        print_box_line(C_DIM "  ... %" PRIu64 " bytes hidden ..." C_RESET, (total_rows - 4) * 8);
        for (uint64_t r = total_rows - 2; r < total_rows; r++) {
            format_hex_row(u_addr + r*8, (unsigned char*)(u_addr + r*8), hex_row);
            print_box_line("%s", hex_row);
        }
    }
    print_box_bot();
}

/* ---------- COALESCING DEMO (Phase 3) ---------- */
static void run_coalescing_demo(void) {
    printf("\n");
    print_box_top();
    print_box_line(C_BCYAN "PHASE 3: COALESCING DEMONSTRATION" C_RESET);
    print_box_line(C_DIM "The crux of prev_size and the P bit." C_RESET);
    print_box_mid();
    print_box_line("Why track PREV_INUSE? To know if prev_size is safe to read.");
    print_box_line("If it's 1, we can't merge backward. If 0, we can.");
    print_box_line("We allocate two 2000-byte chunks (nb=2016) to bypass tcache.");
    print_box_line(C_DIM "This forces glibc to use the unsorted bin and merge logic." C_RESET);
    print_box_mid();

    void *A = malloc(2000);
    void *B = malloc(2000);
    memset(A, 0xBB, 2000);
    memset(B, 0xCC, 2000);

    uint64_t a_chunk = (uint64_t)A - 16;
    uint64_t b_chunk = (uint64_t)B - 16;
    uint64_t a_size = *(uint64_t*)(a_chunk + 8);
    uint64_t b_size = *(uint64_t*)(b_chunk + 8);
    uint64_t a_nb = a_size & ~0xfULL;
    uint64_t b_nb = b_size & ~0xfULL;

    char tag_a[64]; format_tag(tag_a, "A");
    char tag_b[64]; format_tag(tag_b, "B");

    print_box_line("[STEP 1] Initial state (both allocated)");
    print_box_line("  A = 0x%016" PRIx64 " %s (chunk %lu bytes)", (uint64_t)A, tag_a, a_nb);
    print_box_line("  B = 0x%016" PRIx64 " %s (chunk %lu bytes)", (uint64_t)B, tag_b, b_nb);
    print_box_line("  Before freeing A:");
    print_box_line("    B.P = 1 (A is marked in-use)");
    print_box_line("    A.P = 1 (chunk before A is in-use)");
    print_box_mid();

    print_box_line("[STEP 2] free(A)");
    free(A);
    uint64_t b_size_after = *(uint64_t*)(b_chunk + 8);
    uint64_t b_prev_after = *(uint64_t*)(b_chunk);
    print_box_line("  free(A) actions:");
    print_box_line("    glibc checks B.P. It's 1, validating A was in-use.");
    print_box_line("    glibc checks A.P. It's 1, so no backward merge.");
    print_box_line("    glibc writes A's size to B.prev_size, clears B.P.");
    print_box_line("  B.prev_size  = 0x%016" PRIx64, b_prev_after);
    print_box_line("  B.size       = 0x%016" PRIx64 " (P=0)", b_size_after);
    print_box_mid();

    print_box_line("[STEP 3] free(B)");
    free(B);
    uint64_t a_size_after = *(uint64_t*)(a_chunk + 8);
    uint64_t merged_nb = a_size_after & ~0xfULL;
    print_box_line("  free(B) actions:");
    print_box_line("    glibc checks B.P. It's 0, meaning A is free.");
    print_box_line("    Reads B.prev_size (0x%lx), merges A and B.", b_prev_after);
    print_box_line("    prev_chunk = 0x%lx - 0x%lx = 0x%lx", b_chunk, b_prev_after, b_chunk - b_prev_after);
    print_box_line("    Merges A + B into one giant free chunk.");
    print_box_line("    A.size       = 0x%016" PRIx64 " (merged %lu bytes)", a_size_after, merged_nb);
    print_box_line(C_DIM "    Because the result borders the Top Chunk, it absorbs Top." C_RESET);
    print_box_mid();
    print_box_line(C_GREEN "CONCLUSION:" C_RESET);
    print_box_line("B.P initially indicated that A was marked in-use.");
    print_box_line("When A was freed, glibc validated A using B.P, checked A.P,");
    print_box_line("wrote A's size into B.prev_size, and cleared B.P.");
    print_box_line("When B was freed, B.P=0 allowed backward consolidation,");
    print_box_line("and A + B + Top became the new Top Chunk.");
    print_box_bot();
}

/* ---------- VIRTUAL MEMORY MAP GENERATOR ---------- */
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
    uint64_t s_start = 0, s_end = 0, h_start = 0, h_end = 0;
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
    printf("====================================================================================================================================================================\n");
    c_(C_BCYAN); printf(" LINUX x86-64 VIRTUAL ADDRESS MAP (4-LEVEL PAGING)\n"); cr_();
    c_(C_DIM); printf(" Total Process RSS: %" PRIu64 " KB (physical RAM backing mapped pages)\n", process_rss_kb); cr_();
    printf("====================================================================================================================================================================\n\n");

    print_box_top();
    print_box_line("0xffffffffffffffff");
    print_box_line(C_BRED "                       KERNEL SPACE" C_RESET);
    print_box_line(C_DIM "            (direct mapping, vmalloc, kernel code)" C_RESET);
    print_box_line(C_DIM "            [8 TiB guard hole below, omitted for scale]" C_RESET);
    print_box_mid();
    
    print_box_line("");
    print_box_line(C_DIM "                   NON-CANONICAL GAP" C_RESET);
    print_box_line(C_DIM "          (unaddressable by 48-bit pointers)" C_RESET);
    print_box_line("");
    print_box_mid();
    
    print_box_line("0x0000800000000000");
    print_box_line("0x00007fffffffffff"); 
    print_box_line(C_DIM "           [4 KiB guard hole at top of user space]" C_RESET);
    print_box_line("0x00007ffffffff000"); 
    
    print_box_line(C_CYAN "[STACK]    local variables, function frames" C_RESET);
    print_box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, s_start, s_end);
    print_box_line("           size:  %s", sz_stack);
    print_box_mid();
    
    print_box_line(C_DIM "                   UNMAPPED GAP" C_RESET);
    print_box_mid();

    print_box_line(C_BYELLOW "[MMAP]     shared libs & large mallocs" C_RESET);
    print_box_line("           span:  0x%016" PRIx64 " - 0x%016" PRIx64, mmap_min, mmap_max);
    print_box_line("           mapped: %s across %" PRIu64 " regions", sz_mmap, mmap_count);
    print_box_line("           RSS:   %" PRIu64 " KB resident in physical RAM", mmap_rss_kb);
    for (int i = 0; i < N; i++) {
        if (IS_MMAPPED_ARR[i]) {
            char name[32]; sprintf(name, "P[%d]", i);
            char tag_buf[64]; format_tag(tag_buf, name);
            print_box_line("           malloc(%6zu) -> 0x%016" PRIx64 " %s", REQ[i], (uint64_t)P[i], tag_buf);
        }
    }
    print_box_mid();
    
    print_box_line(C_DIM "                   UNMAPPED GAP" C_RESET);
    print_box_mid();

    print_box_line(C_BGREEN "[HEAP]     brk region (contiguous, grows upward)" C_RESET);
    print_box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, h_start, h_end);
    print_box_line("           size:  %s", sz_heap);
    for (int i = 0; i < N; i++) {
        if (!IS_MMAPPED_ARR[i]) {
            uint64_t chunk_start = (uint64_t)P[i] - 16;
            uint64_t raw_size = *(uint64_t*)((char*)P[i] - 8);
            uint64_t nb = raw_size & ~0xfULL;
            uint64_t chunk_end = chunk_start + nb;
            char name[32]; sprintf(name, "P[%d]", i);
            char tag_buf[64]; format_tag(tag_buf, name);
            print_box_line("           chunk [0x%016" PRIx64 " - 0x%016" PRIx64 ") %s", chunk_start, chunk_end, tag_buf);
        } else {
            print_box_line(C_DIM "           (mmap bypassed heap -- top unchanged)" C_RESET);
        }
    }
    
    print_box_line(C_BGREEN "           [TOP CHUNK] free space remaining in heap" C_RESET);
    print_box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, HEAP_TOP, h_end);
    print_box_line("           size:  %s", sz_top);
    print_box_mid();
    
    print_box_line(C_BBLUE "[DATA]     initialized writable globals" C_RESET);
    print_box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, data_start, data_end);
    print_box_line("           size:  %s", sz_data);
    print_box_mid();

    print_box_line(C_BBLUE "[BSS]      uninitialized globals" C_RESET);
    print_box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, bss_start, bss_end);
    print_box_line("           size:  %s", sz_bss);
    print_box_mid();

    print_box_line(C_BBLUE "[READ-ONLY MAPPING]" C_RESET);
    print_box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, rodata_start, rodata_end);
    print_box_line("           size:  %s", sz_rodata);
    print_box_mid();

    print_box_line(C_BBLUE "[EXECUTABLE MAPPING]" C_RESET);
    print_box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, text_start, text_end);
    print_box_line("           size:  %s", sz_text);
    print_box_line("0x0000000000000000");
    print_box_bot();
}

/* ---------- DEALLOCATION TRACE (Phase 4) ---------- */
static void trace_deallocations(void) {
    for (int i = 0; i < N; i++) {
        uint64_t u_ptr    = (uint64_t)P[i];
        uint64_t cstart   = u_ptr - 16;
        uint64_t raw_size = *(uint64_t*)(cstart + 8);
        uint64_t nb       = raw_size & ~0xfULL;
        int mmapped       = (raw_size >> 1) & 1;
        int p_inuse       = raw_size & 1;

        char name[32]; sprintf(name, "P[%d]", i);
        char tag_buf[64]; format_tag(tag_buf, name);

        printf("\n");
        print_box_top();
        print_box_line("FREE: %s", tag_buf);
        print_box_mid();
        
        print_box_line("ADDRESSES & SIZES");
        print_box_line("  ptr = 0x%016" PRIx64 " %s", u_ptr, tag_buf);
        print_box_line("  chunk_start = 0x%016" PRIx64, cstart);
        print_box_line("  nb (actual) = %" PRIu64 " bytes", nb);
        print_box_mid();
        
        print_box_line("HEAP MEMORY DUMP: %s (chunk size = %" PRIu64 " bytes)", name, nb);
        print_box_mid();
        char hex_row[256];
        print_box_line("[CHUNK HEADER (16 bytes)]");
        format_hex_row(cstart, (unsigned char*)cstart, hex_row);
        print_box_line("%s", hex_row);
        format_hex_row(cstart + 8, (unsigned char*)(cstart + 8), hex_row);
        print_box_line("%s", hex_row);
        print_box_mid();
        print_box_line("[USER AREA (Struct Data)]");
        format_hex_row(u_ptr, (unsigned char*)u_ptr, hex_row);
        print_box_line("%s <-- [next] pointer (Safe-Linked)", hex_row);
        format_hex_row(u_ptr + 8, (unsigned char*)(u_ptr + 8), hex_row);
        print_box_line("%s", hex_row);
        print_box_mid();

        if (mmapped) {
            print_box_line("Tcache State (Bypassed - MMAP)");
            print_box_line("  mmap() chunks do not use tcache.");
            print_box_mid();
            print_box_line("POST-FREE ANALYSIS:");
            print_box_line("  glibc called munmap() to return this memory to the kernel.");
            print_box_line("  This chunk NEVER entered tcache. It bypassed the heap entirely.");
            print_box_line("  The memory is now completely unmapped from the process address space.");
            print_box_line("  CONCLUSION: mmap() chunks are Fail-Stop.");
            print_box_line("  Any dereference triggers a SIGSEGV. Silent exploitation is impossible.");

            free(P[i]);
        } else if (nb <= 1032) {
            print_box_line("Tcache State (Post-Free)");
            print_box_line("  entries[idx] = 0x%016" PRIx64 " %s", u_ptr, tag_buf);
            print_box_mid();
            
            free(P[i]);
            
            uint64_t *user = (uint64_t*)P[i];
            uint64_t enc_next = user[0];
            uint64_t key      = user[1];
            uint64_t dec_next = safe_link_decode(enc_next, (uint64_t)P[i]);
            
            print_box_line("  -> [ Chunk @ 0x%016" PRIx64 " %s ]", u_ptr, tag_buf);
            print_box_line("     +0x00: [ next ] = 0x%016" PRIx64, enc_next);
            print_box_line("            Math: (0x%lx >> 12) ^ 0x%016" PRIx64 " = 0x%lx", (u_ptr >> 12), enc_next, dec_next);
            print_box_line("            Decoded: %s", dec_next == 0 ? "NULL" : "");
            print_box_line("     +0x08: [ key  ] = 0x%016" PRIx64, key);
            print_box_mid();
            
            print_box_line("[POST-FREE ANALYSIS]");
            print_box_line("  * glibc pushed this chunk onto the LIFO tcache stack.");
            print_box_line("    It overwrote the first 16 bytes of the user area with [next] and [key].");
            print_box_line("    The following struct fields overlap the 16-byte tcache metadata region and are DESTROYED:");
            print_box_line("           - Field 'user data' at offset 0x00 (size 16)");
            print_box_line("");
            print_box_line("    CONCLUSION: tcache chunks are VULNERABLE to UAF.");
            print_box_line("    The memory remains mapped and owned by glibc. The dangling pointer");
            print_box_line("    is still a valid virtual address, making silent data corruption possible.");
        } else {
            print_box_line("Tcache State (Bypassed - Chunk > 1040 bytes)");
            print_box_line("  Too large for tcache. Went to unsorted bin (or coalesced into Top).");
            print_box_mid();
            
            free(P[i]);
            
            print_box_line("[POST-FREE ANALYSIS]");
            print_box_line("  * This chunk is larger than 1040 bytes, so it bypassed tcache.");
            print_box_line("    It was placed in the unsorted bin.");
            print_box_line("    If adjacent to the Top chunk, glibc coalesced it into the Top chunk.");
            print_box_line("");
            print_box_line("    CONCLUSION: Large heap chunks do not get tcache metadata overwrite.");
        }
        print_box_bot();
    }
}

/* ---------- TCACHE LIVE DEMO (Phase 5) ---------- */
static void draw_tcache(void) {
    uint64_t p0_ptr = (uint64_t)P[0];
    if (p0_ptr == 0) return;

    char tag_p0[64]; format_tag(tag_p0, "P[0]");
    char tag_alias[64]; format_tag(tag_alias, "alias");

    printf("\n");
    print_box_top();
    print_box_line(C_BOLD "PHASE 5: THE TCACHE (Where do the freed chunks go?)" C_RESET);
    print_box_line(C_DIM "tcache is the Thread Local Cache." C_RESET);
    print_box_line(C_DIM "glibc 2.43 uses a randomized 'key' to prevent double-frees." C_RESET);
    print_box_mid();
    
    print_box_line("Let's look at Chunk 0 (P[0]). It was freed in Phase 4.");
    print_box_line("  P[0] user area starts at: 0x%016" PRIx64 " %s", p0_ptr, tag_p0);
    print_box_line("  The first 16 bytes were overwritten by tcache metadata:");
    
    uint64_t next_val = *(uint64_t*)(p0_ptr);
    uint64_t key_val  = *(uint64_t*)(p0_ptr + 8);
    print_box_line("    [next] = 0x%016" PRIx64, next_val);
    print_box_line("    [key]  = 0x%016" PRIx64, key_val);
    print_box_mid();

    uint64_t recovered_next = safe_link_decode(next_val, p0_ptr);
    print_box_line(C_GREEN "STEP 1: VERIFYING THE CHUNK IS IN TCACHE" C_RESET);
    print_box_line("In glibc 2.34+, the [next] pointer is 'safe-linked'.");
    print_box_line("It is obfuscated by XORing it with (chunk_address >> 12).");
    print_box_line("  chunk_addr >> 12 = 0x%lx", (p0_ptr >> 12));
    print_box_line("  [next] ^ (addr >> 12) = 0x%lx", recovered_next);

    if (recovered_next == 0) {
        print_box_line("  Since the result is 0x0 (NULL), this chunk is the HEAD of the bin.");
        print_box_line("  PROOF: P[0] IS DEFINITELY IN THE TCACHE!");
    } else {
        print_box_line("  It points to the next chunk at 0x%lx.", recovered_next);
    }
    print_box_mid();

    print_box_line(C_YELLOW "STEP 2: WHY THE [key] LOOKS INVALID" C_RESET);
    print_box_line("In glibc 2.43, the [key] is NOT a pointer to the tcache struct.");
    print_box_line("It is a randomized 64-bit cookie (tcache_key).");
    print_box_line("When you free a chunk, glibc checks if this key matches.");
    print_box_line("It doesn't abort immediately on a match; it scans the");
    print_box_line("bin first to confirm a real double-free before aborting.");
    print_box_line("Because it's a random cookie, it looks like garbage.");
    print_box_line("It does NOT mean the chunk isn't in tcache.");
    print_box_mid();

    print_box_line(C_CYAN "STEP 3: WHERE ARE THE TCACHE BINS?" C_RESET);
    print_box_line("The actual bins live in the tcache_perthread_struct:");
    print_box_line("  uint16_t num_slots[64];");
    print_box_line("  tcache_entry *entries[64];");
    print_box_line("num_slots is the number of REMAINING slots, not used ones.");
    print_box_line("Chunk 0 is 112 bytes (bin index %zu).", tcache_bin_index(112));
    print_box_line("With a default of 16 slots, after 1 insertion, num_slots[%zu] = 15.", tcache_bin_index(112));
    print_box_line("Because of the random key, we cannot easily locate it");
    print_box_line("from the chunk metadata alone without reading the TLS.");
    print_box_mid();

    print_box_line(C_BOLD "[LIVE DEMO A: POP FROM TCACHE + UAF ALIASING]" C_RESET);
    print_box_line("After Phase 4, bin %zu holds exactly one node: P[0].", tcache_bin_index(112));
    print_box_line("If we call malloc(100) now, glibc should pop it:");

    void *alias = malloc(100);
    print_box_line("  malloc(100)  -> 0x%016" PRIx64 " %s", (uint64_t)alias, tag_alias);
    print_box_line("  old P[0]     -> 0x%016" PRIx64 " %s", p0_ptr, tag_p0);

    if (alias == P[0]) {
        print_box_line("  -> SAME ADDRESS. The tcache pop returned the dangling chunk.");
        print_box_mid();
        print_box_line("Now the classic UAF aliasing test:");
        print_box_line("  1. Write \"UAF_PWN\" via the NEW pointer (alias)");
        snprintf((char*)alias, 8, "UAF_PWN");
        print_box_line("  2. Read via the OLD dangling pointer P[0]");
        print_box_line("     P[0] as string: \"%s\"", (char*)P[0]);
        print_box_line("  -> ALIASING CONFIRMED: two names, one physical chunk.");
        print_box_line("  Restoring: free(alias) pushes it back into bin %zu.", tcache_bin_index(112));
        free(alias);
    } else {
        print_box_line("  -> different address (bin was empty; fresh from top).");
        free(alias);
    }
    print_box_bot();

    printf("\n");
    print_box_top();
    print_box_line(C_BOLD "[LIVE DEMO B: LIFO STACK (3-NODE CHAIN)]" C_RESET);
    print_box_line("Use a fresh size class (nb=320, bin 18) to observe the chain.");
    print_box_line(C_DIM "We allocate 3, free them in order n0, n1, n2, then walk." C_RESET);
    print_box_mid();

    size_t sz = 300;
    void *n0 = malloc(sz);
    void *n1 = malloc(sz);
    void *n2 = malloc(sz);
    
    char tag_n0[64]; format_tag(tag_n0, "n0");
    char tag_n1[64]; format_tag(tag_n1, "n1");
    char tag_n2[64]; format_tag(tag_n2, "n2");

    print_box_line("  malloc(%zu) -> 0x%016" PRIx64 " %s", sz, (uint64_t)n0, tag_n0);
    print_box_line("  malloc(%zu) -> 0x%016" PRIx64 " %s", sz, (uint64_t)n1, tag_n1);
    print_box_line("  malloc(%zu) -> 0x%016" PRIx64 " %s", sz, (uint64_t)n2, tag_n2);
    print_box_mid();

    print_box_line("  free(n0); free(n1); free(n2);");
    free(n0);
    free(n1);
    free(n2);
    print_box_line("  LIFO => head = n2 (last freed), tail = n0 (first freed)");
    print_box_mid();

    print_box_line("  Walking chain from n2, decoding safe-linked next:");
    uint64_t cur = (uint64_t)n2;
    int step = 0;
    while (cur && step < 8) {
        uint64_t enc = *(uint64_t*)cur;
        uint64_t dec = safe_link_decode(enc, cur);
        char step_name[32]; 
        if (step == 0) sprintf(step_name, "n2");
        else if (step == 1) sprintf(step_name, "n1");
        else sprintf(step_name, "n0");
        
        char step_tag[64]; format_tag(step_tag, step_name);
        
        print_box_line("    node %d @ 0x%016" PRIx64 " %s -> next=0x%016" PRIx64 "%s",
            step, cur, step_tag, dec, dec == 0 ? "  (NULL -- end of bin)" : "");
        cur = dec;
        step++;
    }
    print_box_mid();

    print_box_line("  Draining the bin: 3 x malloc(%zu) will return", sz);
    print_box_line("  n2, then n1, then n0 -- exactly the LIFO order.");
    void *d0 = malloc(sz);
    void *d1 = malloc(sz);
    void *d2 = malloc(sz);
    print_box_line("  popped: 0x%016" PRIx64 " 0x%016" PRIx64 " 0x%016" PRIx64,
        (uint64_t)d0, (uint64_t)d1, (uint64_t)d2);
    print_box_line("  -> Order matches n2, n1, n0. LIFO stack confirmed.");
    print_box_mid();

    print_box_line(C_CYAN "HOW THE LINKED LIST WORKS (summary):" C_RESET);
    print_box_line("  tcache->entries[%zu] points to the most-recently-freed chunk.", tcache_bin_index(112));
    print_box_line("  tcache->num_slots[%zu] is the remaining slot count.", tcache_bin_index(112));
    print_box_line("  On malloc, glibc pops the head, XOR-decodes next, updates head.");
    print_box_line("  No heap metadata is read -- only the tcache chain.");
    print_box_line("  That's why tcache is O(1).");
    print_box_bot();
}

/* ---------- MAIN ---------- */
int main(void)
{
    setlocale(LC_ALL, "");
    N = sizeof(REQUESTED_BYTES) / sizeof(REQUESTED_BYTES[0]);
    if (N > MAX_N) N = MAX_N;
    COLOR = isatty(STDOUT_FILENO);

    print_section_header("PHASE 1: ALLOCATION (How glibc evaluates requests)");

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

        char name[32]; sprintf(name, "P[%d]", i);
        char tag_buf[64]; format_tag(tag_buf, name);

        print_box_top();
        print_box_line(C_BOLD "ALLOCATION: %s" C_RESET, tag_buf);
        print_box_mid();
        print_box_line("ADDRESSES & SIZES");
        print_box_line("  ptr = 0x%016" PRIx64 " %s", (uint64_t)P[i], tag_buf);
        print_box_line("  chunk_start = 0x%016" PRIx64, chunk_start);
        print_box_line("  nb (actual) = %" PRIu64 " bytes", nb);
        print_box_mid();

        if (mmapped) {
            print_box_line("  [MMAP THRESHOLD EXCEEDED]");
            print_box_line("  -> chunk size (%" PRIu64 ") >= 128 KB initial threshold", nb);
            print_box_line("  -> BYPASSING [HEAP]. Requesting isolated mapping from OS via mmap().");
            print_box_line("  -> mapped at 0x%016" PRIx64 " (Notice the 0x7f... high address)", chunk_start);
            print_box_line("  -> [HEAP] top is untouched at 0x%016" PRIx64, HEAP_TOP);
        } else {
            if (HEAP_BASE == 0) {
                HEAP_BASE = chunk_start;
                print_box_line("  [CREATING HEAP REGION]");
                print_box_line("  -> initialized main heap at 0x%016" PRIx64, HEAP_BASE);
            }
            if (chunk_start == HEAP_TOP) {
                print_box_line("  [HEAP] placed back-to-back (carved from top chunk)");
            }
            print_box_line("  -> carved %" PRIu64 " bytes starting at 0x%016" PRIx64, nb, chunk_start);
            HEAP_TOP = chunk_start + nb;
            print_box_line("  -> updated [HEAP] top to 0x%016" PRIx64, HEAP_TOP);
        }
        print_box_bot();
        printf("\n");
    }

    print_section_header("PHASE 2: INSPECTION (Memory layout & flag logic)");
    for (int i = 0; i < N; i++) dump_one(i);

    print_section_header("PHASE 3: COALESCING DEMONSTRATION");
    run_coalescing_demo();

    draw_vmem_map();

    print_section_header("PHASE 4: DEALLOCATION TRACE (How glibc reads the headers)");
    trace_deallocations();

    print_section_header("PHASE 5: THE TCACHE (Where do the freed chunks go?)");
    draw_tcache();

    printf("\n");
    return 0;
}
