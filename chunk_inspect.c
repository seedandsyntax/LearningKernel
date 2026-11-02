/* chunk_inspect_v28.c */
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

/* Linker symbols for exact section boundaries */
extern char __data_start;
extern char _edata;
extern char __bss_start;
extern char _end;

/* ---------- CONFIG ---------- */
static unsigned char FILL_BYTE         = 0xAA;       
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
static uint64_t HEAP_TOP  = 0;

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

static void format_size(uint64_t bytes, char *out, size_t max) {
    if (bytes < 1024) {
        snprintf(out, max, "%lu bytes", bytes);
    } else {
        snprintf(out, max, "%lu bytes (%.3f KiB)", bytes, bytes / 1024.0);
    }
}

static int is_little_endian(void) {
    uint16_t x = 1;
    return *((uint8_t*)&x) == 1;
}

static void print_env(void) {
    printf("\n");
    rule_heavy();
    c_(C_BCYAN); printf("  ALLOCATOR ENVIRONMENT\n"); cr_();
    rule_heavy();
    printf("  glibc version:    %s\n", gnu_get_libc_version());
    printf("  architecture:     x86-64\n");
    printf("  page size:        %ld\n", sysconf(_SC_PAGESIZE));
    
    char *env_mmap = getenv("MALLOC_MMAP_THRESHOLD_");
    printf("  MALLOC_MMAP_THRESHOLD_: %s\n", env_mmap ? env_mmap : "unset");
    char *env_tunables = getenv("GLIBC_TUNABLES");
    printf("  GLIBC_TUNABLES:   %s\n", env_tunables ? env_tunables : "unset");
    printf("  tcache_max:       1032 (default, max user request size)\n");
    printf("  tcache_count:     16 (default, TCACHE_FILL_COUNT in glibc 2.43)\n");
}

/* ---------- CHUNK BOX VISUALS ---------- */

#define CHUNK_BOX_WIDTH 63

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

static void print_chunk_box_top(void) {
    printf("  ┌");
    for (int i = 0; i < CHUNK_BOX_WIDTH; i++) printf("─");
    printf("┐\n");
}
static void print_chunk_box_mid(void) {
    printf("  ├");
    for (int i = 0; i < CHUNK_BOX_WIDTH; i++) printf("─");
    printf("┤\n");
}
static void print_chunk_box_bot(void) {
    printf("  └");
    for (int i = 0; i < CHUNK_BOX_WIDTH; i++) printf("─");
    printf("┘\n");
}
static void print_chunk_box_line(const char *fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    int len = visible_len(buf);
    printf("  │ ");
    fputs(buf, stdout);
    for (int i = len; i < CHUNK_BOX_WIDTH - 2; i++) putchar(' ');
    printf(" │\n");
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
    print_chunk_box_top();
    if (mmapped) {
        print_chunk_box_line(C_BCYAN "CHUNK %d of %d  " C_RESET C_BYELLOW "[MMAP]  MMAPPED CHUNK" C_RESET, i, N);
    } else {
        print_chunk_box_line(C_BCYAN "CHUNK %d of %d  " C_RESET C_BGREEN "[HEAP]  BRK CHUNK" C_RESET, i, N);
    }
    print_chunk_box_mid();

    if (mmapped) {
        print_chunk_box_line("requested: %zu bytes", rq);
        print_chunk_box_line("nb:        %" PRIu64 " bytes", nb);
        print_chunk_box_line(C_DIM "(mmapped chunks do not have neighbors or overlap)" C_RESET);
    } else {
        uint64_t in_chunk = nb - 16;
        uint64_t usable   = nb - 8;
        uint64_t overlap  = (rq > in_chunk) ? (rq - in_chunk) : 0;
        print_chunk_box_line("requested: %zu bytes", rq);
        print_chunk_box_line("nb:        %" PRIu64 " bytes  (total chunk size)", nb);
        print_chunk_box_line("in-chunk:  %" PRIu64 " bytes  (strictly inside chunk, nb - 16)", in_chunk);
        print_chunk_box_line("usable:    %" PRIu64 " bytes  (malloc_usable_size, nb - 8)", usable);
        print_chunk_box_line("overlap:   %" PRIu64 " bytes  (req - in-chunk, tail payload)", overlap);
    }
    print_chunk_box_mid();

    // prev_size
    print_chunk_box_line(C_BBLUE "[PREV_SIZE] " C_RESET "chunk_start + 0   (0x%" PRIx64 ")", cstart);
    char memstr[32] = {0};
    for (int b=0; b<8; b++) sprintf(memstr + b*3, "%02x ", (unsigned)((prev_slot >> (8*b)) & 0xff));
    print_chunk_box_line("  memory: %s " C_DIM "(%s Endian)" C_RESET, memstr, is_little_endian() ? "Little" : "Big");
    
    if (mmapped) {
        print_chunk_box_line("  STATE:  " C_BYELLOW "OFFSET TO MMAP BASE" C_RESET);
        print_chunk_box_line("  WHY:    IS_MMAPPED = 1. Not on contiguous heap.");
        print_chunk_box_line("          Holds offset to mmap base for munmap().");
    } else {
        if (p_inuse) {
            if (prev_slot == 0) {
                print_chunk_box_line("  STATE:  " C_BGREEN "UNUSED (all zeroes)" C_RESET);
            } else {
                print_chunk_box_line("  STATE:  " C_YELLOW "IGNORED (contains active tail payload)" C_RESET);
            }
            print_chunk_box_line(C_DIM "  LOGIC:  if (!(size & PREV_INUSE)) { read prev_size; }" C_RESET);
            print_chunk_box_line(C_DIM "          P = 1 → SKIP read" C_RESET);
            if (prev_slot != 0) {
                print_chunk_box_line(C_DIM "          The 0x%02x bytes are active user payload" C_RESET, FILL_BYTE);
            }
        } else {
            print_chunk_box_line("  STATE:  " C_YELLOW "ACTIVE (holds previous chunk size)" C_RESET);
            print_chunk_box_line(C_DIM "  LOGIC:  if (!(size & PREV_INUSE)) { read prev_size; }" C_RESET);
            print_chunk_box_line(C_DIM "          P = 0 → EXECUTE read" C_RESET);
            print_chunk_box_line(C_DIM "          prev_chunk = 0x%" PRIx64 " - 0x%" PRIx64 " = 0x%" PRIx64 C_RESET,
                cstart, prev_slot, cstart - prev_slot);
        }
    }
    print_chunk_box_mid();

    // size
    print_chunk_box_line(C_BBLUE "[SIZE]      " C_RESET "chunk_start + 8   (0x%" PRIx64 ")", cstart + 8);
    char size_memstr[32] = {0};
    for (int b=0; b<8; b++) sprintf(size_memstr + b*3, "%02x ", (unsigned)((raw_size >> (8*b)) & 0xff));
    print_chunk_box_line("  memory: %s " C_DIM "(%s Endian)" C_RESET, size_memstr, is_little_endian() ? "Little" : "Big");
    print_chunk_box_line("  raw:    0x%016" PRIx64, raw_size);
    print_chunk_box_line("  math:   (0x%lx & ~0xF) | 0x%lx", (unsigned long)raw_size, (unsigned long)(raw_size & 0xF));
    print_chunk_box_line("          = 0x%" PRIx64 " (size) | 0x%lx (flags)", nb, (unsigned long)(raw_size & 0xF));
    
    if (mmapped) {
        print_chunk_box_line("  P=" C_GRAY "N/A" C_RESET " (mmap chunks have no neighbors)");
        print_chunk_box_line("  MMAP=" C_YELLOW "1" C_RESET " → this chunk was mmapped");
        print_chunk_box_line("  chunksize = %" PRIu64 " bytes", nb);
        print_chunk_box_line("  mmap_size = %" PRIu64 " bytes (chunksize + 16)", nb + 16);
    } else {
        print_chunk_box_line("  P=%d (prev %s)  MMAP=0 (brk)", p_inuse, p_inuse ? "allocated/in-tcache" : "free");
        print_chunk_box_line("  size = %" PRIu64 " bytes", nb);
    }
    
    if (!mmapped) {
        print_chunk_box_mid();
        print_chunk_box_line(C_BBLUE "[USER AREA] " C_RESET "(%" PRIu64 " bytes strictly inside chunk)", nb - 16);
        
        uint64_t total_rows = (nb - 16) / 8;
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
            char mstr[32] = {0};
            for (int b=0; b<8; b++) sprintf(mstr + b*3, "%02x ", (unsigned)((v >> (8*b)) & 0xff));
            print_chunk_box_line("  0x%" PRIx64 ": %s %s", a, mstr, r == 0 ? " (user_ptr)" : "");
        }
        if (show_last > 0) {
            print_chunk_box_line(C_DIM "  ... %" PRIu64 " bytes hidden ..." C_RESET, (total_rows - show_first - show_last) * 8);
            for (uint64_t r = total_rows - show_last; r < total_rows; r++) {
                uint64_t a = u_addr + r*8;
                uint64_t v = *(uint64_t*)a;
                char mstr[32] = {0};
                for (int b=0; b<8; b++) sprintf(mstr + b*3, "%02x ", (unsigned)((v >> (8*b)) & 0xff));
                print_chunk_box_line("  0x%" PRIx64 ": %s %s", a, mstr, r == total_rows - 1 ? " (last in-chunk row)" : "");
            }
        }

        uint64_t overlap = (rq > (nb - 16)) ? (rq - (nb - 16)) : 0;
        if (overlap > 0) {
            print_chunk_box_mid();
            print_chunk_box_line(C_BBLUE "[TAIL PAYLOAD OVERLAP] " C_RESET "0x%" PRIx64, u_addr + (nb - 16));
            uint64_t a = u_addr + (nb - 16);
            uint64_t v = *(uint64_t*)a;
            char mstr[32] = {0};
            for (int b=0; b<8; b++) sprintf(mstr + b*3, "%02x ", (unsigned)((v >> (8*b)) & 0xff));
            print_chunk_box_line("  memory: %s", mstr);
            print_chunk_box_line("  STATE:  " C_BRED "%" PRIu64 " byte(s) of tail payload overlap" C_RESET, overlap);
            print_chunk_box_line("          with next chunk's prev_size.");
            print_chunk_box_line(C_DIM "  NOTE:   This is " C_GREEN "NOT" C_RESET C_DIM " a buffer overflow." C_RESET);
            print_chunk_box_line(C_DIM "          glibc lends these 8 bytes to the user." C_RESET);
        }
        print_chunk_box_mid();
        print_chunk_box_line(C_DIM "Next chunk begins at 0x%" PRIx64 C_RESET, u_addr + (nb - 16));
    }
    print_chunk_box_bot();
}

/* ---------- COALESCING DEMO ---------- */
static void run_coalescing_demo(void) {
    printf("\n");
    print_chunk_box_top();
    print_chunk_box_line(C_BCYAN "PHASE 3: COALESCING DEMONSTRATION" C_RESET);
    print_chunk_box_line(C_DIM "The crux of prev_size and the P bit." C_RESET);
    print_chunk_box_mid();
    print_chunk_box_line("Why track PREV_INUSE? To know if prev_size is safe to read.");
    print_chunk_box_line("If it's 1, we can't merge backward. If 0, we can.");
    print_chunk_box_line("We allocate two 2000-byte chunks (nb=2016) to bypass tcache.");
    print_chunk_box_line(C_DIM "This forces glibc to use the unsorted bin and merge logic." C_RESET);
    print_chunk_box_mid();
    
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

    print_chunk_box_line(C_YELLOW "[STEP 1] Initial state (both allocated)" C_RESET);
    print_chunk_box_line("  A = %p (chunk %lu bytes)", A, a_nb);
    print_chunk_box_line("  B = %p (chunk %lu bytes)", B, b_nb);
    print_chunk_box_line("  Before freeing A:");
    print_chunk_box_line("    B.P = 1 (A is marked in-use)");
    print_chunk_box_line("    A.P = 1 (chunk before A is in-use)");
    print_chunk_box_mid();

    print_chunk_box_line(C_YELLOW "[STEP 2] free(A)" C_RESET);
    free(A);
    uint64_t b_size_after = *(uint64_t*)(b_chunk + 8);
    uint64_t b_prev_after = *(uint64_t*)(b_chunk);
    print_chunk_box_line("  free(A) actions:");
    print_chunk_box_line("    glibc checks B.P. It's 1, validating A was in-use.");
    print_chunk_box_line("    glibc checks A.P. It's 1, so no backward merge.");
    print_chunk_box_line("    glibc writes A's size to B.prev_size, clears B.P.");
    print_chunk_box_line("  B.prev_size  = 0x%016" PRIx64, b_prev_after);
    print_chunk_box_line("  B.size       = 0x%016" PRIx64 " (P=0)", b_size_after);
    print_chunk_box_mid();

    print_chunk_box_line(C_YELLOW "[STEP 3] free(B)" C_RESET);
    free(B);
    uint64_t a_size_after = *(uint64_t*)(a_chunk + 8);
    uint64_t merged_nb = a_size_after & ~0xfULL;
    print_chunk_box_line("  free(B) actions:");
    print_chunk_box_line("    glibc checks B.P. It's 0, meaning A is free.");
    print_chunk_box_line("    Reads B.prev_size (0x%lx), merges A and B.", b_prev_after);
    print_chunk_box_line("    Calculates prev_chunk = 0x%lx - 0x%lx = 0x%lx", b_chunk, b_prev_after, b_chunk - b_prev_after);
    print_chunk_box_line("    Merges A + B into one giant free chunk.");
    print_chunk_box_line("    A.size       = 0x%016" PRIx64 " (merged %lu bytes)", a_size_after, merged_nb);
    print_chunk_box_line(C_DIM "    Because the result borders the Top Chunk, it absorbs Top." C_RESET);
    print_chunk_box_mid();
    print_chunk_box_line(C_GREEN "CONCLUSION:" C_RESET);
    print_chunk_box_line("B.P initially indicated that A was marked in-use.");
    print_chunk_box_line("When A was freed, glibc validated A using B.P, checked A.P,");
    print_chunk_box_line("wrote A's size into B.prev_size, and cleared B.P.");
    print_chunk_box_line("When B was freed, B.P=0 allowed backward consolidation,");
    print_chunk_box_line("and A + B + Top became the new Top Chunk.");
    print_chunk_box_bot();
}

/* ---------- DEALLOCATION TRACE ---------- */
static void trace_deallocations(void) {
    printf("\n");
    print_chunk_box_top();
    print_chunk_box_line(C_BCYAN "PHASE 4: DEALLOCATION TRACE (How glibc reads the headers)" C_RESET);
    print_chunk_box_line(C_DIM "Tracing actual free() calls." C_RESET);
    print_chunk_box_line(C_DIM "The ONLY thing passed to free() is the user pointer." C_RESET);
    print_chunk_box_line(C_DIM "Everything else is derived via pointer math." C_RESET);
    print_chunk_box_mid();

    for (int i = 0; i < N; i++) {
        uint64_t u_ptr    = (uint64_t)P[i];
        uint64_t cstart   = u_ptr - 16;
        uint64_t raw_size = *(uint64_t*)(cstart + 8);
        uint64_t prev_size = *(uint64_t*)(cstart);
        uint64_t nb       = raw_size & ~0xfULL;
        int p_inuse       = raw_size & 1;
        int mmapped       = (raw_size >> 1) & 1;

        print_chunk_box_line(C_BYELLOW "free(0x%" PRIx64 ") [Chunk %d]" C_RESET, u_ptr, i);
        print_chunk_box_line("  " C_CYAN "1. THE CALL:" C_RESET " free(ptr)");
        print_chunk_box_line("     ptr = 0x%" PRIx64, u_ptr);
        
        print_chunk_box_line("  " C_CYAN "2. FIND CHUNK:" C_RESET " chunk_start = ptr - 16");
        print_chunk_box_line("     0x%" PRIx64 " - 16 = " C_BCYAN "0x%" PRIx64 C_RESET, u_ptr, cstart);
        
        print_chunk_box_line("  " C_CYAN "3. OBSERVED METADATA (at 0x%" PRIx64 "):" C_RESET, cstart + 8);
        print_chunk_box_line("     size raw = " C_BYELLOW "0x%016" PRIx64 C_RESET, raw_size);
        print_chunk_box_line("     P bit    = " C_BYELLOW "%d" C_RESET, p_inuse);
        print_chunk_box_line("     M bit    = " C_BMAG "%d" C_RESET, mmapped);
        print_chunk_box_line("     prev_size= 0x%" PRIx64, prev_size);
        
        if (mmapped) {
            print_chunk_box_line("  " C_CYAN "4. INTERPRETATION:" C_RESET);
            print_chunk_box_line("     M = 1 → this chunk is mmapped, not on heap.");
            print_chunk_box_line("     P bit is " C_GRAY "N/A" C_RESET " (no neighbors).");
            
            print_chunk_box_line("  " C_CYAN "5. ACTION (MMAPPED PATH):" C_RESET);
            print_chunk_box_line("     Bypass bins. Call munmap_chunk().");
            print_chunk_box_line("     " C_DIM "block_start = chunk_start - prev_size" C_RESET);
            print_chunk_box_line("     0x%" PRIx64 " - 0x%" PRIx64 " = " C_BCYAN "0x%" PRIx64 C_RESET, cstart, prev_size, cstart - prev_size);
            
            uint64_t block_size = prev_size + nb + 16;
            print_chunk_box_line("     " C_DIM "block_size = prev_size + chunksize + 16" C_RESET);
            print_chunk_box_line("     0x%" PRIx64 " + 0x%" PRIx64 " + 16 = " C_BGREEN "0x%" PRIx64 C_RESET, prev_size, nb, block_size);
            print_chunk_box_line("     " C_BMAG "Kernel munmaps 0x%lx bytes at 0x%lx" C_RESET, block_size, cstart - prev_size);
            print_chunk_box_line("     Memory is instantly returned to the OS.");
        } else {
            print_chunk_box_line("  " C_CYAN "4. INTERPRETATION:" C_RESET);
            print_chunk_box_line("     M = 0 → this chunk is on the heap.");
            if (p_inuse) {
                print_chunk_box_line("     P = 1 → previous physical chunk is marked in-use.");
                print_chunk_box_line("     (It may be allocated, or held in a tcache bin).");
            } else {
                print_chunk_box_line("     P = 0 → previous physical chunk is free.");
                print_chunk_box_line("     prev_size is valid boundary-tag metadata.");
            }
            
            print_chunk_box_line("  " C_CYAN "5. ACTION (HEAP PATH):" C_RESET);
            
            if (nb <= 1032) {
                print_chunk_box_line("     Requested size (%zu) <= tcache_max (1032).", REQ[i]);
                print_chunk_box_line("     " C_BGREEN "Tcache eligible" C_RESET);
                print_chunk_box_line("     ACTION: Insert into tcache thread-local bin.");
                print_chunk_box_line("     Normal consolidation is SKIPPED.");
                print_chunk_box_line(C_DIM "     prev_size is NOT read for backward merging." C_RESET);
                print_chunk_box_line(C_DIM "     (This is why P=0 doesn't force a merge here)." C_RESET);
            } else {
                print_chunk_box_line("     Requested size (%zu) > tcache_max (1032). Bypasses tcache.", REQ[i]);
                if (p_inuse) {
                    print_chunk_box_line("     ACTION: No backward merge (P=1).");
                } else {
                    print_chunk_box_line("     ACTION: glibc READS prev_size (0x%lx).", prev_size);
                    print_chunk_box_line("     prev_chunk = 0x%lx - 0x%lx = 0x%lx", cstart, prev_size, cstart - prev_size);
                    print_chunk_box_line("     " C_BRED "glibc merges backward!" C_RESET);
                }
                print_chunk_box_line("     ACTION: Check forward merge, insert into unsorted bin.");
            }
        }
        
        if (i < N - 1) print_chunk_box_mid();
        free(P[i]);
    }
    print_chunk_box_bot();
}

/* ---------- TCACHE TRACE ---------- */
static void draw_tcache(void) {
    printf("\n");
    print_chunk_box_top();
    print_chunk_box_line(C_BCYAN "PHASE 5: THE TCACHE (Where do the freed chunks go?)" C_RESET);
    print_chunk_box_line(C_DIM "tcache is the Thread Local Cache." C_RESET);
    print_chunk_box_line(C_DIM "glibc 2.43 uses a randomized 'key' to prevent double-frees." C_RESET);
    print_chunk_box_mid();

    uint64_t p0_ptr = (uint64_t)P[0];
    if (p0_ptr == 0) {
        print_chunk_box_line(C_RED "Error: P[0] was not allocated." C_RESET);
        print_chunk_box_bot();
        return;
    }

    uint64_t next_val = *(uint64_t*)(p0_ptr);
    uint64_t key_val  = *(uint64_t*)(p0_ptr + 8);

    print_chunk_box_line("Let's look at Chunk 0 (P[0]). It was freed in Phase 4.");
    print_chunk_box_line("  P[0] user area starts at: 0x%" PRIx64, p0_ptr);
    print_chunk_box_line("  The first 16 bytes were overwritten by tcache metadata:");
    print_chunk_box_line("    [next] = 0x%016" PRIx64, next_val);
    print_chunk_box_line("    [key]  = 0x%016" PRIx64, key_val);
    print_chunk_box_mid();

    // 1. Verify the "next" pointer (safe-linked)
    uint64_t recovered_next = next_val ^ (p0_ptr >> 12);
    print_chunk_box_line(C_GREEN "STEP 1: VERIFYING THE CHUNK IS IN TCACHE" C_RESET);
    print_chunk_box_line("In glibc 2.34+, the [next] pointer is 'safe-linked'.");
    print_chunk_box_line("It is obfuscated by XORing it with (chunk_address >> 12).");
    print_chunk_box_line("  chunk_addr >> 12 = 0x%lx", (p0_ptr >> 12));
    print_chunk_box_line("  [next] ^ (addr >> 12) = 0x%lx", recovered_next);
    
    if (recovered_next == 0) {
        print_chunk_box_line("  Since the result is 0x0 (NULL), this chunk is the " C_BGREEN "HEAD" C_RESET " of the bin.");
        print_chunk_box_line("  " C_GREEN "PROOF: P[0] IS DEFINITELY IN THE TCACHE!" C_RESET);
    } else {
        print_chunk_box_line("  It points to the next chunk at 0x%lx.", recovered_next);
    }
    print_chunk_box_mid();

    // 2. Explain the Key
    print_chunk_box_line(C_YELLOW "STEP 2: WHY THE [key] LOOKS INVALID" C_RESET);
    print_chunk_box_line("In glibc 2.43, the [key] is NOT a pointer to the tcache struct.");
    print_chunk_box_line("It is a randomized 64-bit cookie (tcache_key).");
    print_chunk_box_line("When you free a chunk, glibc checks if this key matches.");
    print_chunk_box_line("It doesn't abort immediately on a match; it scans the");
    print_chunk_box_line("bin first to confirm a real double-free before aborting.");
    print_chunk_box_line("Because it's a random cookie, it looks like garbage.");
    print_chunk_box_line("It does NOT mean the chunk isn't in tcache.");
    print_chunk_box_mid();

    // 3. Explain where the bins are
    print_chunk_box_line(C_CYAN "STEP 3: WHERE ARE THE TCACHE BINS?" C_RESET);
    print_chunk_box_line("The actual bins live in the tcache_perthread_struct:");
    print_chunk_box_line("  uint16_t num_slots[64];");
    print_chunk_box_line("  tcache_entry *entries[64];");
    print_chunk_box_line("num_slots is the number of REMAINING slots, not used ones.");
    print_chunk_box_line("Chunk 0 is 112 bytes (bin index 5).");
    print_chunk_box_line("With a default of 16 slots, after 1 insertion, num_slots[5] = 15.");
    print_chunk_box_line("Because of the random key, we cannot easily locate it");
    print_chunk_box_line("from the chunk metadata alone without reading the TLS.");
    print_chunk_box_mid();

    print_chunk_box_line(C_GREEN "HOW THE LINKED LIST WORKS:" C_RESET);
    print_chunk_box_line("  tcache->entries[5] points to P[0].");
    print_chunk_box_line("  tcache->num_slots[5] is 15.");
    print_chunk_box_line("  If you call malloc(100) right now, glibc will:");
    print_chunk_box_line("    1. Look at tcache->entries[5] (it's P[0]).");
    print_chunk_box_line("    2. Pop P[0] from tcache->entries[5].");
    print_chunk_box_line("    3. Return P[0] without ever touching the heap metadata.");
    print_chunk_box_line("  This is why tcache is incredibly fast (O(1)).");
    print_chunk_box_bot();
}

/* ---------- VIRTUAL MEMORY MAP GENERATOR ---------- */
#define VMM_BOX_WIDTH 64

static void vmm_box_top(const char *addr_str) {
    printf("  %-18s ┌", addr_str);
    for (int i = 0; i < VMM_BOX_WIDTH + 2; i++) printf("─");
    printf("┐\n");
}
static void vmm_box_mid(const char *addr_str) {
    printf("  %-18s ├", addr_str);
    for (int i = 0; i < VMM_BOX_WIDTH + 2; i++) printf("─");
    printf("┤\n");
}
static void vmm_box_bot(const char *addr_str) {
    printf("  %-18s └", addr_str);
    for (int i = 0; i < VMM_BOX_WIDTH + 2; i++) printf("─");
    printf("┘\n");
}
static void vmm_box_line(const char *fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    int len = visible_len(buf);
    printf("  %-18s │ ", "");
    fputs(buf, stdout);
    for (int i = len; i < VMM_BOX_WIDTH; i++) putchar(' ');
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

    vmm_box_top("0xffffffffffffffff");
    vmm_box_line(C_BRED "                       KERNEL SPACE" C_RESET);
    vmm_box_line(C_DIM "            (direct mapping, vmalloc, kernel code)" C_RESET);
    vmm_box_line(C_DIM "            [8 TiB guard hole below, omitted for scale]" C_RESET);
    vmm_box_mid("0xffff800000000000");
    
    vmm_box_line("");
    vmm_box_line(C_DIM "                   NON-CANONICAL GAP" C_RESET);
    vmm_box_line(C_DIM "          (unaddressable by 48-bit pointers)" C_RESET);
    vmm_box_line("");
    
    vmm_box_mid("0x0000800000000000");
    vmm_box_mid("0x00007fffffffffff"); 
    vmm_box_line(C_DIM "           [4 KiB guard hole at top of user space]" C_RESET);
    vmm_box_mid("0x00007ffffffff000"); 
    
    vmm_box_line(C_CYAN "[STACK]    local variables, function frames" C_RESET);
    vmm_box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, s_start, s_end);
    vmm_box_line("           size:  %s", sz_stack);
    vmm_box_mid(" ");
    
    vmm_box_line(C_DIM "                   UNMAPPED GAP" C_RESET);
    vmm_box_mid(" ");

    vmm_box_line(C_BYELLOW "[MMAP]     shared libs & large mallocs" C_RESET);
    vmm_box_line("           span:  0x%016" PRIx64 " - 0x%016" PRIx64, mmap_min, mmap_max);
    vmm_box_line("           mapped: %s across %" PRIu64 " regions", sz_mmap, mmap_count);
    vmm_box_line("           RSS:   %" PRIu64 " KB resident in physical RAM", mmap_rss_kb);
    for (int i = 0; i < N; i++) {
        if (IS_MMAPPED_ARR[i]) {
            vmm_box_line("           malloc(%6zu) -> 0x%016" PRIx64, REQ[i], (uint64_t)P[i]);
        }
    }
    vmm_box_mid(" ");
    
    vmm_box_line(C_DIM "                   UNMAPPED GAP" C_RESET);
    vmm_box_mid(" ");

    vmm_box_line(C_BGREEN "[HEAP]     brk region (contiguous, grows upward)" C_RESET);
    vmm_box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, h_start, h_end);
    vmm_box_line("           size:  %s", sz_heap);
    for (int i = 0; i < N; i++) {
        if (!IS_MMAPPED_ARR[i]) {
            uint64_t chunk_start = (uint64_t)P[i] - 16;
            uint64_t raw_size = *(uint64_t*)((char*)P[i] - 8);
            uint64_t nb = raw_size & ~0xfULL;
            uint64_t chunk_end = chunk_start + nb;
            vmm_box_line("           chunk [0x%016" PRIx64 " - 0x%016" PRIx64 ")", chunk_start, chunk_end);
        } else {
            vmm_box_line(C_DIM "           (mmap bypassed heap — top unchanged)" C_RESET);
        }
    }
    
    vmm_box_line(C_BGREEN "           [TOP CHUNK] free space remaining in heap" C_RESET);
    vmm_box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, HEAP_TOP, h_end);
    vmm_box_line("           size:  %s", sz_top);
    vmm_box_mid(" ");
    
    vmm_box_line(C_BBLUE "[DATA]     initialized writable globals" C_RESET);
    vmm_box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, data_start, data_end);
    vmm_box_line("           size:  %s", sz_data);
    vmm_box_mid(" ");

    vmm_box_line(C_BBLUE "[BSS]      uninitialized globals" C_RESET);
    vmm_box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, bss_start, bss_end);
    vmm_box_line("           size:  %s", sz_bss);
    vmm_box_mid(" ");

    vmm_box_line(C_BBLUE "[READ-ONLY MAPPING]" C_RESET);
    vmm_box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, rodata_start, rodata_end);
    vmm_box_line("           size:  %s", sz_rodata);
    vmm_box_mid(" ");

    vmm_box_line(C_BBLUE "[EXECUTABLE MAPPING]" C_RESET);
    vmm_box_line("           range: 0x%016" PRIx64 " - 0x%016" PRIx64, text_start, text_end);
    vmm_box_line("           size:  %s", sz_text);
    
    vmm_box_bot("0x0000000000000000");
    printf("\n");
}

/* ---------- MAIN ---------- */
int main(void)
{
    N = sizeof(REQUESTED_BYTES) / sizeof(REQUESTED_BYTES[0]);
    if (N > MAX_N) N = MAX_N;
    COLOR = isatty(STDOUT_FILENO);

    print_env();

    printf("\n");
    rule_heavy();
    c_(C_BCYAN); printf("  PHASE 1: ALLOCATION (How glibc evaluates requests)\n"); cr_();
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
    c_(C_BCYAN); printf("  PHASE 2: INSPECTION (Memory layout & flag logic)\n"); cr_();
    rule_heavy();
    for (int i = 0; i < N; i++) dump_one(i);

    run_coalescing_demo();

    draw_vmem_map();

    trace_deallocations();

    draw_tcache();

    printf("\n");
    return 0;
}
