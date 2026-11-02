/* chunk_inspect_v6.c */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>

/* ---------- CONFIG ---------- */
static unsigned char FILL_BYTE         = 0xAA;
static size_t        DISPLAY_MAX_BYTES = 64;
static int           FREE_AT_END       = 1;
static int           DUMP_AFTER_FREE   = 0;

/* The exact sequence from your screenshot */
static size_t REQUESTED_BYTES[] = {
    100, 1000, 127999, 140000, 120000, 110000, 200, 999888444
};

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

static void field_value(const char *label, uint64_t v) {
    field_label(label);
    printf("0x%016" PRIx64 "\n", v);
}

static void print_byte(uint8_t b) {
    if (!COLOR) { printf("%02x", b); return; }
    if (b == FILL_BYTE && b != 0) fputs(C_BMAG, stdout);
    else if (b == 0)              fputs(C_GRAY, stdout);
    else                          fputs(C_CYAN, stdout);
    printf("%02x", b);
    cr_();
}

static void print_memory_row(uint64_t v) {
    for (int i = 0; i < 8; i++) {
        print_byte((v >> (8*i)) & 0xff);
        if (i < 7) printf(" ");
    }
}

static void field_memory(const char *label, uint64_t v) {
    field_label(label);
    print_memory_row(v);
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

/* ---------- RUNTIME ---------- */
#define MAX_N 64
static int    N;
static void  *P[MAX_N];
static size_t REQ[MAX_N];
static int    IS_MMAPPED_ARR[MAX_N];

/* Heap region tracking */
static uint64_t HEAP_BASE = 0;
static uint64_t HEAP_TOP  = 0;
static const uint64_t MMAP_THRESHOLD = 128 * 1024;

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
    int non_main = (raw_size >> 2) & 1;

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
        printf("  These are allocated via mmap() because they exceed the 128KB threshold.\n");
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
        uint64_t usable   = nb - 8;
        uint64_t spill    = (rq > in_chunk) ? (rq - in_chunk) : 0;
        
        printf("  %-20s %zu\n",         "requested bytes", rq);
        printf("  %-20s %" PRIu64 "\n", "chunk size (nb)", nb);
        printf("  %-20s %" PRIu64 "\n", "in-chunk user bytes", in_chunk);
        printf("  %-20s %" PRIu64 "\n", "spill bytes", spill);

        /* prev_size */
        printf("\n  ");
        c_(C_DIM); printf("── "); cr_();
        c_(C_BBLUE); printf("prev_size"); cr_();
        c_(C_DIM); printf(" (chunk_start + 0) ───────────────────────────────────────\n"); cr_();
        field_addr("address", cstart);
        field_memory("memory", prev_slot);

        if (p_inuse) {
            field_label("STATE");
            c_(C_BGREEN); printf("UNUSED"); cr_();
            printf("\n");
            c_(C_DIM);
            printf("     WHY        bit 0 of \"size\" (PREV_INUSE) is 1\n");
            printf("                → previous chunk is allocated\n");
            printf("                → bytes above are leftover user data\n");
            cr_();
        } else {
            field_label("STATE");
            c_(C_BYELLOW); printf("HOLDS SIZE OF PREVIOUS CHUNK"); cr_();
            printf("\n");
            c_(C_DIM);
            printf("     WHY        bit 0 of \"size\" (PREV_INUSE) is 0\n");
            printf("                → previous_start = 0x%" PRIx64 " - 0x%" PRIx64 " = 0x%" PRIx64 "\n",
                   cstart, prev_slot, cstart - prev_slot);
            cr_();
        }

        /* size */
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

        /* user area & spill */
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
            print_memory_row(v);
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
                print_memory_row(v);
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
        /* --------------------------------------------------------- */
        /* MMAPPED CHUNK SPECIAL HANDLING                            */
        /* --------------------------------------------------------- */
        printf("  %-20s %zu\n",         "requested bytes", rq);
        printf("  %-20s %" PRIu64 "\n", "chunk size (nb)", nb);
        printf("  %-20s %s\n",          "in-chunk user bytes", "N/A (entire mapping is for this chunk)");
        printf("  %-20s %s\n",          "spill bytes",          "N/A (no next chunk to spill into)");

        /* prev_size */
        printf("\n  ");
        c_(C_DIM); printf("── "); cr_();
        c_(C_BBLUE); printf("prev_size"); cr_();
        c_(C_DIM); printf(" (chunk_start + 0) ───────────────────────────────────────\n"); cr_();
        field_addr("address", cstart);
        field_memory("memory", prev_slot);
        field_value("as int", prev_slot);
        
        field_label("STATE");
        c_(C_BYELLOW); printf("OFFSET TO MMAP BASE"); cr_();
        printf("\n");
        c_(C_DIM);
        printf("     WHY        bit 1 of \"size\" (IS_MMAPPED) is 1\n");
        printf("                → this chunk is not on the contiguous heap\n");
        printf("                → there is no 'previous chunk'\n");
        printf("                → this field stores the offset from the kernel's mmap\n");
        printf("                  base to the chunk's start (so free() can munmap correctly)\n");
        printf("                → offset = 0x%" PRIx64 "\n", prev_slot);
        cr_();

        /* size */
        printf("\n  ");
        c_(C_DIM); printf("── "); cr_();
        c_(C_BBLUE); printf("size"); cr_();
        c_(C_DIM); printf(" (chunk_start + 8) ─────────────────────────────────────────\n"); cr_();
        field_addr("address", cstart + 8);
        field_memory("memory", raw_size);
        field_value("as int", raw_size);
        
        printf("     bit 0 ");
        c_(C_GRAY); printf("[%d]", p_inuse); cr_();
        printf(" PREV_INUSE      %s\n", p_inuse ? "1" : "0 (mmapped chunks don't have a previous chunk)");

        printf("     bit 1 ");
        if (mmapped) c_(C_BYELLOW); else c_(C_GRAY);
        printf("[%d]", mmapped); cr_();
        printf(" IS_MMAPPED      ");
        if (mmapped) {
            c_(C_YELLOW); printf("1 → this chunk was mmapped, use munmap() on free\n"); cr_();
        } else {
            printf("0\n");
        }

        field_label("size");
        printf("0x%" PRIx64 " = %" PRIu64 " bytes (total mapping length)\n", nb, nb);

        /* user area */
        printf("\n  ");
        c_(C_DIM); printf("── "); cr_();
        c_(C_BBLUE); printf("user area"); cr_();
        c_(C_DIM); printf(" ─────────────────────────────────────────────────────────\n"); cr_();
        printf("     pointer malloc returned: 0x%" PRIx64 "\n", u_addr);
        printf("     The 16-byte header sits right before it.\n");
        printf("     The rest of the mapping up to (chunk_start + size) is yours.\n");
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
            printf("    → chunk size (%" PRIu64 ") >= 128 KB (%" PRIu64 ")\n", nb, MMAP_THRESHOLD);
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
