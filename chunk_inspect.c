/* chunk_inspect_v3.c */
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

static size_t REQUESTED_BYTES[] = {
    1, 8, 16, 17, 24, 25, 32, 33, 64, 100, 1000
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
                      const char *meaning_1, const char *meaning_0,
                      int highlight_zero) {
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

/* ---------- DUMP ONE CHUNK ---------- */
static void dump_one(int i)
{
    void    *u  = P[i];
    size_t   rq = REQ[i];

    uint64_t raw_size  = *(uint64_t*)((char*)u - 8);
    uint64_t prev_slot = *(uint64_t*)((char*)u - 16);
    uint64_t nb        = raw_size & ~0xfULL;
    uint64_t in_chunk  = nb - 16;
    uint64_t usable    = nb - 8;
    uint64_t spill     = (rq > in_chunk) ? (rq - in_chunk) : 0;
    uint64_t cstart    = (uint64_t)u - 16;

    int p_inuse  = (raw_size >> 0) & 1;
    int mmapped  = (raw_size >> 1) & 1;
    int non_main = (raw_size >> 2) & 1;

    printf("\n");
    rule_heavy();
    c_(C_BCYAN); printf("  Chunk %d of %d\n", i, N); cr_();
    rule_heavy();
    printf("\n");

    printf("  %-20s %zu\n",         "requested bytes", rq);
    printf("  %-20s %" PRIu64 "\n", "chunk size (nb)", nb);
    printf("  %-20s 16 (prev_size 8 + size 8)\n", "header bytes");
    printf("  %-20s %" PRIu64 "\n", "in-chunk user bytes", in_chunk);
    printf("  %-20s %" PRIu64 "  (in-chunk + 8 borrowed from next chunk's unused prev_size)\n",
           "total usable bytes", usable);
    printf("  %-20s %" PRIu64 "\n", "spill bytes", spill);

    /* prev_size */
    printf("\n  ");
    c_(C_DIM); printf("── "); cr_();
    c_(C_BBLUE); printf("prev_size"); cr_();
    c_(C_DIM); printf(" (chunk_start + 0) ───────────────────────────────────────\n"); cr_();
    field_addr("address", cstart);
    field_memory("memory", prev_slot);
    field_value("as int", prev_slot);

    if (p_inuse) {
        field_label("STATE");
        c_(C_BGREEN); printf("UNUSED"); cr_();
        printf("\n");
        c_(C_DIM);
        printf("     WHY        bit 0 of \"size\" (PREV_INUSE) is 1\n");
        printf("                → previous chunk is allocated\n");
        printf("                → glibc has no reason to store its size here\n");
        printf("                → bytes above are leftover user data (spill or zero),\n");
        printf("                  NOT a size value\n");
        cr_();
    } else {
        field_label("STATE");
        c_(C_BYELLOW); printf("HOLDS SIZE OF PREVIOUS CHUNK"); cr_();
        printf("\n");
        c_(C_DIM);
        printf("     WHY        bit 0 of \"size\" (PREV_INUSE) is 0\n");
        printf("                → previous chunk is free\n");
        printf("                → glibc stores its size here so free() can find it\n");
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
    field_value("as int", raw_size);
    print_bit(0, "PREV_INUSE",     p_inuse,
              "previous chunk is allocated",
              "previous chunk is free",
              1);
    print_bit(1, "IS_MMAPPED",     mmapped,
              "chunk came from mmap (isolated, not merged)",
              "chunk came from brk (normal heap)",
              0);
    print_bit(2, "NON_MAIN_ARENA", non_main,
              "chunk lives in a non-main thread arena",
              "chunk lives in the main arena",
              0);
    field_label("size");
    printf("0x%" PRIx64 " = %" PRIu64 " bytes\n", nb, nb);

    /* user area */
    printf("\n  ");
    c_(C_DIM); printf("── "); cr_();
    c_(C_BBLUE); printf("user area"); cr_();
    c_(C_DIM); printf(" (%" PRIu64 " bytes) ──────────────────────────────────────────────\n", in_chunk); cr_();
    printf("     pointer malloc returned: 0x%" PRIx64 "\n", (uint64_t)u);

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
        uint64_t a = (uint64_t)u + r*8;
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
        printf("... %" PRIu64 " bytes hidden ...\n",
               (total_rows - show_first - show_last) * 8);
        cr_();
        for (uint64_t r = total_rows - show_last; r < total_rows; r++) {
            uint64_t a = (uint64_t)u + r*8;
            uint64_t v = *(uint64_t*)a;
            printf("     ");
            c_(C_DIM); printf("0x%" PRIx64, a); cr_();
            printf("   ");
            print_memory_row(v);
            c_(C_DIM); printf("   as 0x%016" PRIx64 "%s\n", v,
                             r == total_rows - 1 ? "  ← last in-chunk row" : "");
            cr_();
        }
    }

    /* spill */
    printf("\n");
    if (spill > 0) {
        printf("  ");
        c_(C_DIM); printf("── "); cr_();
        c_(C_BBLUE); printf("SPILL"); cr_();
        c_(C_DIM); printf(" into next chunk's prev_size ────────────────────────────\n"); cr_();
        uint64_t a = (uint64_t)u + in_chunk;
        uint64_t v = *(uint64_t*)a;
        field_addr("address", a);
        field_memory("memory", v);
        field_value("as int", v);
        field_label("STATE");
        c_(C_BRED); printf("%" PRIu64 " byte(s) of fill pattern 0x%02x landed here\n",
                           spill, FILL_BYTE); cr_();
        c_(C_DIM);
        printf("     WHY        request (%zu) exceeds in-chunk area (%" PRIu64 ")\n", rq, in_chunk);
        printf("                by %" PRIu64 " byte(s)\n", spill);
        printf("                → the next chunk's PREV_INUSE bit is 1, so its\n");
        printf("                  prev_size slot is unused\n");
        printf("                → the spill is legal; glibc will never read this\n");
        printf("                  slot while the current chunk is allocated\n");
        cr_();
        if (spill > 8) {
            field_label("WARNING");
            c_(C_BRED);
            printf("spill exceeds 8 bytes — the next chunk's size field is\n");
            printf("                corrupted. glibc will abort on next free().\n");
            cr_();
        }
    } else {
        field_label("NO SPILL");
        printf("request (%zu) fits entirely in the %" PRIu64 "-byte in-chunk area;\n",
               rq, in_chunk);
        printf("               nothing reached the next chunk's header.\n");
    }

    printf("\n  ");
    c_(C_DIM); printf("next chunk starts at 0x%" PRIx64 "\n", (uint64_t)u + in_chunk); cr_();
}

/* ---------- MAIN ---------- */
int main(void)
{
    N = sizeof(REQUESTED_BYTES) / sizeof(REQUESTED_BYTES[0]);
    if (N > MAX_N) N = MAX_N;
    COLOR = isatty(STDOUT_FILENO);

    printf("\n");
    rule_heavy();
    c_(C_BCYAN); printf("  CONFIGURATION\n"); cr_();
    rule_heavy();
    printf("\n");
    printf("  %-35s 0x%02x\n", "fill byte for memset", FILL_BYTE);
    printf("  %-35s %d\n",     "number of allocations", N);
    printf("  %-35s %zu\n",    "display limit per chunk (0 = all)", DISPLAY_MAX_BYTES);
    printf("  %-35s %s\n",     "color", COLOR ? "enabled" : "disabled");

    if (COLOR) {
        printf("\n  ");
        c_(C_DIM); printf("color legend: "); cr_();
        c_(C_BMAG); printf("aa"); cr_(); c_(C_DIM); printf("=fill  "); cr_();
        c_(C_GRAY); printf("00"); cr_(); c_(C_DIM); printf("=unwritten  "); cr_();
        c_(C_CYAN); printf("xx"); cr_(); c_(C_DIM); printf("=other  "); cr_();
        c_(C_BGREEN); printf("[1]"); cr_(); c_(C_DIM); printf("/"); cr_();
        c_(C_BYELLOW); printf("[0]"); cr_(); c_(C_DIM); printf("=flag value\n"); cr_();
    }

    printf("\n");
    rule_heavy();
    c_(C_BCYAN); printf("  ALLOCATION PHASE\n"); cr_();
    rule_heavy();
    printf("\n");
    for (int i = 0; i < N; i++) {
        P[i]   = malloc(REQUESTED_BYTES[i]);
        REQ[i] = REQUESTED_BYTES[i];
        if (!P[i]) { fprintf(stderr, "malloc failed\n"); N = i; break; }
        memset(P[i], FILL_BYTE, REQ[i]);
        printf("  malloc(%5zu) → ", REQ[i]);
        c_(C_CYAN); printf("0x%" PRIx64, (uint64_t)P[i]); cr_();
        printf("   usable = %zu\n", malloc_usable_size(P[i]));
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
        if (DUMP_AFTER_FREE) {
            printf("\n");
            rule_heavy();
            c_(C_BCYAN); printf("  INSPECTION PHASE AFTER FREE\n"); cr_();
            rule_heavy();
            for (int i = 0; i < N; i++) dump_one(i);
        }
    }

    printf("\n");
    return 0;
}
