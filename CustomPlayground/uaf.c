/* uaf_engine.c
 * Build: gcc -O0 -g -Wall -Wextra uaf_engine.c -o uaf
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <malloc.h>
#include <stdalign.h>
#include <sys/mman.h>
#include <errno.h>

/* ========================================================================= */
/* 1. PRESENTATION MODES & TYPES                                             */
/* ========================================================================= */
typedef enum { VIS_HEX, VIS_DEC, VIS_ASCII, VIS_BOTH } VisMode;
typedef enum { STATE_ALLOC, STATE_FREE, STATE_REALLOC, STATE_MEM, STATE_EXPLOIT } InspectState;

#define RST "\033[0m"
#define BC  "\033[1;36m"
#define BG  "\033[1;32m"
#define BY  "\033[1;33m"
#define BR  "\033[1;31m"
#define BB  "\033[1;34m"
#define DIM "\033[2m"

#define INNER_WIDTH 160
static VisMode PRESENTATION_MODE = VIS_BOTH;
static bool CLR = false;

typedef struct { char name[64]; size_t offset; size_t size; } FieldDesc;
typedef struct { char name[64]; size_t size; FieldDesc fields[32]; int field_count; } StructInfo;
typedef struct { uint64_t addr; char name[64]; size_t nb; int is_mmap; } TagInfo;

static TagInfo Tags[64];
static int TagCount = 0;

#define TCACHE_BINS 64
static uint64_t TcacheHeads[TCACHE_BINS] = {0};

static uint64_t HeapBase = 0;
static uint64_t HeapTop = 0;

/* ========================================================================= */
/* 2. UI HELPERS                                                             */
/* ========================================================================= */
static void box_top(void) { printf("  +"); for(int i=0;i<INNER_WIDTH+2;i++) printf("-"); printf("+\n"); }
static void box_bot(void) { printf("  +"); for(int i=0;i<INNER_WIDTH+2;i++) printf("-"); printf("+\n"); }
static void box_mid(void) { printf("  |"); for(int i=0;i<INNER_WIDTH+2;i++) printf("-"); printf("|\n"); }

static int dw(const char *s) {
    int vis = 0; bool esc = false;
    for (int i = 0; s[i]; i++) {
        if (s[i] == '\033') esc = true;
        else if (esc && s[i] == 'm') esc = false;
        else if (!esc) vis++;
    }
    return vis;
}

static void box_line(const char *fmt, ...) {
    char buf[4096];
    va_list a; va_start(a, fmt); vsnprintf(buf, sizeof(buf), fmt, a); va_end(a);
    for (int i = 0; buf[i]; i++) if (buf[i] == '\n') buf[i] = ' ';
    
    printf("  | %s", buf);
    int len = dw(buf);
    for (int i = len; i < INNER_WIDTH; i++) putchar(' ');
    printf(" |\n");
}

static void header(const char *title) {
    printf("\n\n");
    printf(BY "="); for(int i=0; i<INNER_WIDTH+3; i++) printf("="); printf(RST "\n");
    printf(" %-*s\n", INNER_WIDTH+1, title);
    printf(BY "="); for(int i=0; i<INNER_WIDTH+3; i++) printf("="); printf(RST "\n");
}

static void bulletin(const char *title, const char *text) {
    printf("\n  [" BC "%s" RST "]\n", title);
    const char *p = text; int line_len = 5;
    printf("   * ");
    while (*p) {
        if (*p == '\n') { printf("\n       "); line_len = 7; p++; continue; }
        if (line_len > INNER_WIDTH - 5 && *p == ' ') { printf("\n       "); line_len = 7; p++; continue; }
        putchar(*p); line_len++; p++;
    }
    printf("\n\n");
}

static void fmt_byte(unsigned char val, VisMode mode, char *out) {
    char c = (val >= 32 && val < 127) ? val : '.';
    if (mode == VIS_HEX) sprintf(out, "[ %02X ] ", val);
    else if (mode == VIS_DEC) sprintf(out, "[ %3d ] ", val);
    else if (mode == VIS_ASCII) sprintf(out, "[  %c  ] ", c);
    else sprintf(out, "[ %02X|%c ] ", val, c);
}

static const char* get_tag(uint64_t addr) {
    for (int i = 0; i < TagCount; i++) if (Tags[i].addr == addr) return Tags[i].name;
    return NULL;
}

static int is_page_mapped(void *addr) {
    if (addr == NULL) return 0;
    uintptr_t page = (uintptr_t)addr & ~(sysconf(_SC_PAGESIZE) - 1);
    unsigned char vec;
    return mincore((void*)page, sysconf(_SC_PAGESIZE), &vec) == 0;
}

/* ========================================================================= */
/* 3. DWARF PARSER                                                           */
/* ========================================================================= */
static void parse_dwarf(size_t target_size, StructInfo *info) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "timeout 2 readelf --debug-dump=info /proc/%d/exe 2>/dev/null", getpid());
    FILE *fp = popen(cmd, "r");
    if (!fp) return;
    char line[1024]; int in_target = 0; size_t cur_sz = 0; char m_name[64] = {0}; int m_off_raw = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "DW_TAG_structure_type") || strstr(line, "DW_TAG_union_type")) { in_target = 0; cur_sz = 0; }
        else if (strstr(line, "DW_AT_name") && in_target) {
            char *p = strrchr(line, ':'); if (p) { p++; while(*p==' ')p++; strncpy(m_name, p, 63); m_name[strcspn(m_name, "\r\n")] = 0; }
        }
        else if (strstr(line, "DW_AT_byte_size")) {
            char *p = strstr(line, ":"); if (p) { cur_sz = atoi(p + 1); if (cur_sz == target_size) in_target = 1; }
        }
        else if (in_target && strstr(line, "DW_TAG_member")) { m_name[0] = 0; m_off_raw = 0; }
        else if (in_target && strstr(line, "DW_AT_data_member_location")) {
            char *p = strstr(line, ":"); if (p) { m_off_raw = atoi(p + 1);
                if (m_name[0] && info->field_count < 32 && m_off_raw >= 0 && (size_t)m_off_raw < target_size) {
                    strcpy(info->fields[info->field_count].name, m_name);
                    info->fields[info->field_count].offset = (size_t)m_off_raw;
                    info->field_count++;
                }
            }
        }
    }
    pclose(fp);
    info->size = target_size;
    for (int i = 0; i < info->field_count - 1; i++) {
        for (int j = i + 1; j < info->field_count; j++) {
            if (info->fields[j].offset < info->fields[i].offset) {
                FieldDesc tmp = info->fields[i];
                info->fields[i] = info->fields[j];
                info->fields[j] = tmp;
            }
        }
    }
    int valid_count = 0;
    for (int i = 0; i < info->field_count; i++) {
        size_t off = info->fields[i].offset;
        if (off >= target_size) continue;
        size_t sz;
        if (i < info->field_count - 1) {
            size_t next_off = info->fields[i+1].offset;
            if (next_off <= off) continue;
            sz = next_off - off;
        } else {
            sz = target_size - off;
        }
        if (sz == 0 || sz > target_size) continue;
        info->fields[valid_count] = info->fields[i];
        info->fields[valid_count].size = sz;
        valid_count++;
    }
    info->field_count = valid_count;
}

/* ========================================================================= */
/* 4. CORE VISUALIZATION                                                     */
/* ========================================================================= */
static void print_block_visual(const char *name, size_t offset, size_t size, unsigned char *base_ptr, size_t total_size, int depth) {
    if (offset >= total_size) return;
    if (size == 0) return;
    if (offset + size > total_size) size = total_size - offset;
    
    if (size > 1024) {
        box_top(); box_line("%s%s%s", name[0]=='P'?BY:BC, name, RST);
        box_line("Offset: 0x%02zx   Size: %zu bytes", offset, size);
        box_line(BY "  [Block too large to dump raw bytes. Showing layout tree below.]" RST);
        box_bot(); printf("\n");
        return;
    }
    
    box_top(); box_line("%s%s%s", name[0]=='P'?BY:BC, name, RST);
    box_line("Offset: 0x%02zx   Size: %zu bytes", offset, size); box_mid();
    for (size_t i = 0; i < size; i += 16) {
        char line[4096] = {0};
        for (size_t j = 0; j < 16 && i + j < size; j++) {
            size_t idx = offset + i + j;
            if (idx >= total_size) break;
            char b[32]; fmt_byte(base_ptr[idx], PRESENTATION_MODE, b);
            char colored[64]; sprintf(colored, "%s%s%s", idx < 16 ? (CLR?"\033[1;31m":"") : (CLR?"\033[1;32m":""), b, CLR?RST:"");
            strcat(line, colored);
        }
        box_line("  %s", line);
    }
    box_bot(); printf("\n");
}

static void draw_struct_tree(size_t size, const char *var_name, unsigned char *ptr, int depth) {
    StructInfo info = {0}; strcpy(info.name, var_name); info.size = size;
    parse_dwarf(size, &info);
    
    for (int i = 0; i < info.field_count; i++) {
        if (i > 0 && info.fields[i].offset > info.fields[i-1].offset + info.fields[i-1].size) {
            size_t pad_off = info.fields[i-1].offset + info.fields[i-1].size;
            size_t pad_sz = info.fields[i].offset - pad_off;
            if (pad_sz > 0 && depth == 0) print_block_visual("PADDING (Internal)", pad_off, pad_sz, ptr, size, depth);
        }
        print_block_visual(info.fields[i].name, info.fields[i].offset, info.fields[i].size, ptr, size, depth);
    }
    int last = info.field_count - 1;
    if (last >= 0 && info.fields[last].offset + info.fields[last].size < size) {
        size_t pad_off = info.fields[last].offset + info.fields[last].size;
        size_t pad_sz = size - pad_off;
        if (pad_sz > 0 && depth == 0) print_block_visual("PADDING (Trailing)", pad_off, pad_sz, ptr, size, depth);
    }
}

static void analyze_chunk_header(uint64_t chunk_start) {
    uint64_t raw = *(uint64_t*)(chunk_start + 8);
    uint64_t nb = raw & ~0xfULL;
    int p = raw & 1;
    box_top(); box_line("CHUNK HEADER ANALYSIS"); box_mid();
    box_line("  [ prev_size ] @ +0x00: 0x%016" PRIx64, *(uint64_t*)chunk_start);
    if (p == 1 && *(uint64_t*)chunk_start != 0) {
        box_line(BY "    Note: P=1, so glibc IGNORES this field." RST);
        box_line(BY "          These bytes are the TAIL END of the previous chunk's user data." RST);
    }
    box_line("  [ size      ] @ +0x08: 0x%016" PRIx64, raw);
    box_line("                         |---> Flags: 0x%X", (unsigned)(raw & 0xF));
    box_line("                         |     - P (PREV_INUSE) = %d", p);
    box_line("                         |     - M (IS_MMAPPED)  = %lu", (raw >> 1) & 1);
    box_line("                         |     - A (NON_MAIN)    = %lu", (raw >> 2) & 1);
    box_line("                         |---> Size (masked): 0x%" PRIx64 " (%" PRIu64 " bytes)", nb, nb);
    box_bot();
}

static void dump_chunk_memory(const char *name, uint64_t chunk_start, uint64_t nb, int is_freed, StructInfo *info, int is_mmap) {
    if (is_freed && is_mmap) {
        box_top(); box_line("HEAP MEMORY DUMP: %s", name); box_mid();
        box_line(BR "  [SIGSEGV EXPECTED - MEMORY UNMAPPED]" RST);
        box_line("  This allocation bypassed the heap. glibc called mmap().");
        box_line("  Upon free(), glibc immediately called munmap().");
        box_line("  The page is completely removed from the virtual address space.");
        box_mid();
        box_line(CLR ? BR "  NEXT ACCESS -> SIGSEGV (Segmentation Fault)" RST : "  NEXT ACCESS -> SIGSEGV (Segmentation Fault)");
        box_line("  The hardware MMU detects the invalid page.");
        box_line("  The kernel immediately terminates the process.");
        box_bot(); return;
    }
    unsigned char *p = (unsigned char *)chunk_start;
    box_top(); box_line("HEAP MEMORY DUMP: %s (chunk size = %" PRIu64 " bytes)", name, nb); box_mid();
    box_line("%s[CHUNK HEADER (16 bytes)]%s", DIM, RST);
    for (int i = 0; i < 16; i += 16) {
        char line[4096] = {0};
        for (int j = 0; j < 16; j++) { char b[32]; fmt_byte(p[i+j], PRESENTATION_MODE, b); strcat(line, b); }
        box_line("  %s", line);
    }
    box_mid(); box_line("%s[USER AREA (Struct Data)]%s", DIM, RST);
    size_t user_size = nb - 16;
    if (user_size > 64) user_size = 64;
    for (size_t i = 0; i < user_size; i += 16) {
        char line[4096] = {0}; char anno[256] = {0};
        if (is_freed && i == 0 && !is_mmap) strcpy(anno, "<-- [next] pointer (Safe-Linked)");
        else if (is_freed && i == 8 && !is_mmap) strcpy(anno, "<-- [key] cookie (Double-free check)");
        else {
            for (int f = 0; f < info->field_count; f++)
                if (info->fields[f].offset >= i && info->fields[f].offset < i + 16)
                    snprintf(anno, sizeof(anno), "<-- Starts '%s'", info->fields[f].name);
        }
        for (size_t j = 0; j < 16 && i + j < user_size; j++) {
            char b[32]; fmt_byte(p[16 + i + j], PRESENTATION_MODE, b);
            char colored[64]; sprintf(colored, "%s%s%s", (is_freed && i+j < 16 && !is_mmap) ? (CLR?BR:"") : "", b, CLR?RST:"");
            strcat(line, colored);
        }
        if (anno[0]) box_line("  %s  %s", line, anno); else box_line("  %s", line);
    }
    box_bot();
}

static void draw_tcache_list_state(uint64_t head, const char *title) {
    box_top(); box_line("%s", title); box_mid();
    if (head == 0) { box_line("  entries[idx] = NULL (List is empty)"); box_bot(); return; }
    const char *head_tag = get_tag(head);
    box_line("  entries[idx] = 0x%016" PRIx64 " %s##TAG:(%s)%s", head, CLR?BB:"", head_tag ? head_tag : "SYSTEM", CLR?RST:"");
    box_mid();
    uint64_t current = head; int depth = 0;
    while (current != 0 && depth < 10 && is_page_mapped((void*)current)) {
        uint64_t stored = *(uint64_t*)current; uint64_t decoded = stored ^ (current >> 12);
        const char *tag = get_tag(current);
        box_line("  -> [ Chunk @ 0x%016" PRIx64 " %s##TAG:(%s)%s ]", current, CLR?BB:"", tag ? tag : "SYSTEM", CLR?RST:"");
        box_line("     +0x00: [ next ] = 0x%016" PRIx64, stored);
        box_line("            Math: (0x%" PRIx64 " >> 12) ^ 0x%016" PRIx64 " = 0x%" PRIx64, current, stored, decoded);
        if (decoded == 0) box_line("            Decoded: NULL");
        else {
            const char *ntag = get_tag(decoded);
            box_line("            Decoded: 0x%" PRIx64 " %s##TAG:(%s)%s", decoded, CLR?BB:"", ntag ? ntag : "SYSTEM", CLR?RST:"");
        }
        box_line("     +0x08: [ key  ] = 0x%016" PRIx64, *(uint64_t*)(current + 8));
        current = decoded; depth++; if (current != 0) box_line("     |");
    }
    box_bot();
}

static void draw_heap_layout(void) {
    if (HeapBase == 0 || HeapTop == 0) return;
    box_top(); box_line("HEAP LAYOUT MAP"); box_mid();
    uint64_t current = HeapBase; int count = 0;
    
    while (current < HeapTop && count < 200) {
        uint64_t raw = *(uint64_t*)(current + 8);
        uint64_t size = raw & ~0xfULL;
        if (size == 0) break;
        
        const char *tag = get_tag(current + 16);
        char label[128];
        int p = raw & 1;
        int in_tcache = 0;
        int tc_idx = (size >= 32 && size <= 1040) ? ((int)size - 32) / 16 : -1;
        
        if (tc_idx >= 0) {
            uint64_t tc = TcacheHeads[tc_idx];
            while (tc != 0 && is_page_mapped((void*)tc)) {
                if (tc - 16 == current) { in_tcache = 1; break; }
                uint64_t stored = *(uint64_t*)tc;
                tc = stored ^ (tc >> 12);
            }
        }
        
        if (p == 0)                     strcpy(label, "FREE / COALESCED");
        else if (!tag)                  strcpy(label, "SYSTEM / GLIBC");
        else if (in_tcache)             snprintf(label, sizeof(label), "TCACHE: %s", tag);
        else                            snprintf(label, sizeof(label), "ALLOC: %s", tag);
        
        if (strstr(label, "TCACHE") || strstr(label, "ALLOC"))
            box_line("  [0x%016" PRIx64 "] Size: %-8" PRIu64 "  %s%s%s", current, size, CLR?BC:"", label, CLR?RST:"");
        else if (strstr(label, "FREE"))
            box_line("  [0x%016" PRIx64 "] Size: %-8" PRIu64 "  %s%s%s", current, size, CLR?BY:"", label, CLR?RST:"");
        else
            box_line("  [0x%016" PRIx64 "] Size: %-8" PRIu64 "  %s%s%s", current, size, CLR?DIM:"", label, CLR?RST:"");
        
        current += size; count++;
    }
    
    box_line("  [0x%016" PRIx64 "] Size: %-8s  %sTOP CHUNK (Unallocated remainder)%s", current, "?", CLR?BG:"", CLR?RST:"");
    box_bot();
}

/* ========================================================================= */
/* 5. MAIN ENGINE                                                            */
/* ========================================================================= */
void inspect_chunk(void *ptr, size_t size, const char *var_name, InspectState state, void *old_ptr, const char *old_name) {
    if (!ptr && state == STATE_ALLOC) { printf("  [ERROR] %s is NULL.\n", var_name); return; }
    
    if (ptr) {
        int found = 0;
        for (int i = 0; i < TagCount; i++) {
            if (Tags[i].addr == (uint64_t)ptr) { strncpy(Tags[i].name, var_name, 63); found = 1; break; }
        }
        if (!found && TagCount < 64) {
            Tags[TagCount].addr = (uint64_t)ptr;
            strncpy(Tags[TagCount].name, var_name, 63);
            TagCount++;
        }
    }

    int is_mmap = 0; size_t nb = 0;
    for (int i = 0; i < TagCount; i++) {
        if (Tags[i].addr == (uint64_t)ptr) { is_mmap = Tags[i].is_mmap; nb = Tags[i].nb; break; }
    }
    
    if (state == STATE_ALLOC || state == STATE_REALLOC) {
        uint64_t raw = *(uint64_t*)((char*)ptr - 8);
        nb = raw & ~0xfULL;
        is_mmap = (raw >> 1) & 1;
        for (int i = 0; i < TagCount; i++) {
            if (Tags[i].addr == (uint64_t)ptr) { Tags[i].nb = nb; Tags[i].is_mmap = is_mmap; break; }
        }
        if (!is_mmap) {
            int idx = (nb >= 32 && nb <= 1040) ? (int)((nb - 32) / 16) : -1;
            if (idx >= 0 && TcacheHeads[idx] == (uint64_t)ptr) {
                uint64_t stored = *(uint64_t*)ptr;
                TcacheHeads[idx] = stored ^ ((uint64_t)ptr >> 12);
            }
            uint64_t chunk = (uint64_t)ptr - 16;
            if (HeapBase == 0 || chunk < HeapBase) HeapBase = chunk;
            uint64_t top = chunk + nb;
            if (top > HeapTop) HeapTop = top;
        }
    } else if (state == STATE_MEM || state == STATE_EXPLOIT) {
        if (nb == 0) {
            uint64_t raw = *(uint64_t*)((char*)ptr - 8);
            nb = raw & ~0xfULL;
            is_mmap = (raw >> 1) & 1;
        }
    }

    char title[256]; snprintf(title, sizeof(title), "%s: %s", 
        state == STATE_ALLOC ? "ALLOCATION" : (state == STATE_FREE ? "FREE" : (state == STATE_REALLOC ? "REALLOCATION" : (state == STATE_EXPLOIT ? "EXPLOIT PROOF" : "MEMORY CHECK"))), var_name);
    header(title);

    if (state == STATE_ALLOC) {
        printf("\n  SUBTOPIC 1: STRUCT LAYOUT (LOGICAL)\n");
        box_top(); box_line("STRUCT DEFINITION: %s", var_name); box_line("Total Size (sizeof): %zu bytes", size); box_bot(); printf("\n");
        draw_struct_tree(size, var_name, (unsigned char*)ptr, 0);

        printf("\n  SUBTOPIC 2: HEAP ALLOCATION (PHYSICAL)\n");
        if (is_mmap) {
            size_t page_sz = sysconf(_SC_PAGESIZE);
            size_t mmap_sz = (nb + page_sz - 1) & ~(page_sz - 1);
            char msg[512]; snprintf(msg, sizeof(msg), 
                "You allocated %zu bytes.\n"
                "Exceeds 128KB mmap_threshold. glibc called mmap().\n"
                "Actual mapped size (page-aligned): %zu bytes.", size, mmap_sz);
            bulletin("INITIALIZATION (MMAP)", msg);
        } else {
            char msg[512]; snprintf(msg, sizeof(msg), "You allocated %zu bytes.\nFormula: (req + 8 + 15) & ~15 = %zu\nMINSIZE = 32\nActual chunk size: max(%zu, 32) = %zu bytes.", size, (size+23)&~15ULL, (size+23)&~15ULL, nb);
            bulletin("INITIALIZATION", msg);
        }

        box_top(); box_line("ADDRESSES & SIZES");
        box_line("  %s = 0x%016" PRIx64 " %s##TAG:(%s)%s", var_name, (uint64_t)ptr, CLR?BB:"", var_name, CLR?RST:"");
        box_line("  chunk_start = 0x%016" PRIx64, (uint64_t)ptr - 16); box_line("  nb (actual) = %zu bytes", nb);
        if (is_mmap) box_line(BR "  [MMAP DETECTED] Bypassed heap and tcache." RST);
        box_bot();

        analyze_chunk_header((uint64_t)ptr - 16);
        
        StructInfo info = {0}; strcpy(info.name, var_name); info.size = size; parse_dwarf(size, &info);
        dump_chunk_memory(var_name, (uint64_t)ptr - 16, nb, 0, &info, is_mmap);
        
        if (!is_mmap) {
            int idx = (nb >= 32 && nb <= 1040) ? (int)((nb - 32) / 16) : -1;
            if (idx >= 0) draw_tcache_list_state(TcacheHeads[idx], "Tcache State");
            draw_heap_layout();
        }

    } else if (state == STATE_FREE) {
        if (!is_mmap && nb <= 1040) {
            int idx = (nb - 32) / 16;
            uint64_t stored = TcacheHeads[idx] ^ ((uint64_t)ptr >> 12);
            *(uint64_t*)ptr = stored;
            TcacheHeads[idx] = (uint64_t)ptr;
        }
        box_top(); box_line("ADDRESSES & SIZES");
        box_line("  %s = 0x%016" PRIx64 " %s##TAG:(%s)%s", var_name, (uint64_t)ptr, CLR?BB:"", var_name, CLR?RST:"");
        box_line("  chunk_start = 0x%016" PRIx64, (uint64_t)ptr - 16); box_line("  nb (actual) = %zu bytes", nb);
        box_bot();
        
        StructInfo info = {0}; strcpy(info.name, var_name); info.size = size; parse_dwarf(size, &info);
        dump_chunk_memory(var_name, (uint64_t)ptr - 16, nb, 1, &info, is_mmap);
        
        if (!is_mmap && nb <= 1040) {
            int idx = (nb - 32) / 16;
            draw_tcache_list_state(TcacheHeads[idx], "Tcache State (Post-Free)");
        }
        else if (!is_mmap && nb > 1040) {
            box_top(); box_line("Tcache State (Bypassed - Chunk > 1040 bytes)"); box_mid();
            box_line("  Too large for tcache. Went to unsorted bin (or coalesced into Top).");
            box_bot();
        }
        else { box_top(); box_line("Tcache State (Bypassed - MMAP)"); box_mid(); box_line("  mmap() chunks do not use tcache."); box_bot(); }

        char destroy[1024] = "The following struct fields overlap the 16-byte tcache metadata region and are DESTROYED:\n";
        int destroyed = 0;
        if (!is_mmap && nb <= 1040) for (int i = 0; i < info.field_count; i++) if (info.fields[i].offset < 16) {
            char buf[128]; sprintf(buf, "       - Field '%s' at offset 0x%02zx (size %zu)\n", info.fields[i].name, info.fields[i].offset, info.fields[i].size);
            strcat(destroy, buf); destroyed++;
        }
        if (destroyed == 0) strcat(destroy, "       - None\n");
        
        char msg[2048];
        if (is_mmap) {
            snprintf(msg, sizeof(msg), 
                "glibc called munmap() to return this memory to the kernel.\n"
                "This chunk NEVER entered tcache. It bypassed the heap entirely.\n"
                "The memory is now completely unmapped.\n\n"
                "CONCLUSION: mmap() chunks are Fail-Stop *until* the virtual address is reused.\n"
                "Any dereference triggers a SIGSEGV. Silent exploitation is impossible right now.");
        } else if (nb > 1040) {
            snprintf(msg, sizeof(msg),
                "This chunk is larger than 1040 bytes, so it bypassed tcache.\n"
                "It was placed in the unsorted bin.\n"
                "Because it is adjacent to the Top chunk, glibc immediately coalesced it into the Top chunk.\n\n"
                "CONCLUSION: Large heap chunks do not get tcache metadata overwrite.");
        } else {
            snprintf(msg, sizeof(msg), 
                "glibc pushed this chunk onto the LIFO tcache stack.\n"
                "It overwrote the first 16 bytes of the user area with [next] and [key].\n"
                "%s\n"
                "CONCLUSION: tcache chunks are VULNERABLE to UAF.\n"
                "The memory remains mapped and owned by glibc. The dangling pointer\n"
                "is still a valid virtual address, making silent data corruption possible.", 
                destroy);
        }
        bulletin("POST-FREE ANALYSIS", msg);
        
        if (!is_mmap) {
            if (nb > 1040) {
                uint64_t new_top = (uint64_t)ptr - 16 + nb;
                if (new_top > HeapTop) HeapTop = new_top;
            }
            draw_heap_layout();
            bulletin("NOTE: SYSTEM / GLIBC CHUNKS",
                "The chunks labeled 'SYSTEM / GLIBC' are not part of your code.\n"
                "They are allocated by the C standard library before main() even starts.\n"
                "They hold stdio buffers, locale data, and other runtime state.\n"
                "You can ignore them. They just happen to be on the same heap.");
        }

    } else if (state == STATE_REALLOC) {
        if (!is_mmap && nb <= 1040) {
            int idx = (nb - 32) / 16;
            TcacheHeads[idx] = *(uint64_t*)ptr ^ ((uint64_t)ptr >> 12);
        }
        box_top(); box_line("ADDRESSES & SIZES");
        box_line("  %s = 0x%016" PRIx64 " %s##TAG:(%s)%s", var_name, (uint64_t)ptr, CLR?BB:"", var_name, CLR?RST:"");
        box_line("  chunk_start = 0x%016" PRIx64, (uint64_t)ptr - 16); box_line("  nb (actual) = %zu bytes", nb);
        box_bot();
        
        StructInfo info = {0}; strcpy(info.name, var_name); info.size = size; parse_dwarf(size, &info);
        dump_chunk_memory(var_name, (uint64_t)ptr - 16, nb, 0, &info, is_mmap);
        
        if (!is_mmap && nb <= 1040) {
            int idx = (nb - 32) / 16;
            draw_tcache_list_state(TcacheHeads[idx], "Tcache State");
        }

        if (old_ptr && ptr == old_ptr) {
            header("UAF VERIFICATION");
            box_top();
            box_line("New pointer " BC "%s##TAG:(%s)" RST " and old dangling pointer " BR "%s##TAG:(%s)" RST " share address: %p.", var_name, var_name, old_name, old_name, old_ptr);
            if (is_mmap) {
                int mapped = is_page_mapped(old_ptr);
                box_line("mmap() allocation. Kernel unmapped memory on free().");
                box_mid();
                box_line("mincore() check:");
                box_line("  Result: %s", mapped ? "STILL MAPPED (ADDRESS REUSED)" : "UNMAPPED (KERNEL REVOKED ACCESS)");
                if (mapped) box_line(CLR ? BR "  [UAF] The address was reused! %s is now valid again." RST : "  [UAF] The address was reused! %s is now valid again.", old_name);
                box_bot();
                bulletin("DEEP DIVE: MMAP UAF",
                    "mmap() bypasses the heap for allocations > 128KB.\n"
                    "free() calls munmap(), removing the page from the virtual address space.\n"
                    "BUT: The virtual address is just a number. If a new mmap allocation\n"
                    "lands at the exact same address, the dangling pointer becomes valid again.\n"
                    "If mincore() says 'STILL MAPPED', the UAF is active.");
            } else {
                box_line("tcache allocation. Memory still mapped and owned by glibc.");
                box_bot();
                bulletin("DEEP DIVE: TCACHE VULNERABILITY",
                    "tcache chunks remain mapped. The OS is unaware of the free.\n"
                    "glibc writes 16 bytes of metadata ([next] and [key]).\n\n"
                    "CRITICAL LIMIT: Tcache only handles chunks <= 1040 bytes.\n\n"
                    "Because the address is valid, the dangling pointer reads/writes\n"
                    "the same physical bytes the new pointer sees. Silent corruption.");
            }
        } else {
            bulletin("RE-ALLOCATION", "glibc popped this chunk off the tcache stack.");
        }
        if (!is_mmap) draw_heap_layout();

    } else if (state == STATE_EXPLOIT) {
        header("EXPLOIT PROOF (UAF ALIASING)");
        StructInfo info = {0}; strcpy(info.name, var_name); info.size = size; parse_dwarf(size, &info);
        
        box_top();
        box_line("Demonstrating the ALIASING PRIMITIVE:");
        box_line("1. Initial state via " BC "%s" RST, var_name);
        for (int i = 0; i < info.field_count; i++) {
            if (info.fields[i].size == 8) box_line("     %s.%-12s = \"%s\"", var_name, info.fields[i].name, (char*)ptr + info.fields[i].offset);
            else if (info.fields[i].size == 4) box_line("     %s.%-12s = %d", var_name, info.fields[i].name, *(int*)((char*)ptr + info.fields[i].offset));
        }
        box_mid();
        
        box_line("2. Attacker writes through " BC "%s" RST, var_name);
        unsigned char backup[64];
        memcpy(backup, ptr, info.size < 64 ? info.size : 64);
        for (int i = 0; i < info.field_count; i++) {
            if (info.fields[i].size == 8) {
                strcpy((char*)ptr + info.fields[i].offset, "hacker");
                box_line(BC "     strcpy(%s.%s, \"hacker\");" RST, var_name, info.fields[i].name);
            } else if (info.fields[i].size == 4) {
                *(int*)((char*)ptr + info.fields[i].offset) = 1;
                box_line(BC "     %s.%s = 1;" RST, var_name, info.fields[i].name);
            }
        }
        box_mid();
        
        box_line("3. Application reads via OLD dangling pointer " BR "%s" RST, old_name);
        for (int i = 0; i < info.field_count; i++) {
            if (info.fields[i].size == 8) box_line(BR "     %s.%-12s = \"%s\"" RST, old_name, info.fields[i].name, (char*)old_ptr + info.fields[i].offset);
            else if (info.fields[i].size == 4) box_line(BR "     %s.%-12s = %d" RST, old_name, info.fields[i].name, *(int*)((char*)old_ptr + info.fields[i].offset));
        }
        box_mid();
        
        box_line("4. Restoring original state.");
        memcpy(ptr, backup, info.size < 64 ? info.size : 64);
        box_bot();
        
    } else if (state == STATE_MEM) {
        box_top(); box_line("ADDRESSES & SIZES");
        box_line("  %s = 0x%016" PRIx64 " %s##TAG:(%s)%s", var_name, (uint64_t)ptr, CLR?BB:"", var_name, CLR?RST:"");
        box_line("  chunk_start = 0x%016" PRIx64, (uint64_t)ptr - 16); box_line("  nb (actual) = %zu bytes", nb);
        box_bot();
        
        StructInfo info = {0}; strcpy(info.name, var_name); info.size = size; parse_dwarf(size, &info);
        dump_chunk_memory(var_name, (uint64_t)ptr - 16, nb, 0, &info, is_mmap);
        
        if (!is_mmap) draw_heap_layout();
    }
}

/* ========================================================================= */
/* 6. MITIGATIONS                                                            */
/* ========================================================================= */
static void phase_mitigations(void) {
    header("PHASE 7: MITIGATION - HOW TO SAFELY REMOVE DANGLING POINTERS");
    
    bulletin("THE ROOT CAUSE",
        "A Use-After-Free occurs because the program retains the memory address\n"
        "long after the allocator has taken ownership back.\n\n"
        "The C standard does not automatically set pointers to NULL when you free them.\n"
        "You are responsible for erasing the pointer's knowledge of the address.");

    box_top(); box_line("VULNERABLE PATTERN (Red)"); box_mid();
    box_line("%s", CLR ? BR "  void vulnerable() {" RST : "  void vulnerable() {");
    box_line("%s", CLR ? BR "      char *ptr = malloc(32);" RST : "      char *ptr = malloc(32);");
    box_line("%s", CLR ? BR "      strcpy(ptr, \"admin\");" RST : "      strcpy(ptr, \"admin\");");
    box_line("%s", CLR ? BR "      free(ptr);" RST : "      free(ptr);");
    box_line("%s", CLR ? BR "      // ptr still holds the address!" RST : "      // ptr still holds the address!");
    box_line("%s", CLR ? BR "      // ... later ..." RST : "      // ... later ...");
    box_line("%s", CLR ? BR "      printf(\"%%s\\n\", ptr); // UAF" RST : "      printf(\"%%s\\n\", ptr); // UAF");
    box_line("%s", CLR ? BR "  }" RST : "  }");
    box_bot();

    box_top(); box_line("SAFE PATTERN (Green)"); box_mid();
    box_line("%s", CLR ? BG "  void safe() {" RST : "  void safe() {");
    box_line("%s", CLR ? BG "      char *ptr = malloc(32);" RST : "      char *ptr = malloc(32);");
    box_line("%s", CLR ? BG "      strcpy(ptr, \"admin\");" RST : "      strcpy(ptr, \"admin\");");
    box_line("%s", CLR ? BG "      free(ptr);" RST : "      free(ptr);");
    box_line("%s", CLR ? BG "      ptr = NULL;   // THE FIX: Erase the address" RST : "      ptr = NULL;   // THE FIX: Erase the address");
    box_line("%s", CLR ? BG "      // ... later ..." RST : "      // ... later ...");
    box_line("%s", CLR ? BG "      printf(\"%%s\\n\", ptr); // SAFE: Prints (null)" RST : "      printf(\"%%s\\n\", ptr); // SAFE: Prints (null)");
    box_line("%s", CLR ? BG "  }" RST : "  }");
    box_bot();

    bulletin("WHY IT WORKS",
        "When you assign NULL to the pointer, the C language guarantees that\n"
        "dereferencing it (in most implementations) or passing it to printf will\n"
        "result in a clean, observable failure (or print '(null)'), rather than\n"
        "silent memory corruption.\n\n"
        "CRITICAL: This must happen in the SAME scope that owns the pointer.\n"
        "If you pass the pointer to another function that frees it, you must\n"
        "pass a DOUBLE POINTER (char **) to update the original variable.");

    box_top(); box_line("DOUBLE-POINTER SAFE FREE (Green)"); box_mid();
    box_line("%s", CLR ? BG "  void safe_free(void **ptr) {" RST : "  void safe_free(void **ptr) {");
    box_line("%s", CLR ? BG "      if (ptr != NULL && *ptr != NULL) {" RST : "      if (ptr != NULL && *ptr != NULL) {");
    box_line("%s", CLR ? BG "          free(*ptr);" RST : "          free(*ptr);");
    box_line("%s", CLR ? BG "          *ptr = NULL;   // Erase the caller's pointer" RST : "          *ptr = NULL;   // Erase the caller's pointer");
    box_line("%s", CLR ? BG "      }" RST : "      }");
    box_line("%s", CLR ? BG "  }" RST : "  }");
    box_bot();
}

/* ========================================================================= */
/* 7. GLOSSARY                                                               */
/* ========================================================================= */
static void print_glossary(void) {
    header("GLOSSARY (TERMINOLOGY EXPLAINED FOR A 5-YEAR-OLD)");
    
    box_top(); box_line("THE HEAP"); box_mid();
    box_line("  Imagine a giant playground sandbox. glibc is the teacher.");
    box_line("  When your program needs memory, it asks the teacher for a box of sand.");
    box_bot();
    
    box_top(); box_line("CHUNK"); box_mid();
    box_line("  The box of sand the teacher gives you.");
    box_line("  It's not just sand; it has a label on it telling the teacher how big it is.");
    box_bot();

    box_top(); box_line("HEADER (PREV_SIZE & SIZE)"); box_mid();
    box_line("  The label on the box. It tells glibc the size of the box (SIZE)");
    box_line("  and the size of the box right before it (PREV_SIZE).");
    box_bot();

    box_top(); box_line("P-BIT (PREV_INUSE)"); box_mid();
    box_line("  A tiny checkbox on the label. If checked (P=1), it means");
    box_line("  the box right before yours is currently being used by someone else.");
    box_line("  If unchecked (P=0), the box before yours is empty and can be squished together with yours.");
    box_bot();

    box_top(); box_line("MINSIZE"); box_mid();
    box_line("  The smallest box the teacher has. Even if you ask for 1 byte,");
    box_line("  the teacher gives you a box that is at least 32 bytes big.");
    box_bot();

    box_top(); box_line("MALLOC & FREE"); box_mid();
    box_line("  MALLOC: Asking the teacher for a box.");
    box_line("  FREE: Giving the box back to the teacher.");
    box_bot();

    box_top(); box_line("TCACHE (THREAD LOCAL CACHE)"); box_mid();
    box_line("  The teacher's desk. When you give a small box back, the teacher");
    box_line("  doesn't put it in the big closet. She puts it on her desk.");
    box_line("  Next time someone asks for that size, she gives it right back.");
    box_line("  It's super fast.");
    box_bot();

    box_top(); box_line("MMAP"); box_mid();
    box_line("  If you ask for a HUGE box (bigger than 128KB), the teacher");
    box_line("  doesn't have one on her desk. She goes to the Principal (the OS Kernel)");
    box_line("  and asks for a whole new room.");
    box_bot();

    box_top(); box_line("SIGSEGV (SEGMENTATION FAULT)"); box_mid();
    box_line("  The Principal's guard dog. If you try to touch a room");
    box_line("  that the Principal took away from you, the dog bites you");
    box_line("  (the kernel kills your program instantly).");
    box_bot();

    box_top(); box_line("UAF (USE-AFTER-FREE)"); box_mid();
    box_line("  Using a box AFTER you gave it back to the teacher.");
    box_line("  If the teacher put it on her desk (tcache), you can still play with it");
    box_line("  and mess up whatever the next kid puts inside.");
    box_line("  If it was a whole room (mmap), the door is locked, and the dog bites.");
    box_line("  But if the Principal gives that exact same room to another kid,");
    box_line("  your old key still works! That is a mmap UAF.");
    box_bot();

    box_top(); box_line("SAFE-LINKING"); box_mid();
    box_line("  The teacher writes the address of the next box on a piece of paper.");
    box_line("  She scrambles the numbers using the location of the paper itself.");
    box_line("  Math: encoded = next ^ (position >> 12)");
    box_line("  You need the exact location of the paper to unscramble it.");
    box_bot();
}

/* ========================================================================= */
/* ========================================================================= */
/* >>>>>>>>>>>>>>>>>>>  USER CONFIGURATIONS  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< */
/* ========================================================================= */
/* ========================================================================= */

#define ALLOC(var, type) type *var = malloc(sizeof(type)); inspect_chunk(var, sizeof(type), #var, STATE_ALLOC, NULL, NULL)
#define FREE(var) free(var); inspect_chunk(var, sizeof(*var), #var, STATE_FREE, NULL, NULL)
#define REALLOC(new_var, type, old_var) type *new_var = malloc(sizeof(type)); inspect_chunk(new_var, sizeof(type), #new_var, STATE_REALLOC, old_var, #old_var)
#define CHECK(var) inspect_chunk(var, sizeof(*var), #var, STATE_MEM, NULL, NULL)
#define EXPLOIT(new_var, old_var) inspect_chunk(new_var, sizeof(*new_var), #new_var, STATE_EXPLOIT, old_var, #old_var)

void run_user_configurations(void) {
    typedef struct { char username[8]; int is_admin; } SmallAuth;
    typedef struct { char png[80000000]; int is_admin; } LargeAsset;
    typedef struct { char data[34000]; int flag; } BigHeap;
    typedef struct { char SessionID[16]; int privilege_level; char padding[12]; } UserMetaData;
    typedef struct { char SessionID[16]; int privilege_level; char padding[12]; } UserProfile;
    
    typedef struct { char SessionID[16]; LargeAsset privilege_level; SmallAuth padding[12]; } NestedStruct;

    /* SCENARIO 1: Basic Aliasing */
    ALLOC(ptr, SmallAuth);
    strcpy(ptr->username, "admin"); ptr->is_admin = 0;
    FREE(ptr);

    REALLOC(v, SmallAuth, ptr);
    strcpy(v->username, "ME MY"); v->is_admin = 1;
    CHECK(v);
    EXPLOIT(v, ptr);
    
    // SAFE MITIGATION: Nullify the pointers
    free(v); v = NULL;
    ptr = NULL;

    /* SCENARIO 2: Fragmentation & Mmap */
    ALLOC(A, SmallAuth);
    ALLOC(B, SmallAuth);
    ALLOC(C, SmallAuth);
    FREE(B);
    
    ALLOC(H, BigHeap);
    FREE(A);
    FREE(C);
    
    ALLOC(X, LargeAsset);
    FREE(X);
    
    // Reuse the mmap address to trigger the UAF
    ALLOC(X2, LargeAsset);
    EXPLOIT(X2, X);
    
    // SAFE MITIGATION
    free(X2); X2 = NULL;
    X = NULL;
    
    FREE(H);

    /* SCENARIO 3: Nested Structs */
    ALLOC(profile_old, UserProfile);
    strcpy(profile_old->SessionID, "SESS_1234567890");
    profile_old->privilege_level = 1;
    FREE(profile_old);

    REALLOC(meta_new, UserMetaData, profile_old);
    strcpy(meta_new->SessionID, "MALICIOUS");
    meta_new->privilege_level = 99;
    CHECK(meta_new);
    
    // Explicitly demonstrate the exploit on the modified payload
    EXPLOIT(meta_new, profile_old);
    
    strcpy(profile_old->SessionID, "OVERFLOW!");
    CHECK(profile_old);
    
    // SAFE MITIGATION
    free(meta_new); meta_new = NULL;
    profile_old = NULL;

    /* SCENARIO 4: Deeply Nested Large Struct */
    ALLOC(ns, NestedStruct);
    strcpy(ns->SessionID, "NESTED_SESSION");
    ns->privilege_level.is_admin = 1;
    strcpy(ns->padding[0].username, "admin");
    CHECK(ns);
    FREE(ns);
    ns = NULL; // SAFE
}

int main(void) {
    CLR = isatty(STDOUT_FILENO);
    if(CLR) printf(BC);
    printf("========================================================================================================================\n");
    printf(" STRUCT USE-AFTER-FREE INSPECTOR\n");
    printf("========================================================================================================================\n");
    if(CLR) printf(RST);
    run_user_configurations();
    phase_mitigations();
    print_glossary();
    return 0;
}
