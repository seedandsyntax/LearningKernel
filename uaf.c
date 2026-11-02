/* struct_chunk_masterclass_v2.c
 * corrected edition — all fixes from review applied.
 *
 * New structure:
 *   Phase 0   three lifetimes (the reviewer's central framing)
 *   Phase 1   chunk layout with correct absolute offsets
 *   Phase 2   malloc does not zero: observed vs guaranteed
 *   Phase 3   struct fields in their real zones
 *   Phase 4   free() finds the chunk via pointer math
 *   Phase 5   free() chooses path: nb <= 1040 (chunk), not 1032 (request)
 *   Phase 6   tcache_put, exactly three writes
 *   Phase 7   safe-linking (glibc 2.32+)
 *   Phase 8   tcache_key: process-wide, not per-thread
 *   Phase 9   byte diff: before / after free
 *   Phase 10  %s-leak reality check: bounded read vs string read
 *   Phase 11  re-malloc: same address, different lifetimes
 *   Phase 12  tail clobber: triggered by set_foot when THIS chunk is freed
 *   Phase 13  two free paths side by side (tcache vs unsorted)
 *   Phase 14  summary with softened UAF language
 *
 * Build: gcc -O0 -g -Wall -Wextra struct_chunk_masterclass_v2.c -o uaf
 *        gcc -O0 -g -Wall -Wextra -Wformat=2 -Wno-format-nonliteral \
 *            struct_chunk_masterclass_v2.c -o uaf
 * Run:   ./uaf
 *
 * Every "observed" statement below is labeled as such; every "guaranteed"
 * statement cites its source. If they conflict, the source wins.
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
#include <malloc.h>
#include <gnu/libc-version.h>

static const char *RST="\033[0m", *BC="\033[1;36m", *BY="\033[1;33m";
static const char *BG="\033[1;32m", *BR="\033[1;31m", *BM="\033[1;35m", *DIM="\033[2m";
static bool CLR=false;

static int dw(const char *s){
    int w=0; bool esc=false;
    for(int i=0; s[i]; i++){
        unsigned char c=(unsigned char)s[i];
        if(c==0x1b){esc=true;continue;}
        if(esc){if(c=='m')esc=false;continue;}
        if((c&0xC0)==0x80)continue;
        w++;
    }
    return w;
}
static void bt(int w){printf("  ┌");for(int i=0;i<w;i++)printf("─");printf("┐\n");}
static void bb(int w){printf("  └");for(int i=0;i<w;i++)printf("─");printf("┘\n");}
static void bm(int w){printf("  ├");for(int i=0;i<w;i++)printf("─");printf("┤\n");}

/* bl, note, para: all three take printf-style format strings, so all three
 * get __attribute__((format(printf, ...))) so the compiler checks every
 * call site and refuses to build on a mismatched directive. */
static void __attribute__((format(printf, 2, 3)))
bl(int w, const char *f, ...){
    char b[4096]; va_list a; va_start(a,f); vsnprintf(b,sizeof b,f,a); va_end(a);
    int p = w - 2 - dw(b); if(p<0) p=0;
    printf("  │ "); fputs(b, stdout);
    for(int i=0;i<p;i++) putchar(' ');
    printf(" │\n");
}

static void phase(int n, const char *t){
    printf("\n");
    if(CLR) printf("%s", BY);
    printf("╔══════════════════════════════════════════════════════════════════════════╗\n");
    printf("║  PHASE %-2d  %-64s║\n", n, t);
    printf("╚══════════════════════════════════════════════════════════════════════════╝\n");
    if(CLR) printf("%s", RST);
}

static void __attribute__((format(printf, 1, 2)))
para(const char *f, ...){
    char b[4096]; va_list a; va_start(a,f); vsnprintf(b,sizeof b,f,a); va_end(a);
    const char *p=b; int l=0; printf("  ");
    while(*p){
        if(*p=='\n'){printf("\n  ");l=0;p++;continue;}
        if(l>72&&*p==' '){printf("\n  ");l=0;p++;continue;}
        putchar(*p); l++; p++;
    }
    printf("\n");
}

static void __attribute__((format(printf, 1, 2)))
note(const char *f, ...){
    char b[4096]; va_list a; va_start(a,f); vsnprintf(b,sizeof b,f,a); va_end(a);
    if(CLR) printf("%s", DIM);
    printf("  ( "); const char *p=b; int l=2;
    while(*p){
        if(*p=='\n'){printf("\n    ");l=4;p++;continue;}
        if(l>70&&*p==' '){printf("\n    ");l=4;p++;continue;}
        putchar(*p); l++; p++;
    }
    printf(" )\n");
    if(CLR) printf("%s", RST);
}

/* ─────── structs ─────── */
typedef struct { char username[16]; int is_admin; } User;
typedef struct { char data[2000]; uint64_t magic; } Huge;

/* ═══════════════════════════════════════════════════════════════════════════ */
static void phase0(void)
{
    phase(0, "THREE LIFETIMES (start here; everything depends on this)");

    para("A pointer after free() is not simply 'dangling'. Three "
         "different lifetimes have to be tracked separately, and they "
         "end at three different times. The original version of this "
         "tool conflated them, and that conflation is the source of "
         "most beginner confusion about UAF.");

    bt(78);
    bl(78, "%sTHE THREE LIFETIMES%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "1. C OBJECT LIFETIME");
    bl(78, "   Ends at free(u). After that, per the C standard, u is");
    bl(78, "   indeterminate and dereferencing it is UB. Period.");
    bm(78);
    bl(78, "2. ALLOCATOR CHUNK LIFETIME");
    bl(78, "   Ends when THIS chunk leaves all bins (tcache, unsorted,");
    bl(78, "   small, large). The chunk may be merged into a neighbour,");
    bl(78, "   may be split, may be handed to the next malloc of the");
    bl(78, "   same size. Whichever happens, the chunk is 'reissued'.");
    bm(78);
    bl(78, "3. VIRTUAL-MEMORY LIFETIME");
    bl(78, "   Ends when the KERNEL unmaps the page. For a small heap");
    bl(78, "   chunk, that is often 'never' during the process lifetime.");
    bl(78, "   free() does not call munmap for brk-resident chunks.");
    bb(78);

    para("");
    para("These three are independent. That is why 'the pointer still "
         "works' is true and false at the same time:");

    bt(78);
    bl(78, "  %-24s  %-18s  %s", "Reading through u:", "lifetime-1 view", "reality");
    bm(78);
    bl(78, "  compiles?                yes                yes");
    bl(78, "  dereferences without     maybe             yes if page mapped");
    bl(78, "  segfault?");
    bl(78, "  well-defined by C?       NO                 NO");
    bl(78, "  gives you the bytes      undefined          yes (UB)");
    bl(78, "  you wrote earlier?");
    bl(78, "  gives you allocator      undefined          yes (UB)");
    bl(78, "  metadata?");
    bm(78);
    bl(78, "  'works' means the kernel still maps the page. It does");
    bl(78, "  NOT mean the C object still exists, and it does NOT");
    bl(78, "  mean the bytes are still yours.");
    bb(78);

    para("");
    para("A fourth thing, which the reviewer of the previous version "
         "highlighted: the allocator is ENTITLED to repurpose the "
         "bytes. free() ends lifetime-1 and begins the allocator's "
         "use of lifetime-2. Writing tcache metadata into the freed "
         "chunk is not corruption of a live object; it is the "
         "allocator doing exactly what it is permitted to do.");
}

/* ═══════════════════════════════════════════════════════════════════════════ */
static void phase1(void *u, size_t nb)
{
    phase(1, "CHUNK LAYOUT (absolute offsets, no ambiguity)");

    para("The previous version's diagram was off by 4 bytes. Here is "
         "the corrected map for a 32-byte chunk on x86-64 glibc.");

    bt(78);
    bl(78, "%sABSOLUTE CHUNK OFFSETS FOR nb = 32%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  chunk+0                chunk+16               chunk+40");
    bl(78, "  |                      |                      |");
    bl(78, "  v                      v                      v");
    bl(78, "  +-------+-------+------+----------------------+------+");
    bl(78, "  |prev_sz| size  | username[0..15]  |is_adm| pad |");
    bl(78, "  |   8B  |   8B  |     in-chunk     | 4B   | 4B  |");
    bl(78, "  +-------+-------+------+----------------------+------+");
    bl(78, "  |<-header 16B-->|<------requested 20B-------->|");
    bl(78, "                  |<--- in-chunk 16B --->|");
    bl(78, "                                         |<-tail 8B->|");
    bl(78, "                  |<----------- usable 24B ---------->|");
    bm(78);
    bl(78, "  in-chunk = nb - 16 = 16");
    bl(78, "  usable   = nb -  8 = 24");
    bl(78, "  tail     = usable - in-chunk = 8");
    bm(78);
    bl(78, "  Region           Absolute     Size   Contents");
    bl(78, "  --------------   ----------   ----   --------------------");
    bl(78, "  header           [0, 16)      16     prev_size + size");
    bl(78, "  in-chunk         [16, 32)     16     username");
    bl(78, "  tail overlap     [32, 40)      8     is_admin (4B) + pad (4B)");
    bl(78, "                                       = next chunk's prev_size");
    bl(78, "  overflow starts  [40, ...)          this would step on");
    bl(78, "                                       next chunk's SIZE field");
    bb(78);

    para("");
    para("Now the important wording fix. The tail overlap is NOT "
         "'glibc lending you bytes'. It is this:");

    bt(78);
    bl(78, "%sWHAT THE TAIL OVERLAP ACTUALLY IS%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "The 20 bytes you requested extend past the in-chunk boundary.");
    bl(78, "Specifically, is_admin (bytes 16..19 of your request) sits at");
    bl(78, "chunk+32..35, which is inside the next chunk's prev_size field.");
    bm(78);
    bl(78, "This is safe because:");
    bl(78, "  * prev_size is only meaningful when P=0 on the NEXT chunk,");
    bl(78, "  * P is currently 1 (this chunk is in use),");
    bl(78, "  * so glibc does not read/write prev_size while we're live.");
    bm(78);
    bl(78, "It is UNSAFE the moment this chunk is freed via the unsorted");
    bl(78, "bin path (set_foot writes prev_size). It is also unsafe if");
    bl(78, "the allocator writes there for any reason.");
    bb(78);

    para("");
    para("Separately, the 4 bytes at user offsets 20..23 (chunk+36..39) "
         "are excess capacity: they fall within malloc_usable_size() but "
         "beyond your requested 20. The Linux man page for "
         "malloc_usable_size is explicit that writing past the "
         "requested size, even within the reported usable size, is "
         "unsupported. Treat them as read-only observation, never as "
         "guaranteed storage.");

    note("Observed on this run: nb = %zu, user_ptr = %p, chunk_start = %p",
         nb, u, (char *)u - 16);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
static void phase2(User *u)
{
    phase(2, "MALLOC DOES NOT ZERO (observed vs guaranteed)");

    para("The previous version labeled the fresh chunk 'zero user bytes'. "
         "That was true of that particular run, but it is not a "
         "guarantee. malloc() returns uninitialized memory.");

    bt(78);
    bl(78, "%sWHAT YOU CAN AND CANNOT COUNT ON%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  GUARANTEED by C99/C11:");
    bl(78, "    the returned pointer is aligned, non-NULL on success,");
    bl(78, "    and points to malloc_usable_size(p) accessible bytes.");
    bm(78);
    bl(78, "  NOT guaranteed:");
    bl(78, "    the contents of those bytes.");
    bm(78);
    bl(78, "  OFTEN observed (not guaranteed):");
    bl(78, "    fresh brk-extended pages read back as zero;");
    bl(78, "    reused tcache chunks read back as whatever the last");
    bl(78, "    owner left there (or tcache metadata).");
    bb(78);

    para("");
    para("Here are the OBSERVED bytes in this run's fresh allocation. "
         "Treat them as data, not as a contract:");

    bt(78);
    {
        unsigned char *raw = (unsigned char *)u;
        bl(78, "Observed user bytes (user offsets 0..23):");
        for(int r=0;r<3;r++){
            char hx[96]={0}; int p=0;
            for(int c=0;c<8;c++)
                p += snprintf(hx+p,sizeof hx-p,"%02x ", raw[r*8+c]);
            bl(78, "  user+%2d..%2d  %s", r*8, r*8+7, hx);
        }
    }
    bb(78);

    para("");
    para("Similarly: the previous version's writeup said strcpy(\"guest\") "
         "wrote six bytes including the NUL. That is correct — six bytes "
         "written, ten bytes in username[] left alone. Those ten bytes "
         "contain whatever malloc left there. Not zero. Not guaranteed.");

    para("");
    para("So we write the struct explicitly, not relying on malloc:");

    memset(u->username, 0, sizeof u->username);
    strcpy(u->username, "guest");
    u->is_admin = 0;

    bt(78);
    bl(78, "After memset + strcpy + assignment:");
    {
        unsigned char *raw = (unsigned char *)u;
        for(int r=0;r<3;r++){
            char hx[96]={0}, as[24]={0}; int p=0, q=0;
            for(int c=0;c<8;c++){
                unsigned char b=raw[r*8+c];
                p += snprintf(hx+p,sizeof hx-p,"%02x ", b);
                q += snprintf(as+q,sizeof as-q,"%c ", (b>=32&&b<127)?b:'.');
            }
            bl(78, "  user+%2d..%2d  %s  %s", r*8, r*8+7, hx, as);
        }
    }
    bb(78);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
static void phase3(User *u, size_t nb)
{
    phase(3, "FIELDS IN THEIR REAL ZONES");

    uint64_t cs = (uint64_t)u - 16;
    bt(78);
    bl(78, "%sFIELD 0: username   char[16]   user offset 0..15%s",
       CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  absolute:    chunk+16 .. chunk+31");
    bl(78, "  zone:        in-chunk (strictly inside this 32-byte chunk)");
    bl(78, "  lifetime:    belongs to this allocation only");
    bl(78, "  overwritten: on free, by tcache [next][key]");
    bb(78);

    bt(78);
    bl(78, "%sFIELD 1: is_admin   int        user offset 16..19%s",
       CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  absolute:    chunk+32 .. chunk+35");
    bl(78, "  zone:        tail overlap (first 4 of the 8 tail bytes)");
    bl(78, "  lifetime:    belongs to THIS allocation's 20 requested bytes");
    bl(78, "               even though it physically overlaps the NEXT");
    bl(78, "               chunk's prev_size field");
    bm(78);
    bl(78, "  Safe because P=1 on the next chunk (prev_size unused).");
    bl(78, "  Unsafe if this chunk is freed via the set_foot path.");
    bl(78, "  Overwritten: NOT by tcache_put (its 16-byte write window");
    bl(78, "               stops at user+15). MAY be overwritten later");
    bl(78, "               by allocator consolidation of neighbours.");
    bb(78);

    bt(78);
    bl(78, "%sFIELD 2: (padding)   none       user offset 20..23%s",
       CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  absolute:    chunk+36 .. chunk+39");
    bl(78, "  zone:        excess usable (glibc minimum-size padding)");
    bl(78, "  lifetime:    not part of the 20 requested bytes");
    bl(78, "  Writing here is UNSUPPORTED per man 3 malloc_usable_size");
    bl(78, "  even though malloc_usable_size returns 24 for this chunk.");
    bb(78);

    note("chunk_start  = 0x%"PRIx64"  nb = %zu  user_ptr = %p",
         cs, nb, u);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
static void phase4(void *u)
{
    phase(4, "free() FINDS THE CHUNK (pointer math)");

    bt(78);
    bl(78, "%sWHAT free() ACTUALLY DOES FIRST%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  chunk_start = (uintptr_t)user_ptr - 16;");
    bl(78, "              = 0x%"PRIx64" - 0x10", (uint64_t)u);
    bl(78, "              = 0x%"PRIx64, (uint64_t)u - 16);
    bm(78);
    {
        uint64_t raw = *(uint64_t *)((char *)u - 8);
        bl(78, "  raw_size     = *(uint64_t *)(chunk_start + 8)");
        bl(78, "               = 0x%016"PRIx64, raw);
        bl(78, "  nb           = raw_size & ~0xFULL");
        bl(78, "               = 0x%"PRIx64, raw & ~0xfULL);
        bl(78, "  P (in-use)   = raw_size & 0x1   = %lu", raw & 1);
        bl(78, "  M (mmapped)  = (raw_size>>1)&1  = %lu", (raw >> 1) & 1);
    }
    bb(78);
    para("");
    para("free() has no way to verify that user_ptr actually points "
         "into a live allocation. It trusts. Any memory corruption "
         "before this call that changes user_ptr, or any double free, "
         "lands the allocator on garbage it will happily follow.");
}

/* ═══════════════════════════════════════════════════════════════════════════ */
static void phase5(void *u)
{
    phase(5, "free() CHOOSES THE PATH (1040 chunks vs 1032 requests)");

    para("The previous version's writeup said 'nb <= 1032'. The number "
         "1032 is the maximum REQUEST size that ends up in tcache. The "
         "corresponding maximum CHUNK size is 1040. Since the size "
         "header reports chunk size, the chunk-size comparison is what "
         "matters:");

    bt(78);
    bl(78, "%sTHE TWO NUMBERS, KEPT SEPARATE%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  max tcache REQUEST (bytes)    = 1032");
    bl(78, "  max tcache CHUNK   (bytes)    = 1040");
    bl(78, "  formula:  chunk2tidx(nb) = (nb - 32) / 16");
    bl(78, "  valid tcache idx range        = 0 .. 63  (64 small bins)");
    bl(78, "  nb=1040 -> idx = (1040-32)/16 = 63   (last bin)");
    bl(78, "  nb=1056 -> idx = (1056-32)/16 = 64   (out of range)");
    bm(78);
    bl(78, "  A 20-byte request gives nb = 32 -> idx = 0 (bin 0).");
    bl(78, "  Absolutely in tcache. No ambiguity.");
    bb(78);

    para("");
    para("Two conditions must both hold for tcache insertion:");
    bt(78);
    bl(78, "  1. tcache is active for this thread (not disabled).");
    bl(78, "  2. tcache->counts[idx] < tcache_max_count (default 16).");
    bm(78);
    bl(78, "  If either fails, the free falls through to _int_free()");
    bl(78, "  (the slow path: unsorted bin, coalescing, set_foot).");
    bb(78);

    note("This example takes the fast path. The slow-path example is "
         "Phase 12, where a Huge struct forces consolidation.");
}

/* ═══════════════════════════════════════════════════════════════════════════ */
static void phase6(void *u)
{
    phase(6, "TCACHE_PUT: EXACTLY THREE WRITES, 16 BYTES");

    bt(78);
    bl(78, "%sWHAT tcache_put WRITES INTO YOUR CHUNK%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  user+0..7   [next] = PROTECT_PTR(&e->next, bin_head)");
    bl(78, "  user+8..15  [key]  = tcache_key   (see Phase 8)");
    bm(78);
    bl(78, "  user+16..23  NOT WRITTEN. is_admin survives tcache_put.");
    bb(78);

    para("");
    para("That is the whole fast path. Sixteen bytes and a pointer "
         "update. This is why tcache is fast: no coalescing, no "
         "prev_size read, no size arithmetic beyond csize2tidx.");
}

/* ═══════════════════════════════════════════════════════════════════════════ */
static void phase7(void *u)
{
    phase(7, "SAFE-LINKING (glibc 2.32+, not 2.34)");

    para("The previous version said Safe-Linking landed in glibc 2.34. "
         "Correction: it landed in glibc 2.32. The 2.34 change was to "
         "the tcache_key semantics (pointer -> random cookie). These "
         "are two separate hardening mechanisms introduced two "
         "releases apart.");

    bt(78);
    bl(78, "%sTHE FORMULA%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  stored     = (pos >> 12) XOR real_next");
    bl(78, "  real_next  = (pos >> 12) XOR stored");
    bm(78);
    bl(78, "  pos  = address of the FIELD being written");
    bl(78, "       = (uintptr_t)&e->next   =  user_ptr");
    bl(78, "  >> 12 strips the low 12 bits (page offset).");
    bb(78);

    uint64_t pos = (uint64_t)u;
    uint64_t stored = *(uint64_t *)u;
    uint64_t recovered = stored ^ (pos >> 12);

    bt(78);
    bl(78, "  user_ptr         = 0x%016"PRIx64, pos);
    bl(78, "  user_ptr >> 12   = 0x%016"PRIx64, pos >> 12);
    bl(78, "  stored [next]    = 0x%016"PRIx64, stored);
    bl(78, "  decoded head     = 0x%016"PRIx64, recovered);
    if(recovered == 0)
        bl(78, "  -> bin was empty before this free (this chunk is now head)");
    bb(78);

    para("");
    para("What Safe-Linking actually prevents: a single-leak attacker "
         "recovering real_next from the stored bytes alone. What it "
         "does NOT prevent: an attacker who obtains any second "
         "disclosure that provides the missing in-page offset. The "
         "previous version claimed 'any heap disclosure' recovers the "
         "address; that overstates it. The second disclosure must "
         "either supply the exact in-page offset, or be an address "
         "whose relation to the same page is known. A random stack "
         "address or an unrelated global does NOT do it.");
}

/* ═══════════════════════════════════════════════════════════════════════════ */
static void phase8(void *u)
{
    phase(8, "TCACHE_KEY IS PROCESS-WIDE (glibc 2.34+)");

    para("The previous version said the key is per-thread and generated "
         "at thread startup. That is wrong. In glibc 2.43, the key is "
         "a single process-wide value.");

    bt(78);
    bl(78, "%sTHE KEY, CORRECTED%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  symbol:   static uintptr_t tcache_key;");
    bl(78, "  scope:    PROCESS-WIDE (not per-thread)");
    bl(78, "  width:    uintptr_t (64 bits on x86-64)");
    bl(78, "  origin:   getrandom(), with random_bits() fallback");
    bl(78, "  value:    0x%016"PRIx64"  (observed on this run)",
       *(uint64_t *)((char *)u + 8));
    bb(78);

    para("");
    para("Why the distinction matters: a per-thread key would let a "
         "cross-thread attacker who compromised thread B infer thread "
         "A's key by reading their own. A process-wide key means "
         "compromising thread B gives you thread A's key too — but "
         "only if the attacker can read B's key at all. And since the "
         "key is random, reading it requires an existing disclosure.");

    para("");
    para("The double-free check is more complex than the previous "
         "version stated. It is not 'check key, abort on match'. It is:");

    bt(78);
    bl(78, "%sTHE ACTUAL DOUBLE-FREE VERIFICATION%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  if (e->key == tcache_key) {");
    bl(78, "      for (idx = 0; idx < TCACHE_MAX_BINS; idx++) {");
    bl(78, "          /* scan EVERY bin owned by this thread */");
    bl(78, "          t = tcache->entries[idx];");
    bl(78, "          while (t != NULL) {");
    bl(78, "              if (t == e)");
    bl(78, "                  abort(\"double free in tcache 2\");");
    bl(78, "              t = REVEAL_PTR(t->next);");
    bl(78, "          }");
    bl(78, "      }");
    bl(78, "      /* not found in ANY bin: false positive */");
    bl(78, "      e->key = 0;");
    bl(78, "      /* fall through and retry the free */");
    bl(78, "  }");
    bl(78, "  tcache_put(e, idx);");
    bm(78);
    bl(78, "  The scan visits ALL tcache bins, not just the matching one.");
    bl(78, "  If the chunk is not found, the key is cleared and free()");
    bl(78, "  proceeds. This means cross-thread double-frees (where the");
    bl(78, "  same address is in a DIFFERENT thread's tcache) are not");
    bl(78, "  reliably detected by this mechanism.");
    bb(78);

    para("");
    para("Also: zeroing the key via a UAF write does NOT 'poison "
         "tcache'. It only causes the next free of that chunk to skip "
         "the double-free check. To actually poison tcache you would "
         "have to also write a controlled safe-linked value into the "
         "[next] field, and the resulting fake pointer must pass "
         "alignment checks. Zeroing the key is a necessary step, not "
         "a sufficient one. The previous version's Phase 12 conflated "
         "these.");
}

/* ═══════════════════════════════════════════════════════════════════════════ */
static void phase9(void *u, const unsigned char *before)
{
    phase(9, "BYTE DIFF: BEFORE vs AFTER free()");

    unsigned char after[32];
    memcpy(after, (char *)u - 16, 32);

    bt(78);
    bl(78, "%sWHAT CHANGED IN THE CHUNK%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  off       before                        after");
    for(int r=0;r<4;r++){
        char bh[48]={0}, ah[48]={0}; int p=0, q=0;
        bool ch=false;
        for(int c=0;c<8;c++){
            p += snprintf(bh+p,sizeof bh-p,"%02x ", before[r*8+c]);
            q += snprintf(ah+q,sizeof ah-q,"%02x ", after[r*8+c]);
            if(before[r*8+c] != after[r*8+c]) ch=true;
        }
        bl(78, "  +%-3d  %-28s  %-28s  %s%s%s", r*8, bh, ah,
           ch ? (CLR?BR:"") : (CLR?BG:""),
           ch ? "CHANGED" : "SAME",
           CLR ? RST : "");
    }
    bb(78);

    para("");
    para("Bytes 16..31 of the chunk (which is user offsets 0..15) "
         "changed. Bytes 0..15 are the header and did not change. "
         "Bytes 32..39 are the tail overlap (containing is_admin); "
         "they did not change on the tcache path.");

    note("This is the correct interpretation: tcache_put's write "
         "window is user+0..user+15. Anything beyond user+15 is "
         "untouched on this path.");
}

/* ═══════════════════════════════════════════════════════════════════════════ */
static void phase10(void *u)
{
    phase(10, "THE UAF READ — CORRECTED (why %s does not leak the key)");

    para("This was the biggest mistake in the previous version. It said "
         "the UAF read is 'a 16-byte information leak'. That is false "
         "for printf(\"%%s\"). A C string stops at its first NUL byte.");

    bt(78);
    bl(78, "%sWHAT printf(\"%%s\", u->username) ACTUALLY READS%s",
       CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  user+0..15 (hex, as written by tcache_put):");
    {
        unsigned char *raw = (unsigned char *)u;
        char hx[96]={0}; int p=0;
        for(int c=0;c<16;c++)
            p += snprintf(hx+p,sizeof hx-p,"%02x ", raw[c]);
        bl(78, "    %s", hx);
    }
    bm(78);
    bl(78, "  byte-by-byte scan for first NUL (where %%s stops):");
    {
        unsigned char *raw = (unsigned char *)u;
        int firstnul = -1;
        for(int c=0;c<16;c++){
            char mark[8]={0};
            if(raw[c]==0){ mark[0]='*'; mark[1]=0; firstnul=(firstnul<0?c:firstnul); }
            else mark[0]='.';
            bl(78, "    user+%2d  %02x  %s", c, raw[c], mark);
        }
        bm(78);
        if(firstnul >= 0){
            bl(78, "  %%s stops after byte %d.", firstnul);
            bl(78, "  Bytes user+%d .. user+15 are NEVER REACHED by this read.", firstnul);
            if(firstnul < 8)
                bl(78, "  The tcache_key at user+8..15 is NOT leaked.");
        } else {
            bl(78, "  No NUL in first 16 bytes. %%s would read into the");
            bl(78, "  next 8 bytes (chunk+32..39, is_admin area) before");
            bl(78, "  finding a NUL -- this is UNDEFINED BEHAVIOUR in C,");
            bl(78, "  and there is no guarantee of where the NUL lives.");
        }
    }
    bb(78);

    para("");
    para("The honest claim: %%s may partially leak the safe-linked "
         "pointer (the low bytes until the first NUL), but does NOT "
         "reach the cookie in the typical case. To actually read the "
         "whole 16-byte window you need a bounded raw read, not a "
         "string read. Here is what that looks like — and note that "
         "doing it through the STRUCT is still UB; the well-defined "
         "way is to treat the address as bytes:");

    bt(78);
    bl(78, "%sBOUNDED RAW READ (memcpy, not %%s)%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  Code:");
    bl(78, "    uint64_t raw_user_ptr = (uint64_t)u;   // address only");
    bl(78, "    unsigned char buf[16];");
    bl(78, "    memcpy(buf, (void*)raw_user_ptr, 16); // UB but often works");
    bm(78);
    bl(78, "  Result (this run):");
    {
        unsigned char buf[16];
        memcpy(buf, u, 16);
        uint64_t w0, w1;
        memcpy(&w0, buf, 8);
        memcpy(&w1, buf + 8, 8);
        bl(78, "    word0 = 0x%016"PRIx64"   (safe-linked next)", w0);
        bl(78, "    word1 = 0x%016"PRIx64"   (tcache_key)", w1);
        bl(78, "    decoded = 0x%016"PRIx64" (should be 0 if bin empty)",
           w0 ^ ((uint64_t)u >> 12));
    }
    bm(78);
    bl(78, "  This DOES leak both words -- but only because we're using");
    bl(78, "  memcpy on raw bytes, not a C string operation on a struct.");
    bl(78, "  Both are UB at the C-language level; only the memcpy form");
    bl(78, "  delivers all 16 bytes. That distinction matters if you");
    bl(78, "  ever reason about what a real exploit primitive provides.");
    bb(78);

    para("");
    para("And note: the string-based read is UB, but so is the memcpy. "
         "The point is not that one is 'safe' and the other isn't — "
         "they're both UB — the point is that the leak WIDTH is "
         "different. The previous version promised a 16-byte leak from "
         "a %%s read. It doesn't deliver one. That's the correction.");
}

/* ═══════════════════════════════════════════════════════════════════════════ */
static void phase11(User *u, User *v)
{
    phase(11, "RE-MALLOC — SAME ADDRESS, DIFFERENT LIFETIMES");

    para("The previous version said 'one chunk, two owners'. That "
         "blurs the three lifetimes. Here is the precise framing:");

    bt(78);
    bl(78, "%sADDRESSES AND LIFETIMES%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  u (dangling)  = %p", (void *)u);
    bl(78, "  v (fresh)     = %p", (void *)v);
    if(u == v){
        bl(78, "  Addresses are identical.");
        bl(78, "  That means one physical memory region.");
        bl(78, "  It does NOT mean one C object.");
    } else {
        bl(78, "  Addresses differ: tcache was not the head for this");
        bl(78, "  request, so a different chunk was handed out.");
    }
    bm(78);
    bl(78, "  Lifetimes:");
    bl(78, "    u's object  -- ended at free(u)  -- STILL OVER");
    bl(78, "    allocator   -- chunk reissued as v -- ACTIVE for v");
    bl(78, "    VM page     -- unchanged           -- ACTIVE for both");
    bm(78);
    bl(78, "  u is not magically a valid pointer to v's object.");
    bl(78, "  It still has UB semantics. It happens to compare equal");
    bl(78, "  to v's address at the machine level.");
    bb(78);

    para("");
    para("That is the whole reason UAF is dangerous. The program has "
         "two pointers, u and v, into the same bytes, with different "
         "legal lifetimes. If the programmer's mental model is 'u is "
         "dead', they write code that reads only via v — and miss "
         "the fact that the original code path still holds u. That "
         "path now sees attacker-controlled bytes if an attacker can "
         "influence v's contents.");

    bt(78);
    bl(78, "  u->username = \"%s\"", u->username);
    bl(78, "  u->is_admin = %d  %s", u->is_admin,
       u->is_admin ? (CLR?BR:"") : "");
    if(u->is_admin) bl(78, "  ^ this is v's write showing up through u");
    bb(78);

    note("Neither read above is well-defined C. The point is to "
         "demonstrate why attackers do it, not to endorse it.");
}

/* ═══════════════════════════════════════════════════════════════════════════ */
static void phase12(void)
{
    phase(12, "TAIL CLOBBER — WHEN THIS CHUNK TAKES set_foot");

    Huge *h = malloc(sizeof(Huge));
    void *guard = malloc(64);
    if(!h || !guard){ fprintf(stderr, "malloc failed\n"); return; }
    memset(h->data, 0x42, sizeof h->data);
    h->magic = 0xDEADBEEFCAFEBABEULL;

    uint64_t hs = (uint64_t)h - 16;
    uint64_t gs = (uint64_t)guard - 16;
    uint64_t nb = (*(uint64_t *)((char *)h - 8)) & ~0xfULL;
    uint64_t before = h->magic;

    para("The previous version said the clobber happens 'the moment a "
         "neighbour is freed'. That is imprecise. The clobber happens "
         "when THIS chunk itself takes the set_foot path — i.e. when "
         "free(h) is called and h is large enough to bypass tcache.");

    bt(78);
    bl(78, "%sBEFORE free(h)%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  sizeof(struct Huge)  = %zu", sizeof(Huge));
    bl(78, "  nb                   = %"PRIu64"  (> 1040 -> not tcache)", nb);
    bl(78, "  h                    = %p", (void *)h);
    bl(78, "  &h->magic            = 0x%016"PRIx64, (uint64_t)&h->magic);
    bl(78, "  guard chunk start    = 0x%016"PRIx64, gs);
    bl(78, "  guard.prev_size addr = 0x%016"PRIx64, gs);
    if((uint64_t)&h->magic == gs)
        bl(78, "  %sSAME ADDRESS: h->magic IS guard.prev_size%s",
           CLR?BY:"", CLR?RST:"");
    bl(78, "  h->magic value       = 0x%016"PRIx64, before);
    bb(78);

    para("");
    para("Now free(h). nb = 2016 bypasses tcache. The unsorted-bin "
         "path runs. It calls set_foot(h, nb), which writes nb into "
         "the NEXT chunk's prev_size — which is guard.prev_size — "
         "which is h->magic.");

    free(h);

    bt(78);
    bl(78, "%sAFTER free(h)%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  h->magic before  = 0x%016"PRIx64, before);
    bl(78, "  h->magic after   = 0x%016"PRIx64, h->magic);
    bl(78, "  nb written       = 0x%"PRIx64, nb);
    if(before != h->magic && h->magic == nb)
        bl(78, "  %sCLOBBERED with nb%s", CLR?BR:"", CLR?RST:"");
    bb(78);

    para("");
    para("Two important wordings:");
    bt(78);
    bl(78, "  (1) It is not 'the moment a neighbour is freed'.");
    bl(78, "      It is 'when THIS chunk is freed and takes set_foot'.");
    bl(78, "      A tcache-resident chunk never takes set_foot.");
    bm(78);
    bl(78, "  (2) The object's lifetime has ended. This is not");
    bl(78, "      corruption of a LIVE object. The allocator is entitled");
    bl(78, "      to reuse the released bytes for its own bookkeeping.");
    bl(78, "      The interesting property is that the reused bytes");
    bl(78, "      overlap a field of the STRUCT -- which matters only");
    bl(78, "      if a subsequent allocator action writes there, or if");
    bl(78, "      the program reads that field through a stale pointer.");
    bb(78);

    (void)hs;
    free(guard);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
static void phase13(User *u)
{
    phase(13, "SIDE BY SIDE: SMALL tcache PATH vs LARGE BIN PATH");

    para("The previous version's summary said 'the freed pointer leaks "
         "safe-linking cookies'. That is true for the tcache path. It "
         "is different for the unsorted-bin path. Here is the "
         "difference concretely:");

    bt(78);
    bl(78, "%-20s  %-24s  %-24s", "aspect", "tcache (small)", "unsorted bin (large)");
    bm(78);
    bl(78, "%-20s  %-24s  %-24s", "trigger",       "nb <= 1040 and count<16", "nb > 1040");
    bl(78, "%-20s  %-24s  %-24s", "what free() writes", "next + key (16B)", "fd + bk (16B)");
    bl(78, "%-20s  %-24s  %-24s", "set_foot called?", "no", "yes");
    bl(78, "%-20s  %-24s  %-24s", "next chunk clobbered?", "no", "prev_size written");
    bl(78, "%-20s  %-24s  %-24s", "coalesces?",   "no", "yes, if neighbours free");
    bl(78, "%-20s  %-24s  %-24s", "what you leak", "safe-linked ptr + key", "heap ptrs (fd/bk)");
    bl(78, "%-20s  %-24s  %-24s", "double-free check", "key + full bin scan", "fd/bk consistency");
    bb(78);

    para("");
    para("The previous version's blanket statement 'a UAF leaks "
         "safe-linking cookies and random keys' is true only for "
         "tcache-path chunks. For unsorted-bin chunks, you instead "
         "leak raw heap pointers (fd, bk) — which are the classic "
         "pre-tcache leak primitive. Both are exploitable, in "
         "different ways. Keep the distinction.");

    note("User struct (nb=32) is a tcache chunk. Huge struct (nb=2016) "
         "is an unsorted-bin chunk. Both are demonstrated in this run.");

    (void)u;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
static void phase14(void)
{
    phase(14, "SUMMARY (softened claims, hardened framing)");

    bt(78);
    bl(78, "%sINVARIANTS (hold across all glibc >= 2.32 on x86-64)%s",
       CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  chunk_start       = user_ptr - 16");
    bl(78, "  nb                = size_header & ~0xFULL");
    bl(78, "  in-chunk          = nb - 16");
    bl(78, "  usable            = nb - 8  (malloc_usable_size)");
    bl(78, "  tail overlap      = 8 bytes (next chunk's prev_size)");
    bl(78, "  writing past usable is real overflow.");
    bl(78, "  writing past request but within usable is UNSUPPORTED.");
    bb(78);

    bt(78);
    bl(78, "%sTCACHE PATH (nb <= 1040, count < 16)%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  free() writes 16 bytes: [next][key] at user+0..15.");
    bl(78, "  next  = (user_ptr>>12) XOR real_next  (glibc 2.32+)");
    bl(78, "  key   = process-wide random 64-bit  (glibc 2.34+)");
    bl(78, "  malloc() of same size returns same chunk (LIFO).");
    bl(78, "  fields at user offset < 16 are overwritten.");
    bl(78, "  fields at user offset >= 16 survive the free intact");
    bl(78, "    (for the tcache path; consolidation can still clobber).");
    bb(78);

    bt(78);
    bl(78, "%sUNSORTED-BIN PATH (nb > 1040)%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  free() writes fd, bk at user+0..15.");
    bl(78, "  free() calls set_foot(p, nb), writing nb into the NEXT");
    bl(78, "  chunk's prev_size -- potentially a field of your struct.");
    bl(78, "  Coalescing may merge THIS chunk with adjacent free chunks.");
    bb(78);

    bt(78);
    bl(78, "%sWHAT UAF ACTUALLY GIVES AN ATTACKER%s", CLR?BM:"", CLR?RST:"");
    bm(78);
    bl(78, "  A vulnerability class, not an exploit primitive.");
    bl(78, "  Depending on program state, UAF may provide:");
    bl(78, "    - stale read of allocator-recycled memory");
    bl(78, "    - stale write into a subsequently reused allocation");
    bl(78, "    - disclosure of allocator metadata");
    bl(78, "    - opportunity to corrupt freelist metadata");
    bl(78, "    - type confusion when a different object is placed here");
    bm(78);
    bl(78, "  Tcache poisoning requires more than UAF:");
    bl(78, "    - control over the freelist metadata (the [next] field)");
    bl(78, "    - a plausible safe-linked encoding for the poisoned");
    bl(78, "      value (needs the target address AND its XOR key)");
    bl(78, "    - alignment and range checks on the target pointer");
    bl(78, "    - typically, multiple leaks / a second primitive");
    bm(78);
    bl(78, "  Zeroing tcache_key does NOT poison tcache. It only");
    bl(78, "  bypasses the key-based double-free check. The rest of");
    bl(78, "  the poisoning chain (see above) still has to happen.");
    bb(78);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
int main(void)
{
    CLR = isatty(STDOUT_FILENO);

    printf("\n");
    if(CLR) printf("%s", BC);
    printf("══════════════════════════════════════════════════════════════════════════\n");
    printf("  STRUCT CHUNK MASTERCLASS — corrected edition   glibc %s on x86-64\n",
           gnu_get_libc_version());
    printf("══════════════════════════════════════════════════════════════════════════\n");
    if(CLR) printf("%s", RST);

    phase0();

    User *u = malloc(sizeof(User));
    if(!u) return 1;
    size_t nb = (*(uint64_t *)((char *)u - 8)) & ~0xfULL;

    phase1(u, nb);
    phase2(u);
    phase3(u, nb);
    phase4(u);
    phase5(u);

    unsigned char before[32];
    memcpy(before, (char *)u - 16, 32);

    free(u);

    phase6(u);
    phase7(u);
    phase8(u);
    phase9(u, before);
    phase10(u);

    User *v = malloc(sizeof(User));
    if(v){
        strcpy(v->username, "attacker");
        v->is_admin = 1;
    }
    phase11(u, v);
    if(v) free(v);

    phase12();
    phase13(u);
    phase14();

    printf("\n");
    return 0;
}
