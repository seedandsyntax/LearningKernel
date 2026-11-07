#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>

__attribute__((noinline))
static void break_here(void) {
    __asm__ volatile("nop");
}

int main(void) {
    size_t sizes[] = {1, 8, 16, 17, 24, 25, 32, 33, 64, 100, 1000};
    int n = (int)(sizeof(sizes) / sizeof(sizes[0]));
    void *ptrs[16];

        for (int i = 0; i < n; i++) {
                ptrs[i] = malloc(sizes[i]);
                memset(ptrs[i], 0xAA, sizes[i]);
        }

        for (int i = 0; i < n; i++) {
                printf("malloc(%4zu) -> %p  usable=%3zu\n",
                        sizes[i], ptrs[i], malloc_usable_size(ptrs[i]));
        }
    break_here();   // ← breakpoint goes here

    for (int i = 0; i < n; i++) free(ptrs[i]);
    return 0;
}
