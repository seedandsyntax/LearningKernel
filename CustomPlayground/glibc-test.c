#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static void dump(const char *tag, uint8_t *a, uint8_t *b) {
    printf("%s\n", tag);
    printf("  a prev_size @ %p = %#018lx\n", (void*)(a-16), *(uint64_t*)(a-16));
    printf("  a size      @ %p = %#018lx\n", (void*)(a-8),  *(uint64_t*)(a-8));
    printf("  a user      = %016lx %016lx\n", *(uint64_t*)a, *(uint64_t*)(a+8));
    printf("  b prev_size @ %p = %#018lx\n", (void*)(b-16), *(uint64_t*)(b-16));
    printf("  b size      @ %p = %#018lx\n", (void*)(b-8),  *(uint64_t*)(b-8));
}

int main() {
    uint8_t *a = malloc(24);
    uint8_t *b = malloc(24);
    memset(a, 0xAA, 24);

    dump("BEFORE free(a):", a, b);
    free(a);
    dump("AFTER free(a):", a, b);
    return 0;
}
