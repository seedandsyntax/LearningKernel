#include <linux/module.h>
#include <linux/slab.h>

static int __init uaf_init(void) {
    char *ptr = kmalloc(64, GFP_KERNEL);
    pr_info("uaf: Allocated at %px\n", ptr);
    kfree(ptr);
    pr_info("uaf: Freed, now writing to it...\n");
    ptr[0] = 'A'; // KASAN will catch this Use-After-Free
    return 0;
}
static void __exit uaf_exit(void) { }
module_init(uaf_init);
module_exit(uaf_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A test module to trigger Use-After-Free");
