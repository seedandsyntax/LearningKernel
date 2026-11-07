#include <linux/module.h>
#include <linux/slab.h>

static int __init oob_init(void) {
    // I need to still learn about the kmalloc's implementation, glibc is far different than kmalloc
    int *arr = kmalloc(10 * sizeof(int), GFP_KERNEL);
    pr_info("oob: Writing to index 15 of a 10-int array...\n");
    arr[15] = 42; // KASAN will catch this!
    kfree(arr);
    return 0;
}

static void __exit oob_exit(void)
{
	pr_info("oob: unloading\n");
}

module_init(oob_init);
module_exit(oob_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Out-of-tree module that triggers a Out-Of-Bound Error and KASAN catches it.");

