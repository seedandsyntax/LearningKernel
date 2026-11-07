#include <linux/module.h>
#include <linux/mutex.h>

static DEFINE_MUTEX(lock_a);
static DEFINE_MUTEX(lock_b);

static int __init deadlock_init(void) {
    pr_info("deadlock: Locking A then B\n");
    mutex_lock(&lock_a);
    mutex_lock(&lock_b);
    
    // Lockdep catches this immediately
    pr_info("deadlock: Trying to lock B again...\n");
    mutex_lock(&lock_b); 
    
    return 0;
}

static void __exit deadlock_exit(void)
{
	pr_info("deadlock: unloading\n");
}

module_init(deadlock_init);
module_exit(deadlock_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Out-of-tree module that triggers a deadlock and Lockdep will catch it.");

