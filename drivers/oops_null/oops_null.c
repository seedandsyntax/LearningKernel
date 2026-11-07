#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static void create_oops(void)
{
	*(int *)0 = 0;	/* intentional NULL dereference */
}

static int __init oops_null_init(void)
{
	pr_info("oops_null: loading\n");
	create_oops();
	return 0;
}

static void __exit oops_null_exit(void)
{
	pr_info("oops_null: unloading\n");
}

module_init(oops_null_init);
module_exit(oops_null_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Out-of-tree module that triggers a NULL dereference");
