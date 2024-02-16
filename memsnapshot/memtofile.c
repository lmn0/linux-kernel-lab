#include <linux/debugfs.h>
#include <linux/efi.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <asm/pgtable.h>

static int ptdump_show(struct seq_file *m, void *v)
{
	ptdump_walk_pgd_level_debugfs(m, NULL, false);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump);

static int ptdump_curknl_show(struct seq_file *m, void *v)
{
	if (current->mm->pgd) {
		down_read(&current->mm->mmap_lock);
		ptdump_walk_pgd_level_debugfs(m, current->mm, false);
		up_read(&current->mm->mmap_lock);
	}
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump_curknl);

#ifdef CONFIG_PAGE_TABLE_ISOLATION
static int ptdump_curusr_show(struct seq_file *m, void *v)
{
	if (current->mm->pgd) {
		down_read(&current->mm->mmap_lock);
		printk("count: %d",current->mm->mmap_lock.count);
		ptdump_walk_pgd_level_debugfs(m, current->mm, true);
		up_read(&current->mm->mmap_lock);
	}
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump_curusr);
#endif

static struct dentry *dir;

static int __init pt_dump_debug_init(void)
{
	printk(KERN_WARNING "Starting");
	dir = debugfs_create_dir("page_tables", NULL);

	debugfs_create_file("kernel", 0400, dir, NULL, &ptdump_fops);
	debugfs_create_file("current_kernel", 0400, dir, NULL,
			    &ptdump_curknl_fops);

#ifdef CONFIG_PAGE_TABLE_ISOLATION
	debugfs_create_file("current_user", 0400, dir, NULL,
			    &ptdump_curusr_fops);
#endif
	return 0;
}

static void __exit pt_dump_debug_exit(void)
{
	debugfs_remove_recursive(dir);
}

module_init(pt_dump_debug_init);
module_exit(pt_dump_debug_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Thejass Krishnan");
MODULE_DESCRIPTION("Dump pagetables into debugfs");
