#ifdef __KERNEL__

#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "proc.h"
#include "queue.h"
#include "security_table.h"
#include "interfaces_table.h"

// We're going to place all proc entries within a directory called superman.
static struct proc_dir_entry *this_proc_dir;

/*
Each proc entry consists of three parts:
	- *_proc_show - function which does the actual printf work.
	- *_proc_open - function whichs perform the file open bits.
	- *_proc_fops - structure defining the files capability.
*/


/*
Our /proc/superman/version file displays the active superman version.
*/

static int version_proc_show(struct seq_file *m, void *v)
{
	// Inject a bit of ASCII ART fun into an otherwise boring version output.
	seq_printf(m,
"\n"
"SUPERMAN - Security Under Pre-Existing Routing in Mobile Area Networks\n\n"
"            _____________________________________________\n           //:::::::::::::::::::::::::::::::::::::::::::::\\\\\n         //:::_______:::::::::________::::::::::_____:::::::\\\\\n       //:::_/   _-\"\":::_--\"\"\"        \"\"\"--_::::\\_  ):::::::::\\\\\n      //:::/    /:::::_\"                    \"-_:::\\/:::::|^\\:::\\\\\n     //:::/   /~::::::I__                      \\:::::::::|  \\:::\\\\\n     \\\\:::\\   (::::::::::\"\"\"\"---___________     \"--------\"  /::://\n      \\\\:::\\  |::::::::::::::::::::::::::::\"\"\"\"==____      /::://\n       \\\\:::\"\\/::::::::::::::::::::::::::::::::::::::\\   /~::://\n         \\\\:::::::::::::::::::::::::::::::::::::::::::)/~::://\n           \\\\::::\\\"\"\"\"\"\"------_____::::::::::::::::::::::://\n             \\\\:::\"\\               \"\"\"\"\"-----_____:::::://\n               \\\\:::\"\\    __----__                )::://\n                 \\\\:::\"\\/~::::::::~\\_         __/~:://\n                   \\\\::::::::::::::::\"\"----\"\"\":::://\n                     \\\\::::::::::::::::::::::::://\n                       \\\\:::\\^\"\"--._.--\"\"^/::://\n                         \\\\::\"\\         /\":://\n                           \\\\::\"\\     /\":://\n                             \\\\::\"\\_/\":://\n                               \\\\:::::// 				\n"
"                                 \\\\_//\n                                   \"\n\n"
"                The active SUPERMAN version is %d.%d\n\n", SUPERMAN_VERSION_MAJOR, SUPERMAN_VERSION_MINOR);
	return 0;
}

static int version_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, version_proc_show, NULL);
}

static const struct file_operations version_proc_fops = {
    .owner      = THIS_MODULE,
    .open       = version_proc_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release
};

/*
Our /proc/superman/queue_info file display the queue information.
*/


static int queue_info_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, queue_info_proc_show, NULL);
}

static const struct file_operations queue_info_proc_fops = {
    .owner      = THIS_MODULE,
    .open       = queue_info_proc_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release
};

/*
Our /proc/superman/security_table_info file display the security table information.
*/

static int security_table_info_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, security_table_info_proc_show, NULL);
}

static const struct file_operations security_table_info_proc_fops = {
    .owner      = THIS_MODULE,
    .open       = security_table_info_proc_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release
};

/*
Our /proc/superman/interfaces_table_info file display the interfaces table information.
*/

static int interfaces_table_info_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, interfaces_table_info_proc_show, NULL);
}

static const struct file_operations interfaces_table_info_proc_fops = {
    .owner      = THIS_MODULE,
    .open       = interfaces_table_info_proc_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release
};

/*
The proc entry init and deinit functions deal with construction and destruction.
*/

bool InitProc(void)
{
	/* create /proc/superman */
	this_proc_dir = proc_mkdir("superman", NULL);
	if (!this_proc_dir)
		return false;

	proc_create("version", 0, this_proc_dir, &version_proc_fops);
	proc_create("queue_info", 0, this_proc_dir, &queue_info_proc_fops);
	proc_create("security_table", 0, this_proc_dir, &security_table_info_proc_fops);
	proc_create("interfaces_table", 0, this_proc_dir, &interfaces_table_info_proc_fops);

	return true;
}

void DeInitProc(void)
{
	remove_proc_entry("interfaces_table", this_proc_dir);
	remove_proc_entry("security_table", this_proc_dir);
	remove_proc_entry("queue_info", this_proc_dir);
	remove_proc_entry("version", this_proc_dir);
	remove_proc_entry("superman", NULL);
}

#endif
