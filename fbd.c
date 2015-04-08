#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <asm/current.h>
#include <asm/pgtable.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <asm/syscall.h>

/*
 *Parameter Declarations
 */

static int threshold=180; //maximum no of processes allowed
module_param(threshold, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(threshold, "A threshold value");
static int young_age=100000; 
module_param(young_age, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(young_age, "age of processes");
static int young_processes_threshold=50; //maximum number of process allowed in the time intervel of young_age
module_param(young_processes_threshold, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(young_processes_threshold, "no of young processes");

asmlinkage int (*old_clone)(struct pt_regs args); /*Original clone declaration*/
unsigned long *syscalltable = (unsigned long *)0xc1663140; /*syscalltable address*/

/*
 * Overriding clone
 */

asmlinkage int new_clone(struct pt_regs args) {  

	struct task_struct *process;
	unsigned long now = 0;
	int n_processes = 0, n_young_processes = 0;
	if (get_current_cred()->uid.val == 0) {

		printk(KERN_ALERT "FBD: Allowing clone as user is root\n"); /* Allow root to execute commands even if */
		return(*old_clone)(args);
	}

	now = jiffies_to_msecs(jiffies);
	for_each_process(process) {
		n_processes++;
		if((now - (process->start_time.tv_nsec/1000000)) <= young_age) { /* current process is young*/
			n_young_processes++;
		}

		if(n_young_processes >= young_processes_threshold || n_processes > threshold) {
			printk(KERN_ALERT "FBD!: Potential fork bomb by process %d. Denying clone requests. \n", process->parent->pid);	
	        return -EAGAIN;
		}
	}

	printk(KERN_ALERT "FBD: Allowing clone as system is safe\n");
    return (*old_clone)(args);


}

/*
 * Module initialization
 */


static int load_new_module(void) {
	printk(KERN_ALERT "FBD: Loading module\n");
	printk(KERN_ALERT "FBD: threshold %d.\n", threshold);
	printk(KERN_ALERT "FBD: young_age %d.\n", young_age);
	printk(KERN_ALERT "FBD: young_processes_threshold %d.\n", young_processes_threshold);
	write_cr0(read_cr0() & (~0x10000));
	
	old_clone = (void *)syscalltable[__NR_clone];
	syscalltable[__NR_clone] = (sys_call_ptr_t)new_clone;
	
	write_cr0(read_cr0() | (0x10000));
	
	return 0;

}

/*
 * Unloading module
 */

static void unload_new_module(void) {
	printk(KERN_ALERT "FBD: Unloading module\n");

	write_cr0(read_cr0() & (~0x10000));
	
	syscalltable[__NR_clone] = (sys_call_ptr_t)old_clone;

	write_cr0(read_cr0() | (0x10000));
	return;
}

module_init(load_new_module);
module_exit(unload_new_module);
MODULE_LICENSE("GPL");
