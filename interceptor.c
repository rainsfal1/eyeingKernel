#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <asm/unistd.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/syscalls.h>
#include "interceptor.h"


MODULE_DESCRIPTION("kernel module for intercepting system calls");
MODULE_AUTHOR("type name");
MODULE_LICENSE("GPL");

//----- System Call Table Stuff ------------------------------------
/* Symbol that allows access to the kernel system call table */
extern void* sys_call_table[];

/* The sys_call_table is read-only => must make it RW before replacing a syscall */
void set_addr_rw(unsigned long addr) {

    unsigned int level;
    // page table entry
    pte_t *pte = lookup_address(addr, &level);

    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;

}

/* Restores the sys_call_table as read-only */
void set_addr_ro(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    pte->pte = pte->pte &~_PAGE_RW;

}
//-------------------------------------------------------------


//----- Data structures and bookkeeping -----------------------

/* List structure - each intercepted syscall may have a list of monitored pids */
struct pid_list {
    pid_t pid;
    struct list_head list;
};


/* Store info about intercepted/replaced system calls */
typedef struct {

    /* Original system call */
    asmlinkage long (*f)(struct pt_regs);

    /* Status: 1=intercepted, 0=not intercepted */
    int intercepted;

    /* Are any PIDs being monitored for this syscall? */
    int monitored;

    /* List of monitored PIDs */
    int listcount;
    struct list_head my_list;
}mytable;

/* An entry for each system call in this "metadata" table */
mytable table[NR_syscalls];

/* Access to the system call table and your metadata table must be synchronized */
spinlock_t my_table_lock = SPIN_LOCK_UNLOCKED;
spinlock_t sys_call_table_lock = SPIN_LOCK_UNLOCKED;
//-------------------------------------------------------------


//----------LIST OPERATIONS------------------------------------

/*
 * Add a pid to a syscall's list of monitored pids.
 * Returns -ENOMEM if the operation is unsuccessful.
 */
static int add_pid_sysc(pid_t pid, int sysc)
{
    struct pid_list *ple = (struct pid_list*) kmalloc(sizeof(struct pid_list), GFP_KERNEL);

    if (!ple)
        return -ENOMEM;

    INIT_LIST_HEAD(&ple->list);

    ple->pid=pid;

    list_add(&ple->list, &(table[sysc].my_list));
    table[sysc].listcount++;

    return 0;
}

/*
 * Remove a pid from a system call's list of monitored pids.
 * Returns -EINVAL if no such pid was found in the list.
 */
static int del_pid_sysc(pid_t pid, int sysc)
{
    struct list_head *i;
    struct pid_list *ple;

    list_for_each(i, &(table[sysc].my_list)) {

        ple=list_entry(i, struct pid_list, list);
        if(ple->pid == pid) {

            list_del(i);
            kfree(ple);

            table[sysc].listcount--;
            /* If there are no more pids in sysc's list of pids, then
             * stop the monitoring only if it's not for all pids (monitored=2) */
            if(table[sysc].listcount == 0 && table[sysc].monitored == 1) {
                table[sysc].monitored = 0;
            }

            return 0;
        }
    }

    return -EINVAL;
}

/*
 * Remove a pid from all the lists of monitored pids (for all intercepted syscalls).
 * Returns -1 if this process is not being monitored in any list.
 */
static int del_pid(pid_t pid)
{
    struct list_head *i, *n;
    struct pid_list *ple;
    int ispid = 0, s = 0;

    for(s = 1; s < NR_syscalls; s++) {

        list_for_each_safe(i, n, &(table[s].my_list)) {

            ple=list_entry(i, struct pid_list, list);
            if(ple->pid == pid) {

                list_del(i);
                ispid = 1;
                kfree(ple);

                table[s].listcount--;
                /* If there are no more pids in sysc's list of pids, then
                 * stop the monitoring only if it's not for all pids (monitored=2) */
                if(table[s].listcount == 0 && table[s].monitored == 1) {
                    table[s].monitored = 0;
                }
            }
        }
    }

    if (ispid) return 0;
    return -1;
}

/*
 * Clear the list of monitored pids for a specific syscall.
 */
static void destroy_list(int sysc) {

    struct list_head *i, *n;
    struct pid_list *ple;

    list_for_each_safe(i, n, &(table[sysc].my_list)) {

        ple=list_entry(i, struct pid_list, list);
        list_del(i);
        kfree(ple);
    }

    table[sysc].listcount = 0;
    table[sysc].monitored = 0;
}

/**
 * Check if two pids have the same owner - useful for checking if a pid
 * requested to be monitored is owned by the owner of the requesting process.
 */
static int check_pids_same_owner(pid_t pid1, pid_t pid2) {

    struct task_struct *p1 = pid_task(find_vpid(pid1), PIDTYPE_PID);
    struct task_struct *p2 = pid_task(find_vpid(pid2), PIDTYPE_PID);
    if(p1->real_cred->uid != p2->real_cred->uid)
        return -EPERM;
    return 0;
}

/*
 * Check if a pid is already being monitored for a specific syscall.
 * Returns 1 if it already is, or 0 if pid is not in sysc's list.
 */
static int check_pid_monitored(int sysc, pid_t pid) {

    struct list_head *i;
    struct pid_list *ple;

    list_for_each(i, &(table[sysc].my_list)) {

        ple=list_entry(i, struct pid_list, list);
        if(ple->pid == pid)
            return 1;

    }
    return 0;
}
//----------------------------------------------------------------

//----- Intercepting exit_group ----------------------------------
/**
 * Since a process can exit without its owner specifically requesting
 * to stop monitoring it, we must intercept the exit_group system call
 * so that we can remove the exiting process's pid from *all* syscall lists.
 */

/*
 * Stores original exit_group function - after all, we must restore it
 * when our kernel module exits.
 */
asmlinkage long (*orig_exit_group)(struct pt_regs reg);

/*
 * Our custom exit_group system call.
 */
asmlinkage long my_exit_group(struct pt_regs reg)
{
    pid_t pid = current->pid;
    int i;

    spin_lock(&my_table_lock);

    for (i = 0; i < NR_syscalls; i++) {
        if (table[i].monitored) {
            del_pid_sysc(pid, i);
        }
    }

    // Use del_pid here if it's needed
    del_pid(pid);

    spin_unlock(&my_table_lock);

    return orig_exit_group(reg);
}
//----------------------------------------------------------------


//----------------------------------------------------------------
/*
 * This is the generic interceptor function.
 */
asmlinkage long interceptor(struct pt_regs reg) {
    unsigned long  syscall = reg.ax;
    pid_t current_pid = current->pid;
    int monitored = 0;

    spin_lock(&my_table_lock);
    if (table[syscall].monitored == 2) {
        monitored = 1;
    } else if (table[syscall].monitored == 1) {
        monitored = check_pid_monitored(syscall, current_pid);
    }
    spin_unlock(&my_table_lock);

    if (monitored) {
        log_message(current_pid, syscall,
                    reg.bx,
                    reg.cx,
                    reg.dx,
                    reg.si,
                    reg.di,
                    reg.bp);
    }
    return table[syscall].f(reg);
}

/*
 * My system call - this function is called whenever a user issues a MY_CUSTOM_SYSCALL system call.
 * When that happens, the parameters for this system call indicate one of 4 actions/commands:
 *      - REQUEST_SYSCALL_INTERCEPT to intercept the 'syscall' argument
 *      - REQUEST_SYSCALL_RELEASE to de-intercept the 'syscall' argument
 *      - REQUEST_START_MONITORING to start monitoring for 'pid' whenever it issues 'syscall'
 *      - REQUEST_STOP_MONITORING to stop monitoring for 'pid'
 *      For the last two, if pid=0, that translates to "all pids".
 */

asmlinkage long my_syscall(int cmd, int syscall, int pid) {
    int r = 0;

    printk(KERN_DEBUG "my_syscall: Entered with cmd=%d, syscall=%d, pid=%d\n", cmd, syscall, pid);

    if (syscall < 0 || syscall >= NR_syscalls || syscall == MY_CUSTOM_SYSCALL) {
        printk(KERN_ERR "my_syscall: Invalid syscall number %d\n", syscall);
        return -EINVAL;
    }

    if (cmd == REQUEST_SYSCALL_INTERCEPT || cmd == REQUEST_SYSCALL_RELEASE) {
        if (!capable(CAP_SYS_ADMIN)) {
            printk(KERN_ERR "my_syscall: Permission denied for cmd %d\n", cmd);
            return -EPERM;
        }
    } else if (cmd == REQUEST_START_MONITORING || cmd == REQUEST_STOP_MONITORING) {
        if (pid < -1) {
            printk(KERN_ERR "my_syscall: Invalid PID %d\n", pid);
            return -EINVAL;
        }
        if (!capable(CAP_SYS_ADMIN)) {
            if (pid == 0 || (pid != -1 && !check_pids_same_owner(current, pid))) {
                printk(KERN_ERR "my_syscall: Permission denied for cmd %d, pid=%d\n", cmd, pid);
                return -EPERM;
            }
        }
    } else {
        printk(KERN_ERR "my_syscall: Invalid command %d\n", cmd);
        return -EINVAL;
    }

    spin_lock(&my_table_lock);
    printk(KERN_DEBUG "my_syscall: Acquired my_table_lock\n");

    switch (cmd) {
        case REQUEST_SYSCALL_INTERCEPT:
            if (table[syscall].intercepted) {
                printk(KERN_ERR "my_syscall: Syscall %d already intercepted\n", syscall);
                r = -EBUSY;
            } else {
                spin_lock(&sys_call_table_lock);
                set_addr_rw((unsigned long)sys_call_table);
                table[syscall].f = sys_call_table[syscall];
                sys_call_table[syscall] = interceptor;
                set_addr_ro((unsigned long)sys_call_table);
                spin_unlock(&sys_call_table_lock);
                table[syscall].intercepted = 1;
                table[syscall].monitored = 0;
                table[syscall].listcount = 0;
                INIT_LIST_HEAD(&table[syscall].my_list);
                printk(KERN_INFO "my_syscall: Intercepted syscall %d\n", syscall);
            }
            break;

        case REQUEST_SYSCALL_RELEASE:
            if (!table[syscall].intercepted) {
                printk(KERN_ERR "my_syscall: Syscall %d not intercepted\n", syscall);
                r = -EINVAL;
            } else {
                spin_lock(&sys_call_table_lock);
                set_addr_rw((unsigned long)sys_call_table);
                sys_call_table[syscall] = table[syscall].f;
                set_addr_ro((unsigned long)sys_call_table);
                spin_unlock(&sys_call_table_lock);
                table[syscall].intercepted = 0;
                table[syscall].monitored = 0;
                destroy_list(syscall);
                printk(KERN_INFO "my_syscall: Released syscall %d\n", syscall);
            }
            break;

        case REQUEST_START_MONITORING:
            if (!table[syscall].intercepted) {
                printk(KERN_ERR "my_syscall: Syscall %d not intercepted\n", syscall);
                r = -EINVAL;
            } else if (pid == 0) {
                if (table[syscall].monitored == 2) {
                    printk(KERN_ERR "my_syscall: Already monitoring all PIDs for syscall %d\n", syscall);
                    r = -EBUSY;
                } else {
                    destroy_list(syscall);
                    table[syscall].monitored = 2;
                    printk(KERN_INFO "my_syscall: Started monitoring all PIDs for syscall %d\n", syscall);
                }
            } else {
                if (pid == -1) {
                    pid = current->pid;
                }
                if (check_pid_monitored(syscall, pid)) {
                    printk(KERN_ERR "my_syscall: PID %d already monitored for syscall %d\n", pid, syscall);
                    r = -EBUSY;
                } else {
                    r = add_pid_sysc(pid, syscall);
                    if (r == 0) {
                        table[syscall].monitored = 1;
                        printk(KERN_INFO "my_syscall: Started monitoring PID %d for syscall %d\n", pid, syscall);
                    } else {
                        printk(KERN_ERR "my_syscall: Failed to add PID %d to monitored list for syscall %d\n", pid, syscall);
                    }
                }
            }
            break;

        case REQUEST_STOP_MONITORING:
            if (!table[syscall].intercepted) {
                printk(KERN_ERR "my_syscall: Syscall %d not intercepted\n", syscall);
                r = -EINVAL;
            } else if (table[syscall].monitored == 0) {
                printk(KERN_ERR "my_syscall: Syscall %d not monitored\n", syscall);
                r = -EINVAL;
            } else if (pid == 0) {
                destroy_list(syscall);
                table[syscall].monitored = 0;
                printk(KERN_INFO "my_syscall: Stopped monitoring all PIDs for syscall %d\n", syscall);
            } else {
                if (pid == -1) {
                    pid = current->pid;
                }
                if (table[syscall].monitored == 2) {
                    printk(KERN_ERR "my_syscall: Monitoring all PIDs, can't stop individual PID %d for syscall %d\n", pid, syscall);
                    r = -EINVAL;
                } else {
                    r = del_pid_sysc(pid, syscall);
                    if (r == 0) {
                        if (table[syscall].listcount == 0) {
                            table[syscall].monitored = 0;
                        }
                        printk(KERN_INFO "my_syscall: Stopped monitoring PID %d for syscall %d\n", pid, syscall);
                    } else {
                        printk(KERN_ERR "my_syscall: Failed to remove PID %d from monitored list for syscall %d\n", pid, syscall);
                    }
                }
            }
            break;
    }

    spin_unlock(&my_table_lock);
    printk(KERN_DEBUG "my_syscall: Released my_table_lock\n");
    printk(KERN_DEBUG "my_syscall: Exiting with return value %d\n", r);
    return r;
}


long (*orig_custom_syscall)(void);

//----------------------------------------------------------------


//----------------------------------------------------------------
// Module initialization.
static int init_function(void) {
    int i;

    set_addr_rw((unsigned long)sys_call_table);

    spin_lock(&sys_call_table_lock);
    orig_custom_syscall = sys_call_table[MY_CUSTOM_SYSCALL];
    sys_call_table[MY_CUSTOM_SYSCALL] = my_syscall;
    spin_unlock(&sys_call_table_lock);

    spin_lock(&sys_call_table_lock);
    orig_exit_group = sys_call_table[__NR_exit_group];
    sys_call_table[__NR_exit_group] = my_exit_group;
    spin_unlock(&sys_call_table_lock);

    set_addr_ro((unsigned long)sys_call_table);

    spin_lock(&my_table_lock);
    for (i = 0; i < NR_syscalls; i++) {
        table[i].f = NULL;
        table[i].intercepted = 0;
        table[i].monitored = 0;
        table[i].listcount = 0;
        INIT_LIST_HEAD(&table[i].my_list);
    }
    spin_unlock(&my_table_lock);

    return 0;
}

// Module exits
static void exit_function(void) {
    int i;

    set_addr_rw((unsigned long)sys_call_table);

    spin_lock(&sys_call_table_lock);
    sys_call_table[MY_CUSTOM_SYSCALL] = orig_custom_syscall;
    spin_unlock(&sys_call_table_lock);

    spin_lock(&sys_call_table_lock);
    sys_call_table[__NR_exit_group] = orig_exit_group;
    spin_unlock(&sys_call_table_lock);

    set_addr_ro((unsigned long)sys_call_table);

    spin_lock(&my_table_lock);
    for (i = 0; i < NR_syscalls; i++) {
        if (table[i].intercepted) {
            spin_lock(&sys_call_table_lock);
            sys_call_table[i] = table[i].f;
            spin_unlock(&sys_call_table_lock);
        }
        destroy_list(i);
    }
    spin_unlock(&my_table_lock);
}

module_init(init_function);
module_exit(exit_function);

//----------------------------------------------------------------
