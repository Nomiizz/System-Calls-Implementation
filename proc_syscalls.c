#include <types.h>
#include <kern/errno.h>
#include <kern/unistd.h>
#include <kern/wait.h>
#include <lib.h>
#include <syscall.h>
#include <current.h>
#include <proc.h>
#include <thread.h>
#include <addrspace.h>
#include <copyinout.h>
#include <mips/trapframe.h>
#include "opt-A2.h"
#include <synch.h>
#include <limits.h>
#include <kern/fcntl.h>
#include <vfs.h>

/* Helper functions */
static int append_child(pid_t child_pid, pid_t child_arr[])
{
  int idx;

  for (idx = 0; idx < 256; idx++)
  {
    if (child_arr[idx] == -1)
    {
      break;
    }
  }

  if (idx > 255)
  {
    return -1;
  }

  child_arr[idx] = child_pid;

  return 0;
}

static int remove_child(pid_t child_pid, pid_t child_arr[])
{
  int idx;
  int i;

  for (idx = 0; idx < 256; idx++)
  {
    if (child_arr[idx] == child_pid)
    {
      break;
    }
  }

  if (idx > 255)
  {
    return -1;
  }

  /* Overwrite over the child pid location to remove it */
  for (i = idx; child_arr[i] != -1; i++)
  {
    child_arr[i] = child_arr[i + 1];
  }

  return 0;
}


int sys_fork(struct trapframe *tf, pid_t *retval) {

  struct proc *childProc = NULL;
  struct addrspace *childas = NULL;
  struct trapframe *childtf = NULL;
  int result;

  /* Create new process structure */
  childProc = proc_create_runprogram("childProc");
  if (childProc == NULL) 
  {
    return ENOMEM;   
  }

  /* Give new child process its parent's pid */
  childProc->parentpid = curproc->pid;

  /* Add the child pid to parents children_pid_array */
  result = append_child(childProc->pid, curproc->childpids);
  if (result < 0)
  {
    proc_destroy(childProc);
    return ENOMEM;
  }

  /* Create a copy of parent process address space */
  KASSERT(curproc->p_addrspace != NULL);
  result = as_copy(curproc->p_addrspace, &childas);

  if (result != 0)
  {
    proc_destroy(childProc);
    return result;
  }

  /* Create a copy of the trapframe for the child process*/
  childtf = kmalloc(sizeof(struct trapframe));
  if (childtf == NULL)
  {
    as_destroy(childas);
    proc_destroy(childProc);
    return ENOMEM;
  }

  memcpy(childtf, tf, sizeof(struct trapframe));

  /* Create a thread for the process */
  result = thread_fork("childThread", childProc, enter_forked_process, (void *)childtf, (unsigned long)childas);

  if (result != 0) {
    kprintf("thread_fork failed: %s\n", strerror(result));
    as_destroy(childas);
    proc_destroy(childProc);
    kfree(childtf);

    return result;
  }

  *retval = childProc->pid;
  return 0;
}

int sys_execv(userptr_t progname, userptr_t args, int *retval)
{
  struct addrspace *as;
  struct vnode *v;
  vaddr_t entrypoint, stackptr;
  int result;
  int args_count;
  size_t actual_len = 0;
  int i;
  char **argv_copy = NULL;
  int paddedlen;
  int len;

  if (progname == NULL) 
  {
        *retval = EFAULT;
        return -1;
  }

  /* Copy file path from user memory to kernel memory */
  char *progname_copy = kmalloc(sizeof(char) * NAME_MAX);
  result = copyinstr(progname, progname_copy, NAME_MAX, &actual_len);

  if (result)
  {
      kfree(progname_copy);
      *retval = result;
      return -1;
  }

  /* Open the executable file */
  result = vfs_open(progname_copy, O_RDONLY, 0, &v);
  if (result)
  {
    kfree(progname_copy);
    *retval = result;
    return -1;
  }

  kfree(progname_copy);

  /* Count number of arguments in the input */
  for (args_count = 0; args_count < ARG_MAX && ((userptr_t *)args)[args_count] != NULL; args_count++);

  if (args_count > ARG_MAX) 
  {
      *retval = E2BIG;
      return -1;
  }

  /* Copy the arguments to kernel memory */
  argv_copy = (char **) kmalloc(sizeof(char *) * args_count);
  if (argv_copy == NULL)
  {
    *retval = ENOMEM;
    return -1;
  }

  for (i = 0; i < args_count; i++)
  {
    /* +1 accomodates for NULL char */
    len = strlen(((char **)args)[i]) + 1;

    argv_copy[i] = (char *) kmalloc(len);
    if (argv_copy[i] == NULL)
    {
      kfree(argv_copy);
      *retval = ENOMEM;
      return -1;
    }

    result = copyin(((userptr_t *)args)[i], argv_copy[i], len);
    if (result)
    {
      kfree(argv_copy);
      *retval = result;
      return -1;
    }
  }

  /* Destroy the old address space */
  as = curproc_setas(NULL);

  as_destroy(as);

  /* We should be a new process since we have destroyed the as */
  KASSERT(curproc_getas() == NULL);

  /* Create a new address space. */
  as = as_create();
  if (as ==NULL)
  {
    vfs_close(v);
    *retval = ENOMEM;
    return -1;
  }

  /* Switch to it and activate it. */
  curproc_setas(as);
  as_activate();

  /* Load the executable. */
  result = load_elf(v, &entrypoint);
  if (result) 
  {
    /* p_addrspace will go away when curproc is destroyed */
    vfs_close(v);
    *retval = result;
    return -1;
  }

  /* Done with the file now. */
  vfs_close(v);

  /* Define the user stack in the address space */
  result = as_define_stack(as, &stackptr);
  if (result) 
  {
      /* p_addrspace will go away when curproc is destroyed */
      *retval = result;
      return -1;
  }

  /* Copy the arguments and their addresses to the user program stack */
  char **arg_addrs = (char **) kmalloc(sizeof(char *) * (args_count + 1));
  if (arg_addrs == NULL)
  {
    *retval = ENOMEM;
    return -1;
  }

  for (i = 0; i < args_count; i++) 
  {
    /* +1 accomodates for NULL char */
    len = strlen(argv_copy[i]) + 1;
    paddedlen = len;

    if (paddedlen % 4)
    {
        /* Padding for memory alignment */
        paddedlen += (4 - (paddedlen % 4));
    }

    stackptr -= paddedlen;

    /* Store address of arguments */
    arg_addrs[i] = (char *)stackptr;

    copyout(argv_copy[i], (userptr_t)stackptr, len);
  }

  arg_addrs[i] = NULL;
  stackptr -= sizeof(char *) * (args_count + 1);
  copyout(arg_addrs, (userptr_t)stackptr, sizeof(char *) * (args_count + 1));

  /* Free all the allocated data structures */
  for (i = 0; i < args_count; i++) 
  {
    kfree(argv_copy[i]);
  }

  kfree(arg_addrs);
  kfree(argv_copy);

  /* Warp to user mode. */
  enter_new_process(args_count /*argc*/, (userptr_t) stackptr /*userspace addr of argv*/,
        stackptr, entrypoint);

  /* enter_new_process does not return. */
  panic("enter_new_process returned\n");
  
  *retval = EINVAL;
  return -1;
}


  /* this implementation of sys__exit does not do anything with the exit code */
  /* this needs to be fixed to get exit() and waitpid() working properly */

void sys__exit(int exitcode) {

  struct addrspace *as;
  struct proc *p = curproc;
  bool destroySynchs = false;
  int idx; 

#if OPT_A2
  lock_acquire(p->exit_lock);

  /* Set these values to estabilish that the process is exiting */
  p->exitcode = _MKWAIT_EXIT(exitcode);
  p->has_exit = true;

  lock_release(p->exit_lock);

  /* If parent is alive then signal through CV in case its waiting */
  if ((p->parentpid != -1) && (proc_arr[p->parentpid] != NULL)) // To check that this process actually has a parent
  {
    spinlock_acquire(&pid_lock); // To make sure proc_arr is mutually excluded when accessing
    if ((proc_arr[p->parentpid])->has_exit == false) // Parent is alive
    {
      /* Create a shallow copy of the proc and have proc_arr[pid] point to it */
      struct proc *proc_copy = kmalloc(sizeof(struct proc));
      if (proc_copy == NULL) {
        panic("Could not allocate memory for the process copy");
      }

      memcpy(proc_copy, p, sizeof(struct proc));
     
      proc_arr[p->pid] = proc_copy;

      /* Send signal to possibly waiting parent */
      lock_acquire(proc_copy->exit_lock);
      cv_broadcast(proc_copy->exit_cv, proc_copy->exit_lock);
      lock_release(proc_copy->exit_lock);
    }
    else // Parent is dead
    {
      proc_arr[p->pid] = NULL;
      destroySynchs = true;
    }
    spinlock_release(&pid_lock);
  }
  else // Does not have a parent
  {
    spinlock_acquire(&pid_lock);
    proc_arr[p->pid] = NULL;
    destroySynchs = true;
    spinlock_release(&pid_lock);
  }

  /* -> If this process has children that have exited earlier then their values in proc_arr need to be set to NULL */
  for (idx = 0; p->childpids[idx] != -1; idx++)
  {
    if (proc_arr[p->childpids[idx]]->has_exit == true)
    {
      /* Free the proc_arr slot and put it to NULL */
      spinlock_acquire(&pid_lock);

      lock_destroy(proc_arr[p->childpids[idx]]->exit_lock);
      cv_destroy(proc_arr[p->childpids[idx]]->exit_cv);
      kfree(proc_arr[p->childpids[idx]]);
      proc_arr[p->childpids[idx]] = NULL;

      spinlock_release(&pid_lock);
    }
  }


  /* Destroy the lock and condition variable */
  if (destroySynchs) {
    lock_destroy(p->exit_lock);
    cv_destroy(p->exit_cv);
  }
#endif

  DEBUG(DB_SYSCALL,"Syscall: _exit(%d)\n",exitcode);

  KASSERT(curproc->p_addrspace != NULL);
  as_deactivate();
  /*
   * clear p_addrspace before calling as_destroy. Otherwise if
   * as_destroy sleeps (which is quite possible) when we
   * come back we'll be calling as_activate on a
   * half-destroyed address space. This tends to be
   * messily fatal.
   */
  as = curproc_setas(NULL);
  as_destroy(as);

  /* detach this thread from its process */
  /* note: curproc cannot be used after this call */
  proc_remthread(curthread);

  /* if this is the last user process in the system, proc_destroy()
     will wake up the kernel menu thread */
  proc_destroy(p);
  
  thread_exit();
  /* thread_exit() does not return, so we should never get here */
  panic("return from thread_exit in sys_exit\n");
}


/* stub handler for getpid() system call                */
int
sys_getpid(pid_t *retval)
{
  /* for now, this is just a stub that always returns a PID of 1 */
  /* you need to fix this to make it work properly */
  *retval = curproc->pid;
  return(0);
}

/* stub handler for waitpid() system call                */

int
sys_waitpid(pid_t pid,
	    userptr_t status,
	    int options,
	    pid_t *retval)
{
  int exitstatus;
  int result;

  /* this is just a stub implementation that always reports an
     exit status of 0, regardless of the actual exit status of
     the specified process.   
     In fact, this will return 0 even if the specified process
     is still running, and even if it never existed in the first place.

     Fix this!
  */

#if OPT_A2

  /* Wait for child process to exit */
  lock_acquire(proc_arr[pid]->exit_lock);
  while(proc_arr[pid]->has_exit != true)
  {
    cv_wait(proc_arr[pid]->exit_cv, proc_arr[pid]->exit_lock);
  }
  
  /* Get the exit status of the child */
  exitstatus = proc_arr[pid]->exitcode;

  lock_release(proc_arr[pid]->exit_lock);

  /* Remove this child from the child_pid_array */
  result = remove_child(pid, curproc->childpids);
  if (result < 0)
  {
    return ENOMEM;
  }

  /* Free the proc_arr slot and put it to NULL */
  spinlock_acquire(&pid_lock);

  lock_destroy(proc_arr[pid]->exit_lock);
  cv_destroy(proc_arr[pid]->exit_cv);
  kfree(proc_arr[pid]);
  proc_arr[pid] = NULL;

  spinlock_release(&pid_lock);

#endif

  if (options != 0) {
    return(EINVAL);
  }
  /* for now, just pretend the exitstatus is 0 */
  //exitstatus = 0;
  result = copyout((void *)&exitstatus,status,sizeof(int));
  if (result) {
    return(result);
  }
  *retval = pid;
  return(0);
}

