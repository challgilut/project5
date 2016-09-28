#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (int status);
void process_activate (void);

//Stuff needed for waiting
struct process_wait{
  int status;
  tid_t waiting_for;
  struct semaphore sema;
  struct list_elem elem;
};

struct return_status{
	int status;
	tid_t id;
	struct list_elem elem;
};

struct list proc_wait_list; //List of processes being waited for;
struct list return_status_list; //list of return status

#endif /* userprog/process.h */
