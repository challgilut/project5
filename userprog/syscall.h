#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

struct list been_waited;

struct lock lock;

struct lock exec_lock;

#endif /* userprog/syscall.h */
