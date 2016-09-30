#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
//#include "pagedir.c"
#include "devices/shutdown.h"
#include "lib/user/syscall.h"
#include "filesys/filesys.h"
//#include <unistd.h>

#define WNOHANG   0x00000001
#define WUNTRACED 0x00000002
#define WSTOPPED  WUNTRACED
#define WEXITED   0x00000004
#define WCONTINUED  0x00000008
#define WNOWAIT   0x01000000


struct file_descriptor{
  int fd_num;
  tid_t owner;
  struct file *file_struct;
  struct list_elem elem;
};

struct list openFiles;
struct file_descriptor *getOpenFile(int fd);
struct semaphore sema;

static int (*syscall_handlers[20]) (struct intr_frame *);
bool ptr_verification(void *ptr);

static void syscall_handler (struct intr_frame *);
//need to delcare some functions here;
/*
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove (const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);*/
int wait(tid_t pid);
tid_t exec(const char *cmd_line);
int open(const char *file);

int write(int fd, const void *buffer, unsigned size)
{
  if (fd == STDOUT_FILENO){
    putbuf((char *)buffer, (size_t)size);
    return (int)size;
  }
  return -1;
}

/*Terminates the current user program, returning status to the kernel.
* If the process's parent waits for it (see below), this is the status that will be returned. Conventionally, 
* a status of 0 indicates success and nonzero values indicate errors. 
*/
void exit(int status)
{
 // struct thread *t = 
  printf("%s: exit(%i)\n", thread_current()->name, status);
  thread_exit(status);
}

/*Creates a new file called file initially initial_size bytes in size. Returns true if successful, false otherwise.
* Creating a new file does not open it: opening the new file is a separate operation which would require a open
* system call. 
*/
bool create(const char *file, unsigned initial_size)
{
  //if(strlen(file) > PGSIZE || strlen(file) != initial_size)
    //return false;
  return filesys_create(file, initial_size);
}


void
syscall_init (void) 
{
  list_init(&proc_wait_list);
  list_init(&return_status_list);
  list_init(&openFiles);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscall_handlers[SYS_WRITE] = &write;
  sema_init(&sema,1);
}

static void
syscall_handler (struct intr_frame *f) 
{//need to change system call numbers
  //printf ("system call!\n");
  int i = 0;
  for(; i < 4; i++)
  {
    if(!ptr_verification(f->esp + i))
      exit(-1);
}
  int esp =*(int*)(f->esp);
  if(esp == 0){
    //halt();
  }
  else if(esp == 1){
    int status;
    for(i = 0; i < 4; i++)
    {
      if(!ptr_verification(f->esp + 4 + i))
      {
        exit(-1);
        return;
      }
        
    }
    status = *((int*)f->esp+1);
    exit(status);
  }
  else if(esp == 2){
    int i = 0;
    for(; i < 4; i++)
    {
      if(!ptr_verification(f->esp + 4 + i))
        exit(-1);
    }
    char *cmd = *(char**)(f->esp+4);
    f->eax = exec(cmd);
  }
  else if(esp == 3){
    tid_t id = 0;
    int i = 0;
    for(; i< 4; i ++)
    {
      if(!ptr_verification(f->esp +4 +i))
        exit(-1);
    }
    id = *((int*)f->esp + 1);
    f->eax = wait(id);
  }
  else if(esp == 4){
    for(i = 0; i < 4; i++)
    {
      if (!ptr_verification(f->esp + 4 + i) || !ptr_verification(f->esp + 8 + i)){
        exit(-1);
      }
    }
    char *name = *(char **)(f->esp + 4);
    unsigned size = *(int *)(f->esp + 8);
    if(name == NULL || strcmp(name, "") == 0)
      exit(-1);
    f->eax = create(name, size);
  }
  else if(esp == 5){
    //remove(char *temp );
  }
  else if(esp == 6){
    for(; i < 4; i ++)
    {
      if(!ptr_verification(f->esp + 4 + i))
        exit(-1);
    }
    char *name = *(char **)(f->esp + 4); 
    if(name == NULL)
      exit(-1);
    f->eax = open(name);
  }
  else if(esp == 7){
    int fd = *(int *)(f->esp + 4);
    f->eax = filesize(fd);
  }
  else if(esp == 8){
    //read(2, char *temp, 2);
  }
  else if(esp == 9)
  {
    int fd = *(int *)(f->esp + 4);
    void *buffer = *(char**)(f->esp + 8);
    unsigned size = *(unsigned *)(f->esp + 12);
    write(fd, buffer, size);
  }
  else{
    thread_exit (0);

  }
}
/*Terminates Pintos by calling shutdown_power_off() (declared in "threads/init.h").
*This should be seldom used, because you lose some information about possible deadlock situations, etc.
*/
void halt(void)
{
  printf("halt\n");
  shutdown_power_off();
}

/*Runs the executable whose name is given in cmd_line, passing any given arguments,
* and returns the new process's program id (pid). Must return pid -1, which otherwise should not be a valid pid,
* if the program cannot load or run for any reason. Thus, the parent process cannot return from the exec until
* it knows whether the child process successfully loaded its executable. 
* You must use appropriate synchronization to ensure this. 
*/
tid_t exec(const char *cmd_line)
{
  if(strcmp(cmd_line, "") == 0 || strlen(cmd_line) == 0 || strlen(cmd_line) > PGSIZE)
  {
    return -1;
  }
  return process_execute(cmd_line);
}


bool parent_of(tid_t tid){
    struct thread *t = thread_get(tid);
    if(t == NULL || t->parent != thread_tid()){
      return false;
    }
    return true;
  }

/*Waits for a child process pid and retrieves the child's exit status.
* If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit.
* If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception),
* wait(pid) must return -1. It is perfectly legal for a parent process to wait for child processes that
* have already terminated by the time the parent calls wait, but the kernel must still allow the parent to
* retrieve its child's exit status, or learn that the child was terminated by the kernel.
*/
int wait(tid_t pid)
{
  if(!parent_of(pid))
    exit(-1);
  int value = 0;
  return process_wait(pid);
}

/*Deletes the file called file. Returns true if successful, false otherwise.
* A file may be removed regardless of whether it is open or closed, and removing an open file does not close it.
* See Removing an Open File, for details.
*/
bool remove (const char *file)
{

}


int setfd_num(){
  static int current_fd = 1;
  return ++current_fd;
}

struct file_descriptor *getOpenFile(int fd){
  struct list_elem *e;
  struct file_descriptor *fd_struct;
  e = list_tail(&openFiles);
  while((e = list_prev(e)) != list_head(&openFiles)){
    fd_struct = list_entry (e,struct file_descriptor, elem);
    if(fd_struct-> fd_num == fd)
      return fd_struct;
  }
  return NULL;
}

/*Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could
* not be opened. File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is standard input,
* fd 1 (STDOUT_FILENO) is standard output. The open system call will never return either of these file descriptors,
* which are valid as system call arguments only as explicitly described below.
* Each process has an independent set of file descriptors. File descriptors are not inherited by child processes.
* When a single file is opened more than once, whether by a single process or different processes, each open returns
* a new file descriptor. Different file descriptors for a single file are closed independently in separate calls to close
* and they do not share a file position.
*/
int open(const char *name)
{
  if(!ptr_verification(name))
    exit(-1);

  sema_down(&sema);
  struct file *file = filesys_open(name); 

  if(file != NULL){
    struct file_descriptor *file_descriptor = malloc(sizeof(struct file_descriptor));
    file_descriptor->fd_num = setfd_num();
    file_descriptor->owner = thread_current()->tid;
    file_descriptor->file_struct = file;
    list_push_back(&openFiles,&file_descriptor->elem);
    sema_up(&sema);
    return file_descriptor->fd_num;
  }
  sema_up(&sema);
  return (-1);
}
   
//Returns the size, in bytes, of the file open as fd.
int filesize(int fd)
{
  sema_down(&sema);
  struct file *file = getOpenFile(fd);
  if(file != NULL){
    int filesize = file_length(file);
    sema_up(&sema);
    return filesize;
  } 
  sema_up(&sema);
  return (-1);
}
 
/*    Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file),
* or -1 if the file could not be read (due to a condition other than end of file).
* Fd 0 reads from the keyboard using input_getc(). 
*/
int read(int fd, void *buffer, unsigned size)
{

}

/*
* checks for pointer being equal to NULL or if address is not mapped to memory
* Returns false if ptr is invalid and true if valid
*/
bool ptr_verification(void *ptr) {
  struct thread *t = thread_current(); //current thread
  int base = PHYS_BASE;
  if(ptr != NULL && is_user_vaddr(ptr)){ //checks if the pointer is NULL and if it is a valid address
    if(pagedir_get_page (t->pagedir, ptr) != NULL) //checks if value is mapped to memory, if it is then returns true else returns false
      return true;
  } 
  return false;
}
