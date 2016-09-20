#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

/*Terminates Pintos by calling shutdown_power_off() (declared in "threads/init.h").
*This should be seldom used, because you lose some information about possible deadlock situations, etc.
*/
void halt(void)
{

}

/*Terminates the current user program, returning status to the kernel.
* If the process's parent waits for it (see below), this is the status that will be returned. Conventionally, 
* a status of 0 indicates success and nonzero values indicate errors. 
*/
void exit(int status)
{

}

/*Runs the executable whose name is given in cmd_line, passing any given arguments,
* and returns the new process's program id (pid). Must return pid -1, which otherwise should not be a valid pid,
* if the program cannot load or run for any reason. Thus, the parent process cannot return from the exec until
* it knows whether the child process successfully loaded its executable. 
* You must use appropriate synchronization to ensure this. 
*/
pid_t exec(const char *cmd_line)
{

}

/*Waits for a child process pid and retrieves the child's exit status.
* If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit.
* If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception),
* wait(pid) must return -1. It is perfectly legal for a parent process to wait for child processes that
* have already terminated by the time the parent calls wait, but the kernel must still allow the parent to
* retrieve its child's exit status, or learn that the child was terminated by the kernel.
*/
int wait(pid_t pid)
{

}

/*Creates a new file called file initially initial_size bytes in size. Returns true if successful, false otherwise.
* Creating a new file does not open it: opening the new file is a separate operation which would require a open
* system call. 
*/
bool create(const char *file, unsigned initial_size)
{

}

/*Deletes the file called file. Returns true if successful, false otherwise.
* A file may be removed regardless of whether it is open or closed, and removing an open file does not close it.
* See Removing an Open File, for details.
*/
bool remove (const char *file)
{

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
int open(const char *file)
{

}
   
//Returns the size, in bytes, of the file open as fd.
int filesize(int fd)
{

}
 
/*    Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file),
* or -1 if the file could not be read (due to a condition other than end of file).
* Fd 0 reads from the keyboard using input_getc(). 
*/
int read(int fd, void *buffer, unsigned size)
{

}
