/* ==================================
 * = libproc - procfs API for Linux =
 * =                    by rdbo     =
 * ==================================
 */

#ifndef LIBPROC_H
#define LIBPROC_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <unistd.h>
#include <limits.h>
#include <malloc.h>
#include <sys/auxv.h>

struct environ {
	char *name;
	char *value;
};

struct proc {
	pid_t pid;
	pid_t ppid;
	pid_t tracer;
	unsigned long *auxvals;
	size_t nauxvals;
	char state;
	char *path;
	char *name;
	struct environ *environ;
	size_t nenviron;
	char **cmdline;
	size_t ncmdline;
	pid_t *threads;
	size_t nthreads;
};

struct module {
	void *base;
	size_t size;
	void *end;
	char *path;
	char *name;
};

struct page {
	void *base;
	size_t size;
	unsigned long offset;
	void *end;
	int prot;
	int flags;
};

int proc_enumpids(int(*callback)(pid_t pid, void *arg), void *arg);
int proc_checkpid(pid_t pid);
pid_t proc_getppid(pid_t pid);
pid_t proc_gettracer(pid_t pid);
int proc_enumauxvals(pid_t pid, int(*callback)(unsigned long type,
		     unsigned long val, void *arg), void *arg);
unsigned long proc_getauxval(pid_t pid, unsigned long type);
uid_t proc_getuid(pid_t pid);
uid_t proc_geteuid(pid_t pid);
gid_t proc_getgid(pid_t pid);
gid_t proc_getegid(pid_t pid);
char proc_getstate(pid_t pid);
unsigned long proc_getplatform(pid_t pid);
size_t proc_getpath(pid_t pid, char **ppathbuf, size_t maxlen);
size_t proc_getname(pid_t pid, char **pnamebuf, size_t maxlen);
int proc_enumenviron(pid_t pid,
		     int(*callback)(char *name, char *value, void *arg),
		     void *arg);
int proc_enumcmdline(pid_t pid, int(*callback)(char *cmdarg, void *arg),
		     void *arg);
size_t proc_getcmdline(pid_t pid, char **pcmdlinebuf, size_t maxlen);
int proc_enumthreads(pid_t pid, int(*callback)(pid_t tid, void *arg),
		     void *arg);
unsigned long proc_getentry(pid_t pid);
ssize_t proc_vmread(pid_t pid, off_t src, void *dst, size_t size);
ssize_t proc_vmwrite(pid_t pid, off_t dst, void *src, size_t size);
int proc_openproc(pid_t pid, struct proc *pproc);
void proc_closeproc(struct proc *pproc);

#endif
