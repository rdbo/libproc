/*
 * libproc - library to abstract information from /proc
 * by rdbo
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

#define AT_MAX 64 /* AT_MINSIGSTKSZ + 1 */

struct environ {
	char *name;
	char *value;
};

struct proc {
	pid_t id;
	pid_t parent;
	pid_t tracer;
	unsigned long *auxvals;
	char state;
	char *platform;
	char *path;
	char *name;
	struct environ *environ;
	size_t environ_len;
	char **cmdline;
	size_t cmdlen;
	pid_t *threads;
	size_t nthreads;
	unsigned long entry;
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
int proc_openproc(pid_t pid, struct proc *pproc);
void proc_closeproc(struct proc *pproc);


#endif
