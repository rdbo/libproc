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

#define AT_MAX AT_MINSIGSTKSZ + 1

struct envvar {
	char *name;
	char *value;
};

struct proc {
	pid_t id;
	pid_t parent;
	pid_t tracer;
	unsigned long auxvals[AT_MAX];
	char state;
	char *platform;
	char *path;
	char *name;
	struct envvar *env;
	size_t nenv;
	char *cmdline;
	pid_t *threads;
	size_t nthreads;
	void *entry;
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
	size_t offset;
	void *end;
	int prot;
	int flags;
};

int enum_processes(int(*callback)(pid_t pid, void *arg), void *arg);
int check_process(pid_t pid);
size_t get_processes(pid_t **ppids);
pid_t get_process_parent(pid_t pid);
pid_t get_process_tracer(pid_t pid);
unsigned long get_process_auxv(pid_t pid, unsigned long type);
int get_process_auxvals(pid_t pid, unsigned long(*auxvals)[AT_MAX]);
uid_t get_process_uid(pid_t pid);
uid_t get_process_euid(pid_t pid);
gid_t get_process_gid(pid_t pid);
gid_t get_process_egid(pid_t pid);
char get_process_state(pid_t pid);
unsigned long get_process_platform(pid_t pid);
size_t get_process_path(pid_t pid, char **ppathbuf);
size_t get_process_name(pid_t pid, char **pnamebuf);
size_t get_process_env(pid_t pid, struct envvar **penvbuf);
size_t get_process_cmdline(pid_t pid, char **pcmdline);
int enum_threads(int(*callback)(pid_t tid, void *arg), void *arg);
size_t get_process_threads(pid_t pid, pid_t **pthreads);


#endif
