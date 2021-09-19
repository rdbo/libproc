#include <libproc.h>
#include <stdio.h>

int enum_proc_cb(pid_t pid, void *arg)
{
	printf("%d ", pid);
	return 0;
}

int enum_environ_cb(char *name, char *value, void *arg)
{
	printf("\t%s=%s\n", name, value);
	return 0;
}

int enum_threads_cb(pid_t tid, void *arg)
{
	printf("%d ", tid);
	return 0;
}

int main()
{
	char *procpath;
	char *procname;
	char *cmdline;

	printf("[*] Processes: { ");
	proc_enumpids(enum_proc_cb, NULL);
	printf("}\n");
	
	printf("[*] Parent: %d\n", proc_getppid(getpid()));
	printf("[*] Tracer: %d\n", proc_gettracer(getpid()));
	printf("[*] UID: %d\n", proc_getuid(getpid()));
	printf("[*] EUID: %d\n", proc_geteuid(getpid()));
	printf("[*] GID: %d\n", proc_getgid(getpid()));
	printf("[*] EGID: %d\n", proc_getegid(getpid()));
	printf("[*] State: %c\n", proc_getstate(getpid()));
	printf("[*] Platform: %s\n", (char *)proc_getplatform(getpid()));
	proc_getpath(getpid(), &procpath, 0);
	printf("[*] Process Path: %s\n", procpath);
	free(procpath);
	proc_getname(getpid(), &procname, 0);
	printf("[*] Process Name: %s\n", procname);
	free(procname);
	printf("[*] Environment Variables:\n");
	proc_enumenviron(getpid(), enum_environ_cb, NULL);
	proc_getcmdline(getpid(), &cmdline, 0);
	printf("[*] Command Line: %s\n", cmdline);
	
	printf("[*] Threads: { ");
	proc_enumthreads(getpid(), enum_threads_cb, NULL);
	printf("}\n");

	getchar();

	return 0;
}
