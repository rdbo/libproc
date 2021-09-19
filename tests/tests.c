#include <libproc.h>
#include <stdio.h>

int enum_proc_cb(pid_t pid, void *arg)
{
	printf("%d ", pid);
	return 0;
}

int main()
{
	char *procpath;
	char *procname;
	struct envvar *env;
	size_t nenvs;

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
	nenvs = proc_getenv(getpid(), &env);
	{
		size_t i;
		for (i = 0; i < nenvs; ++i) {
			printf("Name: %s\n", env[i].name);
			printf("Value: %s\n", env[i].value);
		}
	}
	free(env);

	getchar();

	return 0;
}
