#include <libproc.h>
#include <stdio.h>

int main()
{
	pid_t pid;
	struct proc proc;

	pid = getpid();
	if (proc_openproc(pid, &proc)) {
		printf("[!] Unable to open process\n");
		return -1;
	}

	printf("[*] PID: %d\n", proc.pid);
	printf("[*] PPID: %d\n", proc.ppid);
	printf("[*] Tracer: %d\n", proc.tracer);
	printf("[*] UID: %d\n", (uid_t)proc.auxvals[AT_UID]);
	printf("[*] EUID: %d\n", (uid_t)proc.auxvals[AT_EUID]);
	printf("[*] GID: %d\n", (gid_t)proc.auxvals[AT_GID]);
	printf("[*] EGID: %d\n", (gid_t)proc.auxvals[AT_EGID]);
	printf("[*] Entry: %p\n", (void *)proc.auxvals[AT_ENTRY]);
	printf("[*] State: %c\n", proc.state);
	printf("[*] Path: %s\n", proc.path);
	printf("[*] Name: %s\n", proc.name);
	printf("[*] Environment Variables: \n");
	{
		size_t i;
		
		for (i = 0; i < proc.nenviron; ++i) {
			printf("\t%s=%s\n", proc.environ[i].name,
			       proc.environ[i].value);
		}
	}
	printf("[*] Command Line: ");
	{
		size_t i;

		for (i = 0; i < proc.ncmdline; ++i) {
			printf("%s ", proc.cmdline[i]);
		}
	}
	printf("\n");
	printf("[*] Threads: { ");
	{
		size_t i;
		
		for (i = 0; i < proc.nthreads; ++i) {
			printf("%d ", proc.threads[i]);
		}
	}
	printf("}\n");

	printf("===================\n");

	proc_closeproc(&proc);

	printf("Press ENTER to exit...");
	getchar();

	return 0;
}
