#include <libproc.h>
#include <stdio.h>

int enum_proc_cb(pid_t pid, void *arg)
{
	printf("%d ", pid);
	return 0;
}

int main()
{
	pid_t *pids;
	size_t npids;
	char *procpath;
	char *procname;
	struct envvar *env;
	size_t nenvs;

	npids = get_processes(&pids);
	printf("[*] Processes: { ");
	{
		size_t i;

		for (i = 0; i < npids; ++i) {
			printf("%d ", pids[i]);
		}
	}
	printf("}\n");
	free(pids);
	
	printf("[*] Parent: %d\n", get_process_parent(getpid()));
	printf("[*] Tracer: %d\n", get_process_tracer(getpid()));
	printf("[*] UID: %d\n", get_process_uid(getpid()));
	printf("[*] EUID: %d\n", get_process_euid(getpid()));
	printf("[*] GID: %d\n", get_process_gid(getpid()));
	printf("[*] EGID: %d\n", get_process_egid(getpid()));
	printf("[*] State: %c\n", get_process_state(getpid()));
	printf("[*] Platform: %s\n", (char *)get_process_platform(getpid()));
	get_process_path(getpid(), &procpath);
	printf("[*] Process Path: %s\n", procpath);
	free(procpath);
	get_process_name(getpid(), &procname);
	printf("[*] Process Name: %s\n", procname);
	free(procname);
	nenvs = get_process_env(getpid(), &env);
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
