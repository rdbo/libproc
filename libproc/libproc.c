#include "libproc.h"
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <memory.h>
#include <fcntl.h>
#include <sys/stat.h>

struct get_processes_struct {
	pid_t **ppids;
	size_t npids;
};

static char *get_filebuf(char *path)
{
	int fd;
	char *filebuf = (char *)NULL;
	char databuf[1024] = { 0 };
	ssize_t total = 0;
	ssize_t rdsize;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return filebuf;
	
	while ((rdsize = read(fd, databuf, sizeof(databuf))) > 0) {
		char *old_filebuf = filebuf;
		
		filebuf = malloc(total + rdsize + 1);
		if (old_filebuf) {
			if (filebuf)
				memcpy(filebuf, old_filebuf, (size_t)total);
			free(old_filebuf);
		}

		if (!filebuf)
			break;
		
		memcpy(&filebuf[total], databuf, (size_t)rdsize);
		total += rdsize;
		filebuf[total] = '\x00';
	}

	close(fd);

	return filebuf;
}

int enum_processes(int(*callback)(pid_t pid, void *arg), void *arg)
{
	DIR *procdir;
	struct dirent *pdirent;

	if (!callback) {
		errno = EINVAL;
		return -1;
	}

	procdir = opendir("/proc");
	if (!procdir)
		return -1;
	
	while((pdirent = readdir(procdir))) {
		pid_t curpid;

		curpid = (pid_t)atoi(pdirent->d_name);
		if (!curpid)
			continue;
		
		if (callback(curpid, arg))
			break;
	}
	
	closedir(procdir);
	return 0;
}

int check_process(pid_t pid)
{
	char proc_path[64] = { 0 };
	struct stat st;

	snprintf(proc_path, sizeof(proc_path) - 1, "/proc/%d", pid);
	if (!stat(proc_path, &st) && S_ISDIR(st.st_mode))
		return 1;
	return 0;
}

static int get_processes_callback(pid_t pid, void *arg)
{
	struct get_processes_struct *parg;
	pid_t *old_pids;

	parg = (struct get_processes_struct *)arg;
	old_pids = *parg->ppids;
	*parg->ppids = calloc(parg->npids + 1, sizeof(pid_t));
	if (old_pids) {
		if (*parg->ppids) {
			memcpy(*parg->ppids, old_pids,
			       parg->npids * sizeof(pid_t));
		}
		free(old_pids);
	}

	if (!(*parg->ppids)) {
		parg->npids = 0;
		return -1;
	}

	(*parg->ppids)[parg->npids] = pid;
	++parg->npids;

	return 0;
}

size_t get_processes(pid_t **ppids)
{
	struct get_processes_struct arg;

	arg.ppids = ppids;
	arg.npids = 0;

	if (!arg.ppids) {
		errno = EINVAL;
		return arg.npids;
	}

	*arg.ppids = (pid_t *)NULL;

	enum_processes(get_processes_callback, (void *)&arg);

	return arg.npids;
}

static pid_t _get_process_parent(char *status_filebuf)
{
	pid_t parent = (pid_t)-1;
	char *ptr;

	ptr = strstr(status_filebuf, "PPid:\t");
	if (!ptr)
		return parent;
	ptr = strchr(ptr, '\t');
	ptr = &ptr[1];
	parent = (pid_t)atoi(ptr);

	return parent;
}

pid_t get_process_parent(pid_t pid)
{
	pid_t parent = (pid_t)-1;
	char status_path[64] = { 0 };
	char *status_filebuf;
	
	snprintf(status_path, sizeof(status_path) - 1, "/proc/%d/status", pid);
	if ((status_filebuf = get_filebuf(status_path))) {
		parent = _get_process_parent(status_filebuf);
		free(status_filebuf);
	}
	
	return parent;
}

static pid_t _get_process_tracer(char *status_filebuf)
{
	pid_t tracer = (pid_t)-1;
	char *ptr;

	ptr = strstr(status_filebuf, "TracerPid:\t");
	if (!ptr)
		return tracer;
	ptr = strchr(ptr, '\t');
	ptr = &ptr[1];
	tracer = (pid_t)atoi(ptr);

	return tracer;
}

pid_t get_process_tracer(pid_t pid)
{
	pid_t tracer = (pid_t)-1;
	char status_path[64] = { 0 };
	char *status_filebuf;
	
	snprintf(status_path, sizeof(status_path) - 1, "/proc/%d/status", pid);
	if ((status_filebuf = get_filebuf(status_path))) {
		tracer = _get_process_tracer(status_filebuf);
		free(status_filebuf);
	}
	
	return tracer;
}

unsigned long get_process_auxv(pid_t pid, unsigned long type)
{
	struct {
		unsigned long type;
		unsigned long value;
	} auxv = { 0, 0 };
	char auxv_path[64] = { 0 };
	int fd;
	
	snprintf(auxv_path, sizeof(auxv_path) - 1, "/proc/%d/auxv", pid);

	fd = open(auxv_path, O_RDONLY);
	if (fd == -1)
		return auxv.value;
	
	while ((read(fd, &auxv, sizeof(auxv))) > 0) {
		if (auxv.type == type)
			break;
	}

	return auxv.value;
}

int get_process_auxvals(pid_t pid, unsigned long(*auxvals)[AT_MAX])
{
	struct {
		unsigned long type;
		unsigned long value;
	} auxv = { 0, 0 };
	char auxv_path[64] = { 0 };
	int fd;
	size_t i;
	
	snprintf(auxv_path, sizeof(auxv_path) - 1, "/proc/%d/auxv", pid);

	fd = open(auxv_path, O_RDONLY);
	if (fd == -1)
		return -1;
	
	for (i = 0; i < AT_MAX; ++i) {
		if (read(fd, &auxv, sizeof(auxv)) <= 0)
			break;
		
		(*auxvals)[i] = auxv.value;
	}

	return 0;
}

uid_t get_process_uid(pid_t pid)
{
	return (uid_t)get_process_auxv(pid, AT_UID);
}

uid_t get_process_euid(pid_t pid)
{
	return (uid_t)get_process_auxv(pid, AT_EUID);
}

gid_t get_process_gid(pid_t pid)
{
	return (gid_t)get_process_auxv(pid, AT_GID);
}

gid_t get_process_egid(pid_t pid)
{
	return (gid_t)get_process_auxv(pid, AT_EGID);
}

static char _get_process_state(char *status_filebuf)
{
	char state = 0;
	char *ptr;

	ptr = strstr(status_filebuf, "State:\t");
	if (!ptr)
		return state;
	ptr = strchr(ptr, '\t');
	ptr = &ptr[1];
	state = *ptr;

	return state;
}

char get_process_state(pid_t pid)
{
	char state = 0;
	char status_path[64] = { 0 };
	char *status_filebuf;
	
	snprintf(status_path, sizeof(status_path) - 1, "/proc/%d/status", pid);
	if ((status_filebuf = get_filebuf(status_path))) {
		state = _get_process_state(status_filebuf);
		free(status_filebuf);
	}
	
	return state;
}

unsigned long get_process_platform(pid_t pid)
{
	return get_process_auxv(pid, AT_PLATFORM);
}

size_t get_process_path(pid_t pid, char **ppathbuf)
{
	size_t pathlen = 0;
	char exe_path[64] = { 0 };
	char *pathbuf;

	pathbuf = (char *)calloc(PATH_MAX, sizeof(char));
	if (!pathbuf)
		return pathlen;

	snprintf(exe_path, sizeof(exe_path) - 1, "/proc/%d/exe", pid);
	readlink(exe_path, pathbuf, PATH_MAX - 1);
	pathbuf[PATH_MAX] = '\x00';

	pathlen = strlen(pathbuf);
	*ppathbuf = (char *)calloc(pathlen + 1, sizeof(char));
	if (*ppathbuf) {
		strncpy(*ppathbuf, pathbuf, pathlen);
		(*ppathbuf)[pathlen] = '\x00';
	} else {
		pathlen = 0;
	}

	free(pathbuf);

	return pathlen;
}

static size_t _get_process_name(char *status_filebuf, char **pnamebuf)
{
	char name = 0;
	char *ptr;
	char *endptr;
	size_t len = 0;

	ptr = strstr(status_filebuf, "Name:\t");
	if (!ptr)
		return name;
	ptr = strchr(ptr, '\t');
	ptr = &ptr[1];
	endptr = strchr(ptr, '\n');
	len = (size_t)((ptrdiff_t)endptr - (ptrdiff_t)ptr);
	*pnamebuf = malloc(len + 1);
	if (!(*pnamebuf)) {
		len = 0;
		return len;
	}

	strncpy(*pnamebuf, ptr, len);
	(*pnamebuf)[len] = '\x00';

	return len;
}

size_t get_process_name(pid_t pid, char **pnamebuf)
{
	size_t namelen;
	char status_path[64] = { 0 };
	char *status_filebuf;
	
	snprintf(status_path, sizeof(status_path) - 1, "/proc/%d/status", pid);
	if ((status_filebuf = get_filebuf(status_path))) {
		namelen = _get_process_name(status_filebuf, pnamebuf);
		free(status_filebuf);
	}
	
	return namelen;
}

size_t get_process_env(pid_t pid, struct envvar **penvbuf)
{
	size_t nenvvars = 0;
	char environ_path[64] = { 0 };
	char *environ_filebuf;
	char *ptr;

	snprintf(environ_path, sizeof(environ_path) - 1,
		 "/proc/%d/environ", pid);
	
	environ_filebuf = get_filebuf(environ_path);
	if (!environ_filebuf)
		return nenvvars;
	
	*penvbuf = (struct envvar *)NULL;

	for (ptr = environ_filebuf; (ptr = strchr(ptr, '=')); ptr = &ptr[1]) {
		struct envvar envvar;
		struct envvar *old_envbuf;
		size_t namelen;
		size_t vallen;
		char *pequals = ptr;

		while (*ptr != '\x00' || ptr == environ_filebuf)
			ptr = &ptr[-1];
		
		if (*ptr == '\x00')
			ptr = &ptr[1];
		
		/* TODO: Add 'malloc' check */
		namelen = (size_t)((ptrdiff_t)pequals - (ptrdiff_t)ptr);
		envvar.name = malloc(namelen + 1);
		strncpy(envvar.name, ptr, namelen);
		envvar.name[namelen] = '\x00';

		ptr = &pequals[1];
		vallen = strlen(ptr);
		envvar.value = malloc(vallen + 1);
		strncpy(envvar.value, ptr, vallen);
		envvar.value[vallen] = '\x00';

		ptr = &ptr[vallen]; /* go to null terminator */

		/* TODO: Add 'calloc' check */
		old_envbuf = *penvbuf;
		*penvbuf = calloc(nenvvars + 1, sizeof(struct envvar));
		
		if (old_envbuf) {
			if (*penvbuf) {
				memcpy(*penvbuf, old_envbuf,
				       nenvvars * sizeof(struct envvar));
			}
		}

		(*penvbuf)[nenvvars] = envvar;
		++nenvvars;
	}

	free(environ_filebuf);

	return nenvvars;
}
