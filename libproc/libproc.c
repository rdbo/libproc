#include "libproc.h"
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <memory.h>
#include <fcntl.h>
#include <sys/stat.h>

struct proc_getauxval_struct {
	unsigned long type;
	unsigned long value;
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

int proc_enumpids(int(*callback)(pid_t pid, void *arg), void *arg)
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

int proc_checkpid(pid_t pid)
{
	char proc_path[64] = { 0 };
	struct stat st;

	snprintf(proc_path, sizeof(proc_path) - 1, "/proc/%d", pid);
	if (!stat(proc_path, &st) && S_ISDIR(st.st_mode))
		return 1;
	return 0;
}

static pid_t _proc_getppid(char *status_filebuf)
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

pid_t proc_getppid(pid_t pid)
{
	pid_t parent = (pid_t)-1;
	char status_path[64] = { 0 };
	char *status_filebuf;
	
	snprintf(status_path, sizeof(status_path) - 1, "/proc/%d/status", pid);
	if ((status_filebuf = get_filebuf(status_path))) {
		parent = _proc_getppid(status_filebuf);
		free(status_filebuf);
	}
	
	return parent;
}

static pid_t _proc_gettracer(char *status_filebuf)
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

pid_t proc_gettracer(pid_t pid)
{
	pid_t tracer = (pid_t)-1;
	char status_path[64] = { 0 };
	char *status_filebuf;
	
	snprintf(status_path, sizeof(status_path) - 1, "/proc/%d/status", pid);
	if ((status_filebuf = get_filebuf(status_path))) {
		tracer = _proc_gettracer(status_filebuf);
		free(status_filebuf);
	}
	
	return tracer;
}

int proc_enumauxvals(pid_t pid, int(*callback)(unsigned long type,
		     unsigned long val, void *arg), void *arg)
{
	struct {
		unsigned long type;
		unsigned long value;
	} auxv = { 0, 0 };
	char auxv_path[64] = { 0 };
	int fd;

	if (!callback) {
		errno = EINVAL;
		return -1;
	}
	
	snprintf(auxv_path, sizeof(auxv_path) - 1, "/proc/%d/auxv", pid);

	fd = open(auxv_path, O_RDONLY);
	if (fd == -1)
		return auxv.value;
	
	while ((read(fd, &auxv, sizeof(auxv))) > 0) {
		if (callback(auxv.type, auxv.value, arg))
			break;
	}

	return 0;
}

static int _proc_getauxval_callback(unsigned long type, unsigned long value,
				      void *arg)
{
	struct proc_getauxval_struct *parg;

	parg = (struct proc_getauxval_struct *)arg;

	if (type == parg->type) {
		parg->value = value;
		return 1;
	}

	return 0;
}

unsigned long proc_getauxval(pid_t pid, unsigned long type)
{
	struct proc_getauxval_struct arg;

	arg.type = type;
	arg.value = (unsigned long)-1;

	if (proc_enumauxvals(pid, _proc_getauxval_callback, (void *)&arg))
		arg.value = (unsigned long)-1;
	
	return arg.value;
}

uid_t proc_getuid(pid_t pid)
{
	return (uid_t)proc_getauxval(pid, AT_UID);
}

uid_t proc_geteuid(pid_t pid)
{
	return (uid_t)proc_getauxval(pid, AT_EUID);
}

gid_t proc_getgid(pid_t pid)
{
	return (gid_t)proc_getauxval(pid, AT_GID);
}

gid_t proc_getegid(pid_t pid)
{
	return (gid_t)proc_getauxval(pid, AT_EGID);
}

static char _proc_getstate(char *status_filebuf)
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

char proc_getstate(pid_t pid)
{
	char state = 0;
	char status_path[64] = { 0 };
	char *status_filebuf;
	
	snprintf(status_path, sizeof(status_path) - 1, "/proc/%d/status", pid);
	if ((status_filebuf = get_filebuf(status_path))) {
		state = _proc_getstate(status_filebuf);
		free(status_filebuf);
	}
	
	return state;
}

unsigned long proc_getplatform(pid_t pid)
{
	return proc_getauxval(pid, AT_PLATFORM);
}

size_t proc_getpath(pid_t pid, char **ppathbuf, size_t maxlen)
{
	size_t pathlen = 0;
	char exe_path[64] = { 0 };
	char *pathbuf;

	if (!maxlen) {
		maxlen = PATH_MAX;
		pathbuf = (char *)calloc(maxlen + 1, sizeof(char));
		if (!pathbuf)
			return pathlen;
	} else {
		pathbuf = *ppathbuf;
	}

	snprintf(exe_path, sizeof(exe_path) - 1, "/proc/%d/exe", pid);
	pathlen = (size_t)readlink(exe_path, pathbuf, maxlen);
	pathbuf[pathlen] = '\x00';

	if (pathbuf != *ppathbuf) {
		*ppathbuf = (char *)calloc(pathlen + 1, sizeof(char));
		if (*ppathbuf) {
			strncpy(*ppathbuf, pathbuf, pathlen);
			(*ppathbuf)[pathlen] = '\x00';
		} else {
			pathlen = 0;
		}

		free(pathbuf);
	}

	return pathlen;
}

static size_t _proc_getname(char *status_filebuf, char **pnamebuf,
			    size_t maxlen)
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
	if (!maxlen) {
		*pnamebuf = malloc(len + 1);
		if (!(*pnamebuf)) {
			len = 0;
			return len;
		}
	} else if (len > maxlen) {
		len = maxlen;
	}

	strncpy(*pnamebuf, ptr, len);
	(*pnamebuf)[len] = '\x00';

	return len;
}

size_t proc_getname(pid_t pid, char **pnamebuf, size_t maxlen)
{
	size_t namelen;
	char status_path[64] = { 0 };
	char *status_filebuf;
	
	snprintf(status_path, sizeof(status_path) - 1, "/proc/%d/status", pid);
	if ((status_filebuf = get_filebuf(status_path))) {
		namelen = _proc_getname(status_filebuf, pnamebuf, maxlen);
		free(status_filebuf);
	}
	
	return namelen;
}

int proc_enumenviron(pid_t pid,
		     int(*callback)(char *name, char *value, void *arg),
		     void *arg)
{
	char environ_path[64] = { 0 };
	char *environ_filebuf;
	char *ptr;

	snprintf(environ_path, sizeof(environ_path) - 1,
		 "/proc/%d/environ", pid);
	
	environ_filebuf = get_filebuf(environ_path);
	if (!environ_filebuf)
		return -1;

	for (ptr = environ_filebuf; (ptr = strchr(ptr, '=')); ptr = &ptr[1]) {
		char *name;
		char *value;
		char *pequals = ptr;

		while (ptr != environ_filebuf && ptr[-1] != '\x00')
			ptr = &ptr[-1];
		
		name = ptr;
		value = &pequals[1];
		*pequals = '\x00';

		if (callback(name, value, arg))
			break;

		ptr = &value[strlen(value)]; /* go to null terminator */
	}

	free(environ_filebuf);

	return 0;
}
