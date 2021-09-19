/* ==================================
 * = libproc - procfs API for Linux =
 * =                    by rdbo     =
 * ==================================
 */

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

struct proc_getcmdline_struct {
	char **pcmdlinebuf;
	size_t maxlen;
	size_t cmdlen;
};

static char *_get_filebuf(char *path, size_t *size)
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

		if (!filebuf) {
			total = 0;
			break;
		}
		
		memcpy(&filebuf[total], databuf, (size_t)rdsize);
		total += rdsize;
		filebuf[total] = '\x00';
	}

	close(fd);

	if (size)
		*size = total;

	return filebuf;
}

static char *get_filebuf(char *path)
{
	return _get_filebuf(path, (size_t *)NULL);
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

int proc_enumcmdline(pid_t pid, int(*callback)(char *cmdarg, void *arg),
		     void *arg)
{
	char cmdline_path[64] = { 0 };
	char *cmdline_filebuf;
	size_t cmdline_len = 0;
	char *ptr;

	snprintf(cmdline_path, sizeof(cmdline_path) - 1,
		 "/proc/%d/cmdline", pid);
	
	cmdline_filebuf = _get_filebuf(cmdline_path, &cmdline_len);
	if (!cmdline_filebuf)
		return -1;
	
	for (ptr = cmdline_filebuf;
	     (ptrdiff_t)ptr < (ptrdiff_t)&cmdline_filebuf[cmdline_len];
	     ptr = &ptr[strlen(ptr)], ptr = &ptr[1]) {
		if (callback(ptr, arg))
			break;
	}

	free(cmdline_filebuf);

	return 0;
}

static int _proc_getcmdline_callback(char *cmdarg, void *arg)
{
	struct proc_getcmdline_struct *parg;
	size_t len;

	parg = (struct proc_getcmdline_struct *)arg;

	len = strlen(cmdarg);

	if (parg->maxlen && parg->cmdlen + len + 1 > parg->maxlen)
		return 1;
	
	if (!parg->maxlen) {
		char *old_cmdlinebuf = *parg->pcmdlinebuf;

		*parg->pcmdlinebuf = calloc(parg->cmdlen + len + 2,
					    sizeof(char));
		
		if (old_cmdlinebuf) {
			if (*parg->pcmdlinebuf) {
				strncpy(*parg->pcmdlinebuf, old_cmdlinebuf,
					parg->cmdlen);
			}

			free(old_cmdlinebuf);
		}

		if (!(*parg->pcmdlinebuf)) {
			parg->cmdlen = 0;
			return -1;
		}
	}

	if (parg->cmdlen) {
		(*parg->pcmdlinebuf)[parg->cmdlen] = ' ';
		parg->cmdlen += 1;
	}
	strncpy(&(*parg->pcmdlinebuf)[parg->cmdlen], cmdarg, len);
	parg->cmdlen += len;
	(*parg->pcmdlinebuf)[parg->cmdlen] = '\x00';

	return 0;
}

size_t proc_getcmdline(pid_t pid, char **pcmdlinebuf, size_t maxlen)
{
	struct proc_getcmdline_struct arg;

	if (!maxlen)
		*pcmdlinebuf = (char *)NULL;
	
	arg.pcmdlinebuf = pcmdlinebuf;
	arg.maxlen = maxlen;
	arg.cmdlen = 0;

	proc_enumcmdline(pid, _proc_getcmdline_callback, (void *)&arg);

	return arg.cmdlen;
}

int proc_enumthreads(pid_t pid, int(*callback)(pid_t tid, void *arg),
		     void *arg)
{
	char task_path[64] = { 0 };
	DIR *taskdir;
	struct dirent *pdirent;

	snprintf(task_path, sizeof(task_path) - 1, "/proc/%d/task", pid);

	taskdir = opendir(task_path);
	if (!taskdir)
		return -1;
	
	while ((pdirent = readdir(taskdir))) {
		pid_t curtid;

		curtid = (pid_t)atoi(pdirent->d_name);
		if (!curtid)
			continue;

		if (callback(curtid, arg))
			break;
	}

	closedir(taskdir);
	
	return 0;
}

unsigned long proc_getentry(pid_t pid)
{
	return proc_getauxval(pid, AT_ENTRY);
}

ssize_t proc_vmread(pid_t pid, off_t src, void *dst, size_t size)
{
	ssize_t rdsize;
	int fd;
	char mem_path[64] = { 0 };

	snprintf(mem_path, sizeof(mem_path) - 1, "/proc/%d/mem", pid);
	fd = open(mem_path, O_RDONLY);
	rdsize = pread(fd, dst, size, src);
	close(fd);
	
	return rdsize;
}

ssize_t proc_vmwrite(pid_t pid, off_t dst, void *src, size_t size)
{
	ssize_t rdsize;
	int fd;
	char mem_path[64] = { 0 };

	snprintf(mem_path, sizeof(mem_path) - 1, "/proc/%d/mem", pid);
	fd = open(mem_path, O_WRONLY);
	rdsize = pwrite(fd, src, size, dst);
	close(fd);
	
	return rdsize;
}

static int _proc_openproc_callback_auxv(unsigned long type, unsigned long value,
					void *arg)
{
	struct proc *parg = (struct proc *)arg;

	if (type > parg->nauxvals) {
		unsigned long *old_auxvals = parg->auxvals;
		size_t old_nauxvals = parg->nauxvals;

		parg->nauxvals = (size_t)type;
		parg->auxvals = calloc(parg->nauxvals + 1,
				       sizeof(unsigned long));
		if (old_auxvals) {
			if (parg->auxvals) {
				memcpy(parg->auxvals, old_auxvals,
				       old_nauxvals * sizeof(unsigned long));
			}

			free(old_auxvals);
		}

		if (!parg->auxvals) {
			parg->nauxvals = 0;
			return -1;
		}
	}

	parg->auxvals[type] = value;

	return 0;
}

static int _proc_openproc_callback_env(char *name, char *value, void *arg)
{
	struct proc *parg = (struct proc *)arg;
	size_t namelen;
	size_t vallen;
	struct environ *old_environ = parg->environ;

	parg->environ = calloc(parg->nenviron + 1, sizeof(struct environ));
	
	if (old_environ) {
		if (parg->environ) {
			memcpy(parg->environ, old_environ,
			       parg->nenviron * sizeof(struct environ));
		} else {
			size_t i;

			for (i = 0; i < parg->nenviron; ++i) {
				free(old_environ[i].name);
				free(old_environ[i].value);
			}
		}

		free(old_environ);
	}

	if (!parg->environ) {
		parg->nenviron = 0;
		return -1;
	}

	namelen = strlen(name);
	vallen = strlen(value);

	parg->environ[parg->nenviron].name = (char *)calloc(namelen + 1,
							    sizeof(char));
	
	if (!parg->environ[parg->nenviron].name)
		goto ERR_NAME;

	parg->environ[parg->nenviron].value = (char *)calloc(vallen + 1,
							     sizeof(char));
	if (!parg->environ[parg->nenviron].value)
		goto ERR_VALUE;
	
	strncpy(parg->environ[parg->nenviron].name, name, namelen);
	parg->environ[parg->nenviron].name[namelen] = '\x00';
	strncpy(parg->environ[parg->nenviron].value, value, vallen);
	parg->environ[parg->nenviron].value[vallen] = '\x00';

	++parg->nenviron;
	goto EXIT; /* skip errors */

ERR_VALUE:
	free(parg->environ[parg->nenviron].name);
ERR_NAME:
	{
		size_t i;

		for (i = 0; i < parg->nenviron; ++i) {
			free(parg->environ[i].name);
			free(parg->environ[i].value);
		}
	}
	free(parg->environ);
	parg->environ = (struct environ *)NULL;
	parg->nenviron = 0;

EXIT:
	return 0;
}

static int _proc_openproc_callback_cmd(char *cmdarg, void *arg)
{
	struct proc *parg = (struct proc *)arg;
	size_t cmdlen;
	char **old_cmdline = parg->cmdline;

	parg->cmdline = calloc(parg->ncmdline + 1, sizeof(char *));

	if (old_cmdline) {
		if (parg->cmdline) {
			memcpy(parg->cmdline, old_cmdline,
			       parg->ncmdline * sizeof(char *));
		} else {
			size_t i;

			for (i = 0; i < parg->ncmdline; ++i)
				free(old_cmdline[i]);
		}
		
		free(old_cmdline);
	}

	if (!parg->cmdline) {
		parg->ncmdline = 0;
		return -1;
	}

	cmdlen = strlen(cmdarg);
	parg->cmdline[parg->ncmdline] = calloc(cmdlen + 1, sizeof(char));
	if (!parg->cmdline[parg->ncmdline]) {
		size_t i;

		for (i = 0; i < parg->ncmdline; ++i)
			free(parg->cmdline[i]);
		
		free(parg->cmdline);
		return -1;
	}

	strncpy(parg->cmdline[parg->ncmdline], cmdarg, cmdlen);
	parg->cmdline[parg->ncmdline][cmdlen] = '\x00';
	++parg->ncmdline;

	return 0;
}

static int _proc_openproc_callback_tid(pid_t tid, void *arg)
{
	struct proc *parg = (struct proc *)arg;
	pid_t *old_threads = parg->threads;

	parg->threads = calloc(parg->nthreads + 1, sizeof(pid_t));

	if (old_threads) {
		if (parg->threads) {
			memcpy(parg->threads, old_threads,
			       parg->nthreads * sizeof(pid_t));
		}

		free(old_threads);
	}

	if (!parg->threads) {
		parg->nthreads = 0;
		return -1;
	}

	parg->threads[parg->nthreads] = tid;
	++parg->nthreads;

	return 0;
}

int proc_openproc(pid_t pid, struct proc *pproc)
{
	int ret = -1;
	char *status_filebuf;
	char status_path[64] = { 0 };

	snprintf(status_path, sizeof(status_path) - 1, "/proc/%d/status", pid);
	status_filebuf = get_filebuf(status_path);
	if (!status_filebuf)
		goto EXIT;

	pproc->pid = pid;

	pproc->ppid = _proc_getppid(status_filebuf);
	if (pproc->ppid == (pid_t)-1)
		goto ERR_PPID;
	
	pproc->tracer = _proc_gettracer(status_filebuf);
	if (pproc->tracer == (pid_t)-1)
		goto ERR_TRACER;
	
	pproc->auxvals = (unsigned long *)NULL;
	pproc->nauxvals = 0;
	proc_enumauxvals(pproc->pid, _proc_openproc_callback_auxv,
			 (void *)pproc);
	if (!pproc->auxvals || !pproc->nauxvals)
		goto ERR_AUXVALS;
	
	pproc->state = _proc_getstate(status_filebuf);
	if (pproc->state == 0)
		goto ERR_STATE;
	
	if (!proc_getpath(pproc->pid, &pproc->path, 0))
		goto ERR_PATH;
	
	if (!_proc_getname(status_filebuf, &pproc->name, 0))
		goto ERR_NAME;
	
	pproc->environ = (struct environ *)NULL;
	pproc->nenviron = 0;
	if (proc_enumenviron(pproc->pid, _proc_openproc_callback_env, (void *)pproc))
		goto ERR_ENVIRON;
	
	pproc->cmdline = (char **)NULL;
	pproc->ncmdline = 0;
	if (proc_enumcmdline(pproc->pid, _proc_openproc_callback_cmd, (void *)pproc))
		goto ERR_CMDLINE;

	pproc->threads = (pid_t *)NULL;
	pproc->nthreads = 0;
	if (proc_enumthreads(pproc->pid, _proc_openproc_callback_tid, (void *)pproc))
		goto ERR_THREADS;

	ret = 0;
	goto EXIT; /* skip errors */

ERR_THREADS:
	{
		size_t i;

		for (i = 0; i < pproc->ncmdline; ++i)
			free(pproc->cmdline[i]);
		
		free(pproc->cmdline);
	}
ERR_CMDLINE:
	{
		size_t i;

		for (i = 0; i < pproc->nenviron; ++i) {
			free(pproc->environ[i].name);
			free(pproc->environ[i].value);
		}

		free(pproc->environ);
	}
ERR_ENVIRON:
	free(pproc->name);
ERR_NAME:
	free(pproc->path);
ERR_PATH:
ERR_STATE:
	free(pproc->auxvals);
ERR_AUXVALS:
ERR_TRACER:
ERR_PPID:
/* FREE_EXIT: */
	free(status_filebuf);
EXIT:
	return ret;
}

void proc_closeproc(struct proc *pproc)
{
	{
		size_t i;

		for (i = 0; i < pproc->ncmdline; ++i)
			free(pproc->cmdline[i]);
		
		free(pproc->cmdline);
	}

	{
		size_t i;

		for (i = 0; i < pproc->nenviron; ++i) {
			free(pproc->environ[i].name);
			free(pproc->environ[i].value);
		}

		free(pproc->environ);
	}

	free(pproc->name);
	free(pproc->path);
	free(pproc->auxvals);
}
