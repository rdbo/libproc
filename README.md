# libproc
Linux API to abstract information from /proc (WIP)  

## Usage
- Include `libproc/libproc.h`
- Compile `libproc/libproc.c`

## Example
The following example shows how to get the name of the current process
through `struct proc`, which contains valuable information about the process,
such as command line, absolute path, ppid, tracer pid, state, environment 
variables and much more.  
For more examples, look at `tests/tests.c`  
```c
#include <libproc.h>

int main()
{
        struct proc proc;

        if (proc_openproc(getpid(), &proc)) {
                printf("Error!\n");
                return -1;
        }

        printf("Process name: %s\n", proc.name);

        proc_closeproc(&proc);

        return 0;
}
```

## Requirements
- Linux headers
- GCC/clang (may work on other compilers too)

## License
Read `LICENSE`
