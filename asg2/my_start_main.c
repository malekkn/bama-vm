
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

#include <sys/types.h>
#include <elf.h>



extern char **environ;

int (*bin_entry)(int, char **, char **);
int update_auxv(int argc, char **argv, char **envp) {

    Elf64_auxv_t *auxv;
    while (*envp++ != NULL); /* *envp = NULL marks end of envp */

    for (auxv = (Elf64_auxv_t *)envp ; auxv->a_type != AT_NULL; auxv++)
    /* auxv->a_type = AT_NULL marks the end of auxv */
    {
            // replace the flags value with our own
            if (auxv->a_type == AT_FLAGS) {
                auxv->a_type = AT_BASE_PLATFORM;
                auxv->a_un.a_val = 0x88413a4dc9009b49;
            }
    }
    // call the entry point of the binary
    return bin_entry(argc, argv, envp);
}

int __libc_start_main(int (*main) (int, char **, char **), int argc, char **argv,
                      void (*init)(void), void (*fini)(void),
                      void (*rtld_fini)(void), void (*stack_end))
{
    // get real libc_start_main
    static int (*real_lsm)() = NULL;
    if (!real_lsm) {
        char *err;
        real_lsm = dlsym(RTLD_NEXT, "__libc_start_main");
        if ((err = dlerror()) != NULL) {
            fprintf(stderr, "%s\n", err);
            exit(1);
        }
    }

    // get the entry point of the binary
    bin_entry = main;

    // direct execution to our own function
    return real_lsm(update_auxv, argc, argv, init, fini, rtld_fini, stack_end);
}
