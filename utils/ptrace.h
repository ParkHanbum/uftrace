#include <sys/ptrace.h>
#include <wait.h>
#include <time.h>
#include "mcount-arch.h"

void ptrace_attach(pid_t target);
void ptrace_detach(pid_t target);
#if !defined (ARCH_REGS)
  #include <sys/user.h>
  #if defined (__arm__) || defined (__aarch64__)
    #define ARCH_REGS struct user_regs
  #elif defined (__i386__) || defined (__x86_64)
    #define ARCH_REGS struct user_regs_struct
  #endif
#endif
void ptrace_getregs(pid_t target, ARCH_REGS *regs);
void ptrace_setregs(pid_t target, ARCH_REGS *regs);
void ptrace_write(int pid, unsigned long addr, void *vptr, int len);
