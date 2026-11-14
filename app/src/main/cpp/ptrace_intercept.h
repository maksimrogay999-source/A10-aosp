#pragma once
#include <atomic>
#include <sys/types.h>

// tracer_running: общий флаг активности единственного потока-монитора (сбрасывается при выходе).
void ptrace_syscall_intercept(pid_t pid, bool resumed_by_caller, std::atomic<bool>* tracer_running);