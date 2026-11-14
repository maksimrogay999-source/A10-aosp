#pragma once
#include <string>
#include <cstdint>

bool engine_kernel_init(const std::string& aospPath);
std::string engine_kernel_status();
void engine_kernel_shutdown();

// Перехват syscalls
extern "C" long engine_syscall_intercept(long syscallNumber, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6);