#pragma once
#include <string>
#include <sys/types.h>

bool loader_init(const std::string& rootfsDir);
bool loader_init(const std::string& rootfsDir, const std::string& nativeLibDir);
void loader_shutdown();
pid_t loader_start_init();
bool loader_guest_alive();
std::string loader_status();
std::string loader_last_error();