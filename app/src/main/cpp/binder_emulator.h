#pragma once
#include <cstdint>

bool binder_emulator_init();
void binder_emulator_shutdown();
void* binder_emulator_get_context();
int binder_emulator_get_fd();