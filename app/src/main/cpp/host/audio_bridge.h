#pragma once
#include <cstdint>

bool audio_bridge_init();
void audio_bridge_shutdown();
void* audio_bridge_get_context();