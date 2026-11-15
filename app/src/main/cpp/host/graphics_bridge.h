#pragma once
#include <cstdint>

bool graphics_bridge_init();
void graphics_bridge_shutdown();
void* graphics_bridge_get_egl_context();
void* graphics_bridge_get_egl_display();
void* graphics_bridge_get_egl_surface();