#pragma once
#include <string>

bool aosp_unpack(const std::string& zipPath, const std::string& destDir);
std::string aosp_unpack_status();