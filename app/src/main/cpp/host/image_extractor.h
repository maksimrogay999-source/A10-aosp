#pragma once
#include <string>

bool image_extract_system(const std::string& systemImgPath, const std::string& outDir, std::string& err);
bool sparse_to_raw(const std::string& sparsePath, const std::string& rawPath, std::string& err);