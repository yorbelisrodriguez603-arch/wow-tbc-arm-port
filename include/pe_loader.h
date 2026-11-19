#pragma once
#include "emu_runtime.h"
#include <cstdint>
#include <string>
#include <vector>

namespace pe {

struct SectionInfo {
    std::string name;
    uint32_t va;
    uint32_t vsize;
    uint32_t raw_size;
    uint32_t raw_offset;
    uint32_t chars;
};

struct LoadedImage {
    bool valid = false;
    uint32_t image_base = 0x00400000u;
    uint32_t entry_point = 0;
    uint32_t size_of_image = 0;
    uint32_t imports_resolved = 0;
    uint32_t imports_stubbed = 0;
    std::vector<SectionInfo> sections;
};

LoadedImage load_pe32(emu::RuntimeState& st, const char* path);

} // namespace pe
