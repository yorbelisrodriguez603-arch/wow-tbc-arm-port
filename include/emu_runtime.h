#pragma once
#include <unicorn/unicorn.h>
#include <cstddef>
#include <cstdint>
#include <string>

namespace emu {

struct RuntimeState {
    uc_engine* uc = nullptr;
    uint32_t next_alloc = 0x10000000u;
    uint32_t stack_base = 0;
    uint32_t stack_size = 8u * 1024u * 1024u;
    uint32_t esp_init = 0;
    uint32_t teb_addr = 0x7FFDF000u;
    uint32_t peb_addr = 0x7FFDE000u;
    uint32_t gdt_addr = 0;
    uint32_t tls_slots[64] = {0};
};

bool init_runtime(RuntimeState& st);
void destroy_runtime(RuntimeState& st);

uint32_t alloc_mem(RuntimeState& st, size_t bytes, uint32_t perms = UC_PROT_ALL);
uint32_t alloc_str(RuntimeState& st, const char* s);
uint32_t alloc_wstr(RuntimeState& st, const char* s);

uint32_t rd32(RuntimeState& st, uint64_t addr);
void wr32(RuntimeState& st, uint64_t addr, uint32_t val);
std::string rd_str(RuntimeState& st, uint64_t addr, size_t max_len = 256);

} // namespace emu
