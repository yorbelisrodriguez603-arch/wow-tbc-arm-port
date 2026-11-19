#pragma once
#include "emu_runtime.h"
#include <cstdint>
#include <string>

namespace shims {

using ShimFn = uint32_t (*)(emu::RuntimeState& st, const uint32_t* args);
constexpr uint32_t SENTINEL_BASE = 0x2000u;

struct ShimEntry {
    uint32_t sentinel;
    std::string dll;
    std::string func;
    int nargs;
    ShimFn fn;
};

void reset_registry();
uint32_t register_shim(const char* dll, const char* func, int nargs, ShimFn fn = nullptr);
uint32_t register_or_get(const char* dll, const char* func, int default_nargs, ShimFn fn = nullptr, uint32_t* stubbed_out = nullptr);
const ShimEntry* find_by_sentinel(uint32_t sentinel);
void register_default_shims(emu::RuntimeState& st);

} // namespace shims
