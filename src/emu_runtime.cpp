#include "emu_runtime.h"
#include <cstdio>
#include <cstring>

namespace emu {

static uint64_t make_seg_desc(uint32_t base, uint32_t limit, uint8_t access, uint8_t flags) {
    uint64_t d = 0;
    d |= (limit & 0xFFFFull);
    d |= ((uint64_t)(base & 0xFFFFFFull)) << 16;
    d |= ((uint64_t)access) << 40;
    d |= ((uint64_t)((limit >> 16) & 0xFull)) << 48;
    d |= ((uint64_t)(flags & 0xFull)) << 52;
    d |= ((uint64_t)((base >> 24) & 0xFFull)) << 56;
    return d;
}

bool init_runtime(RuntimeState& st) {
    if (uc_open(UC_ARCH_X86, UC_MODE_32, &st.uc) != UC_ERR_OK) {
        std::fprintf(stderr, "[emu] uc_open failed\n");
        return false;
    }

    // Mapea zona baja para sentineles y estructuras auxiliares
    if (uc_mem_map(st.uc, 0x00000000u, 0x00010000u, UC_PROT_ALL) != UC_ERR_OK) {
        std::fprintf(stderr, "[emu] failed mapping low 64KB\n");
        return false;
    }

    // Stack de 8 MB en zona segura
    st.stack_base = alloc_mem(st, st.stack_size, UC_PROT_READ | UC_PROT_WRITE);
    if (!st.stack_base) {
        std::fprintf(stderr, "[emu] failed allocating stack\n");
        return false;
    }
    st.esp_init = (st.stack_base + st.stack_size - 0x1000u) & ~0xFu;

    // PEB y TEB
    if (uc_mem_map(st.uc, st.peb_addr, 0x1000u, UC_PROT_READ | UC_PROT_WRITE) != UC_ERR_OK ||
        uc_mem_map(st.uc, st.teb_addr, 0x1000u, UC_PROT_READ | UC_PROT_WRITE) != UC_ERR_OK) {
        std::fprintf(stderr, "[emu] failed mapping PEB/TEB\n");
        return false;
    }

    uint32_t ldr_addr = alloc_mem(st, 0x1000u);
    uint32_t heap_addr = alloc_mem(st, 0x10000u);
    uint32_t tls_slots_addr = alloc_mem(st, sizeof(st.tls_slots));

    wr32(st, st.peb_addr + 0x08u, 0x00400000u); // ImageBaseAddress
    wr32(st, st.peb_addr + 0x0Cu, ldr_addr);    // Ldr
    wr32(st, st.peb_addr + 0x18u, heap_addr);   // ProcessHeap

    wr32(st, st.teb_addr + 0x00u, 0xFFFFFFFFu);    // SEH chain end
    wr32(st, st.teb_addr + 0x04u, st.esp_init);     // StackBase
    wr32(st, st.teb_addr + 0x08u, st.stack_base);   // StackLimit
    wr32(st, st.teb_addr + 0x18u, st.teb_addr);     // Self (TEB linear)
    wr32(st, st.teb_addr + 0x2Cu, tls_slots_addr);  // TlsSlots pointer
    wr32(st, st.teb_addr + 0x30u, st.peb_addr);     // ProcessEnvironmentBlock

    // GDT: slot 3 = CS (0x1B), slot 4 = DS/ES/SS (0x23), slot 7 = FS/TEB (0x3B)
    st.gdt_addr = alloc_mem(st, 0x1000u);
    uint64_t desc3 = make_seg_desc(0, 0xFFFFFu, 0xFA, 0xC);
    uint64_t desc4 = make_seg_desc(0, 0xFFFFFu, 0xF2, 0xC);
    uint64_t desc7 = make_seg_desc(st.teb_addr, 0xFFFu, 0xF2, 0x4);
    uc_mem_write(st.uc, st.gdt_addr + 3u * 8u, &desc3, 8);
    uc_mem_write(st.uc, st.gdt_addr + 4u * 8u, &desc4, 8);
    uc_mem_write(st.uc, st.gdt_addr + 7u * 8u, &desc7, 8);

    struct {
        uint16_t limit;
        uint32_t base;
    } __attribute__((packed)) gdtr = { (uint16_t)(8u * 8u - 1u), st.gdt_addr };
    uc_reg_write(st.uc, UC_X86_REG_GDTR, &gdtr);

    uint16_t cs_sel = 0x1Bu, ds_sel = 0x23u, fs_sel = 0x3Bu;
    uc_reg_write(st.uc, UC_X86_REG_CS, &cs_sel);
    uc_reg_write(st.uc, UC_X86_REG_DS, &ds_sel);
    uc_reg_write(st.uc, UC_X86_REG_ES, &ds_sel);
    uc_reg_write(st.uc, UC_X86_REG_SS, &ds_sel);
    uc_reg_write(st.uc, UC_X86_REG_FS, &fs_sel);

    uint32_t esp = st.esp_init;
    uint32_t ebp = st.esp_init;
    uint32_t eflags = 0x202u;
    uc_reg_write(st.uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(st.uc, UC_X86_REG_EBP, &ebp);
    uc_reg_write(st.uc, UC_X86_REG_EFLAGS, &eflags);

    return true;
}

void destroy_runtime(RuntimeState& st) {
    if (st.uc) {
        uc_close(st.uc);
        st.uc = nullptr;
    }
}

uint32_t alloc_mem(RuntimeState& st, size_t bytes, uint32_t perms) {
    if (bytes == 0) bytes = 0x1000u;
    uint32_t aligned = (st.next_alloc + 0xFFFu) & ~0xFFFu;
    uint32_t sz = (uint32_t)((bytes + 0xFFFu) & ~0xFFFu);
    if (uc_mem_map(st.uc, aligned, sz, perms) != UC_ERR_OK) {
        return 0;
    }
    st.next_alloc = aligned + sz + 0x1000u;
    return aligned;
}

uint32_t alloc_str(RuntimeState& st, const char* s) {
    if (!s) s = "";
    size_t n = std::strlen(s) + 1;
    uint32_t addr = alloc_mem(st, n);
    if (addr) uc_mem_write(st.uc, addr, s, n);
    return addr;
}

uint32_t alloc_wstr(RuntimeState& st, const char* s) {
    if (!s) s = "";
    size_t len = std::strlen(s);
    uint32_t addr = alloc_mem(st, (len + 1) * 2u);
    if (addr) {
        for (size_t i = 0; i <= len; ++i) {
            uint16_t ch = (i < len) ? (uint8_t)s[i] : 0;
            uc_mem_write(st.uc, addr + i * 2u, &ch, 2);
        }
    }
    return addr;
}

uint32_t rd32(RuntimeState& st, uint64_t addr) {
    uint32_t v = 0;
    uc_mem_read(st.uc, addr, &v, sizeof(v));
    return v;
}

void wr32(RuntimeState& st, uint64_t addr, uint32_t val) {
    uc_mem_write(st.uc, addr, &val, sizeof(val));
}

std::string rd_str(RuntimeState& st, uint64_t addr, size_t max_len) {
    std::string out;
    if (!addr) return out;
    out.reserve(max_len);
    for (size_t i = 0; i < max_len; ++i) {
        char ch = 0;
        if (uc_mem_read(st.uc, addr + i, &ch, 1) != UC_ERR_OK || ch == '\0') break;
        out.push_back(ch);
    }
    return out;
}

} // namespace emu
