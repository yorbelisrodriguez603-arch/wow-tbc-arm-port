#include "pe_loader.h"
#include "shim_api.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace pe {

static uint32_t rva_to_file_offset(const std::vector<uint8_t>& raw,
                                   uint32_t pe_off,
                                   uint16_t num_sects,
                                   uint16_t opt_hdr_sz,
                                   uint32_t rva) {
    auto rd32 = [&](size_t off) -> uint32_t {
        uint32_t v = 0;
        if (off + 4 <= raw.size()) std::memcpy(&v, raw.data() + off, 4);
        return v;
    };
    uint32_t headers_size = rd32(pe_off + 0x18u + 0x3Cu);
    if (rva < headers_size && rva < raw.size()) return rva;

    size_t sect_table_off = pe_off + 0x18u + opt_hdr_sz;
    for (uint16_t i = 0; i < num_sects; ++i) {
        size_t s_off = sect_table_off + static_cast<size_t>(i) * 40u;
        if (s_off + 40u > raw.size()) break;
        uint32_t vsize = rd32(s_off + 0x08u);
        uint32_t va = rd32(s_off + 0x0Cu);
        uint32_t raw_sz = rd32(s_off + 0x10u);
        uint32_t raw_ptr = rd32(s_off + 0x14u);
        uint32_t span = vsize > raw_sz ? vsize : raw_sz;
        if (span == 0) span = raw_sz;
        if (rva >= va && rva < va + span) {
            uint32_t delta = rva - va;
            if (delta < raw_sz && static_cast<size_t>(raw_ptr) + delta < raw.size()) {
                return raw_ptr + delta;
            }
        }
    }
    return 0;
}

static std::string read_cstr_raw(const std::vector<uint8_t>& raw, size_t off, size_t max_len = 128) {
    std::string out;
    if (off >= raw.size()) return out;
    for (size_t i = 0; i < max_len && off + i < raw.size(); ++i) {
        char ch = static_cast<char>(raw[off + i]);
        if (ch == '\0') break;
        out.push_back(ch);
    }
    return out;
}

LoadedImage load_pe32(emu::RuntimeState& st, const char* path) {
    LoadedImage out;
    std::FILE* f = std::fopen(path, "rb");
    if (!f) {
        std::fprintf(stderr, "[pe] cannot open %s\n", path);
        return out;
    }

    std::fseek(f, 0, SEEK_END);
    long fsz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (fsz <= 0x100) {
        std::fclose(f);
        return out;
    }

    std::vector<uint8_t> raw(static_cast<size_t>(fsz));
    if (std::fread(raw.data(), 1, raw.size(), f) != raw.size()) {
        std::fclose(f);
        return out;
    }
    std::fclose(f);

    auto rd16 = [&](size_t off) -> uint16_t {
        uint16_t v = 0;
        if (off + 2 <= raw.size()) std::memcpy(&v, raw.data() + off, 2);
        return v;
    };
    auto rd32 = [&](size_t off) -> uint32_t {
        uint32_t v = 0;
        if (off + 4 <= raw.size()) std::memcpy(&v, raw.data() + off, 4);
        return v;
    };

    if (rd16(0) != 0x5A4Du) {
        std::fprintf(stderr, "[pe] invalid MZ header\n");
        return out;
    }

    uint32_t pe_off = rd32(0x3Cu);
    if (pe_off + 0x18u > raw.size() || rd32(pe_off) != 0x00004550u) {
        std::fprintf(stderr, "[pe] invalid PE header\n");
        return out;
    }

    uint16_t num_sects = rd16(pe_off + 0x06u);
    uint16_t opt_hdr_sz = rd16(pe_off + 0x14u);
    size_t opt_off = pe_off + 0x18u;

    uint32_t image_base = rd32(opt_off + 0x1Cu);
    uint32_t entry_rva = rd32(opt_off + 0x10u);
    uint32_t size_of_image = rd32(opt_off + 0x38u);
    uint32_t headers_size = rd32(opt_off + 0x3Cu);

    uint32_t map_sz = (size_of_image + 0xFFFu) & ~0xFFFu;
    if (uc_mem_map(st.uc, image_base, map_sz, UC_PROT_ALL) != UC_ERR_OK) {
        std::fprintf(stderr, "[pe] uc_mem_map failed at 0x%x (sz=0x%x)\n", image_base, map_sz);
        return out;
    }

    size_t hdr_copy = headers_size < raw.size() ? headers_size : raw.size();
    uc_mem_write(st.uc, image_base, raw.data(), hdr_copy);

    size_t sect_table_off = opt_off + opt_hdr_sz;
    for (uint16_t i = 0; i < num_sects; ++i) {
        size_t s_off = sect_table_off + static_cast<size_t>(i) * 40u;
        if (s_off + 40u > raw.size()) break;

        char sname[9] = {0};
        std::memcpy(sname, raw.data() + s_off, 8);
        uint32_t vsize = rd32(s_off + 0x08u);
        uint32_t va = rd32(s_off + 0x0Cu);
        uint32_t raw_sz = rd32(s_off + 0x10u);
        uint32_t raw_ptr = rd32(s_off + 0x14u);
        uint32_t chars = rd32(s_off + 0x24u);

        SectionInfo info{sname, va, vsize, raw_sz, raw_ptr, chars};
        out.sections.push_back(info);

        size_t to_copy = raw_sz;
        if (vsize > 0 && to_copy > vsize) to_copy = vsize;
        if (raw_ptr + to_copy > raw.size()) {
            to_copy = raw_ptr < raw.size() ? raw.size() - raw_ptr : 0;
        }
        if (to_copy > 0) {
            uc_mem_write(st.uc, static_cast<uint64_t>(image_base) + va, raw.data() + raw_ptr, to_copy);
        }
    }

    // Resolver Import Directory (DataDirectory[1] -> offset +0x60 en OptionalHeader PE32)
    uint32_t imp_rva = rd32(opt_off + 0x68u);
    uint32_t imp_size = rd32(opt_off + 0x6Cu);
    uint32_t resolved = 0, stubbed = 0;
    uint32_t dll_count = 0;

    if (imp_rva != 0 && imp_size != 0) {
        uint32_t imp_off = rva_to_file_offset(raw, pe_off, num_sects, opt_hdr_sz, imp_rva);
        for (size_t desc_off = imp_off; desc_off + 20u <= raw.size(); desc_off += 20u) {
            uint32_t ilt_rva = rd32(desc_off + 0x00u);
            uint32_t name_rva = rd32(desc_off + 0x0Cu);
            uint32_t iat_rva = rd32(desc_off + 0x10u);
            if (ilt_rva == 0 && name_rva == 0 && iat_rva == 0) break;

            uint32_t name_off = rva_to_file_offset(raw, pe_off, num_sects, opt_hdr_sz, name_rva);
            std::string dll_name = read_cstr_raw(raw, name_off, 128);
            uint32_t thunk_rva = ilt_rva ? ilt_rva : iat_rva;
            uint32_t thunk_off = rva_to_file_offset(raw, pe_off, num_sects, opt_hdr_sz, thunk_rva);
            uint32_t iat_va = image_base + iat_rva;
            dll_count++;

            uint32_t dll_imports = 0;
            for (size_t idx = 0; thunk_off + idx * 4u + 4u <= raw.size(); ++idx) {
                uint32_t t_val = rd32(thunk_off + idx * 4u);
                if (t_val == 0) break;

                char ord_buf[32] = {0};
                std::string func_name;
                if (t_val & 0x80000000u) {
                    uint16_t ord = static_cast<uint16_t>(t_val & 0xFFFFu);
                    std::snprintf(ord_buf, sizeof(ord_buf), "Ordinal_%u", (unsigned)ord);
                    func_name = ord_buf;
                } else {
                    uint32_t ibn_off = rva_to_file_offset(raw, pe_off, num_sects, opt_hdr_sz, t_val);
                    if (ibn_off + 2u < raw.size()) {
                        func_name = read_cstr_raw(raw, ibn_off + 2u, 128);
                    }
                }
                if (func_name.empty()) func_name = "UnknownImport";

                uint32_t sentinel = shims::register_or_get(dll_name.c_str(), func_name.c_str(), 4, nullptr, &stubbed);
                emu::wr32(st, iat_va + static_cast<uint32_t>(idx) * 4u, sentinel);
                resolved++;
                dll_imports++;
            }
            if (dll_count <= 20) {
                std::printf("[pe] DLL #%u: %s (%u imports)\n", dll_count, dll_name.c_str(), dll_imports);
            }
        }
    }

    out.image_base = image_base;
    out.entry_point = image_base + entry_rva;
    out.size_of_image = size_of_image;
    out.imports_resolved = resolved;
    out.imports_stubbed = stubbed;
    out.valid = true;

    std::printf("[pe] ImageBase=0x%x Entry=0x%x SizeOfImage=0x%x Sections=%zu Imports=%u (stubs=%u)\n",
                out.image_base, out.entry_point, out.size_of_image, out.sections.size(), resolved, stubbed);
    return out;
}

} // namespace pe
