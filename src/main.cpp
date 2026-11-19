#include "emu_runtime.h"
#include "pe_loader.h"
#include "shim_api.h"
#include <cstdio>
#include <cstdlib>

namespace {

struct DiagCtx {
    emu::RuntimeState* st = nullptr;
    uint32_t img_base = 0x00400000u;
    uint32_t img_end = 0x00EC8000u;
    uint32_t rsrc_start = 0x00EBE000u;
    uint32_t rsrc_end = 0x00EC8000u;
    uint32_t prev_eip = 0;
    uint32_t prev_sz = 0;
    uint32_t last_jmp_from = 0;
    uint32_t last_jmp_to = 0;
    uint32_t call_count = 0;
    bool reported_rsrc = false;
};

static void on_intr(uc_engine* uc, uint32_t intno, void* user_data) {
    uint32_t eip = 0, esp = 0, ebp = 0;
    uc_reg_read(uc, UC_X86_REG_EIP, &eip);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uc_reg_read(uc, UC_X86_REG_EBP, &ebp);
    uint8_t b = 0;
    uc_mem_read(uc, eip, &b, 1);
    std::printf("[intr] intno=%u EIP=0x%x byte=0x%02x ESP=0x%x EBP=0x%x\n",
                intno, eip, b, esp, ebp);
    if (b == 0xCCu) {
        uint32_t next_eip = eip + 1u;
        uc_reg_write(uc, UC_X86_REG_EIP, &next_eip);
    } else {
        uc_emu_stop(uc);
    }
}

static void on_code(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data) {
    auto* ctx = static_cast<DiagCtx*>(user_data);
    uint32_t eip = static_cast<uint32_t>(addr);



    if (eip >= shims::SENTINEL_BASE && eip < 0x10000u) {
        const auto* entry = shims::find_by_sentinel(eip);
        uint32_t esp = 0, ret_addr = 0;
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        uc_mem_read(uc, esp, &ret_addr, 4);

        uint32_t args[8] = {0};
        if (entry && entry->nargs > 0) {
            int n = entry->nargs > 8 ? 8 : entry->nargs;
            uc_mem_read(uc, esp + 4u, args, static_cast<size_t>(n) * 4u);
        }

        uint32_t retval = 0;
        int nargs = entry ? entry->nargs : 0;
        const char* dll = entry ? entry->dll.c_str() : "UNKNOWN";
        const char* fn_name = entry ? entry->func.c_str() : "stub";
        if (ret_addr < 0x10000u || ctx->last_jmp_from == 0x41bb2bu) {
            uint32_t w[8] = {0};
            uc_mem_read(uc, esp, w, sizeof(w));
            uint32_t ebp_val = 0;
            uc_reg_read(uc, UC_X86_REG_EBP, &ebp_val);
            std::printf("  [BAD RET] call #%u %s!%s ret=0x%x ESP=0x%x EBP=0x%x lastJmp=0x%x->0x%x | +0:0x%x +4:0x%x +8:0x%x +12:0x%x\n",
                        ctx->call_count + 1, dll, fn_name, ret_addr, esp, ebp_val,
                        ctx->last_jmp_from, ctx->last_jmp_to, w[0], w[1], w[2], w[3]);
        }
        if (entry && entry->fn) {
            retval = entry->fn(*ctx->st, args);
        } else {
            static int unimpl_logs = 0;
            if (unimpl_logs < 20) {
                std::printf("  [unimpl stub] %s!%s ret=0x%x ESP=0x%x\n", dll, fn_name, ret_addr, esp);
                unimpl_logs++;
            }
        }

        ctx->call_count++;
        uint32_t new_esp = esp + 4u + static_cast<uint32_t>(nargs) * 4u;
        uc_reg_write(uc, UC_X86_REG_EAX, &retval);
        uc_reg_write(uc, UC_X86_REG_ESP, &new_esp);
        uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);

        if (ctx->call_count <= 180 || ctx->call_count % 100 == 0) {
            std::printf("[api #%u] %s!%s -> EAX=0x%x ret=0x%x ESP: 0x%x->0x%x\n",
                        ctx->call_count, dll, fn_name, retval, ret_addr, esp, new_esp);
        }
        ctx->prev_eip = ret_addr;
        ctx->prev_sz = 0;
        return;
    }

    if (eip < ctx->img_base || eip >= ctx->img_end) {
        static bool reported_out = false;
        if (!reported_out) {
            reported_out = true;
            uint32_t esp_v = 0, ebp_v = 0, eax_v = 0;
            uint32_t stk_v[6] = {0};
            uc_reg_read(uc, UC_X86_REG_ESP, &esp_v);
            uc_reg_read(uc, UC_X86_REG_EBP, &ebp_v);
            uc_reg_read(uc, UC_X86_REG_EAX, &eax_v);
            uc_mem_read(uc, esp_v, stk_v, sizeof(stk_v));
            std::printf("[OUT_OF_IMG] EIP=0x%x ESP=0x%x EBP=0x%x EAX=0x%x lastJmp=0x%x->0x%x calls=%u\n",
                        eip, esp_v, ebp_v, eax_v, ctx->last_jmp_from, ctx->last_jmp_to, ctx->call_count);
            std::printf("  stk: +0:0x%x +4:0x%x +8:0x%x +12:0x%x +16:0x%x +20:0x%x\n",
                        stk_v[0], stk_v[1], stk_v[2], stk_v[3], stk_v[4], stk_v[5]);
            uc_emu_stop(uc);
            return;
        }
    }

    if (ctx->prev_eip != 0 && eip != ctx->prev_eip + ctx->prev_sz) {
        ctx->last_jmp_from = ctx->prev_eip;
        ctx->last_jmp_to = eip;
    }

    if (!ctx->reported_rsrc && eip >= ctx->rsrc_start && eip < ctx->rsrc_end) {
        ctx->reported_rsrc = true;
        uint32_t esp = 0;
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        std::printf("[diag] entered .rsrc: jmp=0x%x->0x%x EIP=0x%x ESP=0x%x\n",
                    ctx->last_jmp_from, ctx->last_jmp_to, eip, esp);
    }

    ctx->prev_eip = eip;
    ctx->prev_sz = size;
}

static bool on_unmapped(uc_engine* uc, uc_mem_type type, uint64_t addr, int size, int64_t, void* user_data) {
    auto* ctx = static_cast<DiagCtx*>(user_data);
    uint64_t pg = addr & ~0xFFFull;
    uint32_t sz = static_cast<uint32_t>(((addr + size + 0xFFFu) & ~0xFFFu) - pg);
    if (sz == 0) sz = 0x1000u;
    if (uc_mem_map(uc, pg, sz, UC_PROT_ALL) == UC_ERR_OK) {
        std::printf("[mem] auto-mapped page 0x%llx (sz=0x%x, type=%d)\n",
                    (unsigned long long)pg, sz, (int)type);
        return true;
    }
    std::fprintf(stderr, "[mem] failed auto-mapping 0x%llx (lastJmp=0x%x->0x%x)\n",
                 (unsigned long long)addr, ctx->last_jmp_from, ctx->last_jmp_to);
    return false;
}

} // namespace

static void on_mem_write(uc_engine* uc, uc_mem_type, uint64_t addr, int size, int64_t value, void*) {
    if (size == 4 && (static_cast<uint32_t>(value) & 0xFFFFu) == 0x0a28u) {
        uint32_t eip = 0, esp = 0;
        uc_reg_read(uc, UC_X86_REG_EIP, &eip);
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        static int w_cnt = 0;
        if (w_cnt < 10) {
            std::printf("  [WATCH 0xa28] wrote 0x%llx at addr=0x%llx from EIP=0x%x ESP=0x%x\n",
                        (unsigned long long)value, (unsigned long long)addr, eip, esp);
            w_cnt++;
        }
    }
}

int main(int argc, char** argv) {
    const char* pe_path = (argc > 1)
        ? argv[1]
        : "/storage/FEF7-725E/WoW-Imito/Client/The Burning Crusade 2.4.3 (8606)/Wow.exe";

    emu::RuntimeState st{};
    if (!emu::init_runtime(st)) return 1;

    shims::reset_registry();
    shims::register_default_shims(st);

    pe::LoadedImage img = pe::load_pe32(st, pe_path);
    if (!img.valid) {
        emu::destroy_runtime(st);
        return 1;
    }

    DiagCtx diag;
    diag.st = &st;
    diag.img_base = img.image_base;
    diag.img_end = img.image_base + img.size_of_image;
    for (const auto& s : img.sections) {
        if (s.name == ".rsrc") {
            diag.rsrc_start = img.image_base + s.va;
            diag.rsrc_end = diag.rsrc_start + (s.vsize > s.raw_size ? s.vsize : s.raw_size);
        }
    }

    uc_hook h_code = 0, h_unmap = 0;
    uc_hook_add(st.uc, &h_code, UC_HOOK_CODE, (void*)on_code, &diag, 1, 0xFFFFFFFFULL);
    uc_hook_add(st.uc, &h_unmap, UC_HOOK_MEM_UNMAPPED, (void*)on_unmapped, &diag, 1, 0xFFFFFFFFULL);
    uc_hook h_w0a28;
    uc_hook_add(st.uc, &h_w0a28, UC_HOOK_MEM_WRITE, (void*)on_mem_write, &diag, 1, 0xFFFFFFFFULL);

    uint32_t esp_init = st.esp_init - 4u;
    emu::wr32(st, esp_init, 0x0000DEADu);
    uc_reg_write(st.uc, UC_X86_REG_ESP, &esp_init);
    uc_reg_write(st.uc, UC_X86_REG_EBP, &esp_init);
    uc_hook hh_intr = 0;
    uc_hook_add(st.uc, &hh_intr, UC_HOOK_INTR, (void*)on_intr, &st, 1, 0);

    uc_err err = uc_emu_start(st.uc, img.entry_point, 0x0000DEADu, 0, 1000000);

    uint32_t eip = 0, esp = 0, ebp = 0, eax = 0, ecx = 0, edx = 0, esi = 0, edi = 0;
    uc_reg_read(st.uc, UC_X86_REG_EIP, &eip);
    uc_reg_read(st.uc, UC_X86_REG_ESP, &esp);
    uc_reg_read(st.uc, UC_X86_REG_EBP, &ebp);
    uc_reg_read(st.uc, UC_X86_REG_EAX, &eax);
    uc_reg_read(st.uc, UC_X86_REG_ECX, &ecx);
    uc_reg_read(st.uc, UC_X86_REG_EDX, &edx);
    uc_reg_read(st.uc, UC_X86_REG_ESI, &esi);
    uc_reg_read(st.uc, UC_X86_REG_EDI, &edi);

    uint32_t stk[6] = {0};
    uc_mem_read(st.uc, esp, stk, sizeof(stk));

    unsigned char opb[16] = {0};
    uc_mem_read(st.uc, eip, opb, sizeof(opb));
    std::printf("[stop] err=%d (%s) EIP=0x%x ESP=0x%x EBP=0x%x lastJmp=0x%x->0x%x calls=%u\n",
                (int)err, uc_strerror(err), eip, esp, ebp, diag.last_jmp_from, diag.last_jmp_to, diag.call_count);
    std::printf("[stack@ESP] +0:0x%x +4:0x%x +8:0x%x +12:0x%x +16:0x%x +20:0x%x\n",
                stk[0], stk[1], stk[2], stk[3], stk[4], stk[5]);
    std::printf("[code@EIP] %02x %02x %02x %02x %02x %02x %02x %02x\n",
                opb[0], opb[1], opb[2], opb[3], opb[4], opb[5], opb[6], opb[7]);
    std::printf("[regs] EAX=0x%x ECX=0x%x EDX=0x%x ESI=0x%x EDI=0x%x\n", eax, ecx, edx, esi, edi);

    emu::destroy_runtime(st);
    return 0;
}
