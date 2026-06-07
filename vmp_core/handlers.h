#pragma once
// ============================================================================
// Handler Implementations - Direct Threading Pattern
// ============================================================================
// In VMProtect 2, each handler is native x64 code that:
//   1. Performs its operation (stack/register/memory/arithmetic)
//   2. Ends with calc_jmp code (direct threading - no central dispatch loop)
//
// The calc_jmp code at the end of each handler:
//   movzx eax, byte [rsi]    ; read next opcode
//   lea   rsi, [rsi+1]       ; advance VIP
//   mov   rdx, [r12+rax*8]   ; fetch handler entry
//   xor   rdx, <key>         ; decrypt handler entry
//   xor   rbx, rax           ; update rolling key
//   jmp   rdx                ; dispatch to next handler
//
// This means there is NO central dispatch loop in real VMP.
// Each handler directly jumps to the next one.
//
// For our simulation, each handler calls calc_jmp() at the end.
// ============================================================================

#include "vmp_core.h"

namespace vmp {

    // ============================================================================
    // Helper: read operand from VIP (inline in each handler for realism)
    // ============================================================================
    // In real VMP, operand reading is done with MOVZX/MOV instructions
    // from [RSI] with various sizes, followed by transform decryption.

    // ============================================================================
    // Register all handlers into the table
    // ============================================================================
    inline void register_all_handlers(HandlerTable& table) {

        // ========================================================================
        // HALT - Stop VM execution
        // In real VMP: restores context via vm_exit
        // ========================================================================
        table.register_handler(OP_HALT, [](
            VMEngine& engine, VMContext& ctx) {
                // vm_exit: stop VM, restore native context
                engine.vm_exit(ctx);
                // No calc_jmp - VM execution ends here
            });

        // ========================================================================
        // NOP
        // ========================================================================
        table.register_handler(OP_NOP, [](
            VMEngine& engine, VMContext& ctx) {
                // End with calc_jmp (direct threading)
                calc_jmp(engine, ctx);
            });

        // ========================================================================
        // PUSH IMM variants
        // In real VMP: MOVZX RAX, byte/word/dword [RSI]; transforms; push
        // Each PUSH variant has its own handler with unique transform chain
        // ========================================================================

        // PUSH IMM8 - variant 1 (standard)
        table.register_handler(OP_PUSH_IMM8, [](
            VMEngine& engine, VMContext& ctx) {
                BytecodeReader reader(ctx, *engine.operand_chain());
                uint64_t imm = static_cast<int64_t>(static_cast<int8_t>(reader.read_u8()));
                ctx.push64(imm);
                calc_jmp(engine, ctx);
            });

        // PUSH IMM16
        table.register_handler(OP_PUSH_IMM16, [](
            VMEngine& engine, VMContext& ctx) {
                BytecodeReader reader(ctx, *engine.operand_chain());
                uint64_t imm = static_cast<int64_t>(static_cast<int16_t>(reader.read_u16()));
                ctx.push64(imm);
                calc_jmp(engine, ctx);
            });

        // PUSH IMM32
        table.register_handler(OP_PUSH_IMM32, [](
            VMEngine& engine, VMContext& ctx) {
                BytecodeReader reader(ctx, *engine.operand_chain());
                uint64_t imm = static_cast<int64_t>(static_cast<int32_t>(reader.read_u32()));
                ctx.push64(imm);
                calc_jmp(engine, ctx);
            });

        // PUSH IMM64 - has two handler variants (demonstrates polymorphism)
        // Variant 1: standard read + push
        table.register_handler(OP_PUSH_IMM64, [](
            VMEngine& engine, VMContext& ctx) {
                BytecodeReader reader(ctx, *engine.operand_chain());
                uint64_t imm = reader.read_u64();
                ctx.push64(imm);
                calc_jmp(engine, ctx);
            });
        // Variant 2: same logic, different native code (in real VMP, different
        // register allocation, different instruction ordering, different junk code)
        table.register_handler(OP_PUSH_IMM64, [](
            VMEngine& engine, VMContext& ctx) {
                BytecodeReader reader(ctx, *engine.operand_chain());
                uint64_t imm = reader.read_u64();
                ctx.vsp -= 8;
                *reinterpret_cast<uint64_t*>(ctx.vsp) = imm;
                calc_jmp(engine, ctx);
            });

        // ========================================================================
        // POP
        // ========================================================================
        table.register_handler(OP_POP, [](
            VMEngine& engine, VMContext& ctx) {
                ctx.pop64();
                calc_jmp(engine, ctx);
            });

        // DUP
        table.register_handler(OP_DUP, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t val = ctx.read_vsp<uint64_t>(0);
                ctx.push64(val);
                calc_jmp(engine, ctx);
            });

        // ========================================================================
        // LREG - Load scratch register onto stack
        // In real VMP: MOV RAX, [RDI+offset]; PUSH RAX
        // ========================================================================
        table.register_handler(OP_LREG, [](
            VMEngine& engine, VMContext& ctx) {
                BytecodeReader reader(ctx, *engine.operand_chain());
                uint8_t idx = reader.read_u8();
                ctx.push64(ctx.regs[idx]);
                calc_jmp(engine, ctx);
            });

        // SREG - Store into scratch register
        // In real VMP: POP RAX; MOV [RDI+offset], RAX
        table.register_handler(OP_SREG, [](
            VMEngine& engine, VMContext& ctx) {
                BytecodeReader reader(ctx, *engine.operand_chain());
                uint8_t idx = reader.read_u8();
                ctx.regs[idx] = ctx.pop64();
                calc_jmp(engine, ctx);
            });

        // LCONST - Load constant into scratch register
        table.register_handler(OP_LCONST, [](
            VMEngine& engine, VMContext& ctx) {
                BytecodeReader reader(ctx, *engine.operand_chain());
                uint8_t idx = reader.read_u8();
                uint64_t val = reader.read_u64();
                ctx.regs[idx] = val;
                calc_jmp(engine, ctx);
            });

        // ========================================================================
        // Memory operations
        // In real VMP: POP RAX (address); MOVZX/POP value; PUSH result
        // ========================================================================

        table.register_handler(OP_LD8, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t addr = ctx.pop64();
                ctx.push64(*reinterpret_cast<const uint8_t*>(addr));
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_LD16, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t addr = ctx.pop64();
                ctx.push64(*reinterpret_cast<const uint16_t*>(addr));
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_LD32, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t addr = ctx.pop64();
                ctx.push64(*reinterpret_cast<const uint32_t*>(addr));
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_LD64, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t addr = ctx.pop64();
                ctx.push64(*reinterpret_cast<const uint64_t*>(addr));
                calc_jmp(engine, ctx);
            });

        table.register_handler(OP_ST8, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t val = ctx.pop64(); uint64_t addr = ctx.pop64();
                *reinterpret_cast<uint8_t*>(addr) = (uint8_t)val;
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_ST16, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t val = ctx.pop64(); uint64_t addr = ctx.pop64();
                *reinterpret_cast<uint16_t*>(addr) = (uint16_t)val;
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_ST32, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t val = ctx.pop64(); uint64_t addr = ctx.pop64();
                *reinterpret_cast<uint32_t*>(addr) = (uint32_t)val;
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_ST64, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t val = ctx.pop64(); uint64_t addr = ctx.pop64();
                *reinterpret_cast<uint64_t*>(addr) = val;
                calc_jmp(engine, ctx);
            });

        // ========================================================================
        // Arithmetic - push result + RFLAGS
        // In real VMP: POP RAX, POP RCX, compute, PUSH result, PUSHF
        // Each arithmetic op can have multiple handler variants.
        // ========================================================================

        // ADD - two variants (demonstrates handler polymorphism)
        table.register_handler(OP_ADD, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t b = ctx.pop64(), a = ctx.pop64();
                uint64_t result = a + b;
                ctx.push64(result);
                ctx.push64(compute_flags(a, b, result, false).raw);
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_ADD, [](
            VMEngine& engine, VMContext& ctx) {
                // Variant 2: uses VSP-relative access instead of pop/push
                uint64_t b = ctx.read_vsp<uint64_t>(0);
                uint64_t a = ctx.read_vsp<uint64_t>(8);
                ctx.vsp += 8; // pop one, overwrite the other
                uint64_t result = a + b;
                *reinterpret_cast<uint64_t*>(ctx.vsp) = result;
                ctx.push64(compute_flags(a, b, result, false).raw);
                calc_jmp(engine, ctx);
            });

        table.register_handler(OP_SUB, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t b = ctx.pop64(), a = ctx.pop64();
                uint64_t result = a - b;
                ctx.push64(result);
                ctx.push64(compute_flags(a, b, result, true).raw);
                calc_jmp(engine, ctx);
            });

        table.register_handler(OP_MUL, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t b = ctx.pop64(), a = ctx.pop64();
                uint64_t result = a * b;
                VFlags f{}; f.raw = 0x2;
                ctx.push64(result);
                ctx.push64(f.raw);
                calc_jmp(engine, ctx);
            });

        table.register_handler(OP_AND, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t b = ctx.pop64(), a = ctx.pop64();
                uint64_t result = a & b;
                VFlags f{}; f.raw = 0x2;
                f.ZF = (result == 0); f.SF = (result & 0x8000000000000000ULL) != 0;
                ctx.push64(result); ctx.push64(f.raw);
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_OR, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t b = ctx.pop64(), a = ctx.pop64();
                uint64_t result = a | b;
                VFlags f{}; f.raw = 0x2;
                f.ZF = (result == 0); f.SF = (result & 0x8000000000000000ULL) != 0;
                ctx.push64(result); ctx.push64(f.raw);
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_XOR, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t b = ctx.pop64(), a = ctx.pop64();
                uint64_t result = a ^ b;
                VFlags f{}; f.raw = 0x2;
                f.ZF = (result == 0); f.SF = (result & 0x8000000000000000ULL) != 0;
                ctx.push64(result); ctx.push64(f.raw);
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_NOT, [](
            VMEngine& engine, VMContext& ctx) {
                ctx.push64(~ctx.pop64());
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_NEG, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t a = ctx.pop64();
                uint64_t result = (uint64_t)(-(int64_t)a);
                VFlags f{}; f.raw = 0x2;
                f.CF = (a != 0); f.ZF = (result == 0);
                f.SF = (result & 0x8000000000000000ULL) != 0;
                ctx.push64(result); ctx.push64(f.raw);
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_SHL, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t cnt = ctx.pop64(), a = ctx.pop64();
                uint8_t c = cnt & 63;
                uint64_t result = c < 64 ? (a << c) : 0;
                VFlags f{}; f.raw = 0x2;
                f.ZF = (result == 0); f.SF = (result & 0x8000000000000000ULL) != 0;
                if (c > 0 && c <= 64) f.CF = (a >> (64 - c)) & 1;
                ctx.push64(result); ctx.push64(f.raw);
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_SHR, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t cnt = ctx.pop64(), a = ctx.pop64();
                uint8_t c = cnt & 63;
                uint64_t result = c < 64 ? (a >> c) : 0;
                VFlags f{}; f.raw = 0x2;
                f.ZF = (result == 0); f.SF = (result & 0x8000000000000000ULL) != 0;
                if (c > 0 && c <= 64) f.CF = (a >> (c - 1)) & 1;
                ctx.push64(result); ctx.push64(f.raw);
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_INC, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t a = ctx.pop64(), result = a + 1;
                VFlags f{}; f.raw = 0x2;
                f.ZF = (result == 0); f.SF = (result & 0x8000000000000000ULL) != 0;
                f.OF = (a == 0x7FFFFFFFFFFFFFFFULL);
                ctx.push64(result); ctx.push64(f.raw);
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_DEC, [](
            VMEngine& engine, VMContext& ctx) {
                uint64_t a = ctx.pop64(), result = a - 1;
                VFlags f{}; f.raw = 0x2;
                f.ZF = (result == 0); f.SF = (result & 0x8000000000000000ULL) != 0;
                f.OF = (a == 0x8000000000000000ULL);
                ctx.push64(result); ctx.push64(f.raw);
                calc_jmp(engine, ctx);
            });

        // ========================================================================
        // PUSHF / POPF
        // ========================================================================
        table.register_handler(OP_PUSHF, [](
            VMEngine& engine, VMContext& ctx) {
                ctx.push64(ctx.rflags);
                calc_jmp(engine, ctx);
            });
        table.register_handler(OP_POPF, [](
            VMEngine& engine, VMContext& ctx) {
                ctx.rflags = ctx.pop64();
                calc_jmp(engine, ctx);
            });

        // ========================================================================
        // Control Flow
        // ========================================================================

        // JMP - unconditional relative jump
        table.register_handler(OP_JMP, [](
            VMEngine& engine, VMContext& ctx) {
                BytecodeReader reader(ctx, *engine.operand_chain());
                int32_t offset = (int32_t)reader.read_u32();
                ctx.vip += offset;
                calc_jmp(engine, ctx);
            });

        // JCC - conditional jump
        table.register_handler(OP_JCC, [](
            VMEngine& engine, VMContext& ctx) {
                BytecodeReader reader(ctx, *engine.operand_chain());
                uint8_t cc = reader.read_u8();
                int32_t offset = (int32_t)reader.read_u32();

                VFlags f; f.raw = ctx.rflags;
                bool take = false;
                switch (cc) {
                case CC_O:   take = f.OF; break;
                case CC_NO:  take = !f.OF; break;
                case CC_B:   take = f.CF; break;
                case CC_NB:  take = !f.CF; break;
                case CC_Z:   take = f.ZF; break;
                case CC_NZ:  take = !f.ZF; break;
                case CC_BE:  take = f.CF || f.ZF; break;
                case CC_NBE: take = !f.CF && !f.ZF; break;
                case CC_S:   take = f.SF; break;
                case CC_NS:  take = !f.SF; break;
                case CC_L:   take = f.SF != f.OF; break;
                case CC_NL:  take = f.SF == f.OF; break;
                case CC_LE:  take = f.ZF || (f.SF != f.OF); break;
                case CC_NLE: take = !f.ZF && (f.SF == f.OF); break;
                case CC_P:   take = f.PF; break;
                case CC_NP:  take = !f.PF; break;
                }
                if (take) ctx.vip += offset;
                calc_jmp(engine, ctx);
            });

        // CALL - push return address, jump
        table.register_handler(OP_CALL, [](
            VMEngine& engine, VMContext& ctx) {
                BytecodeReader reader(ctx, *engine.operand_chain());
                int32_t offset = (int32_t)reader.read_u32();
                ctx.push64(ctx.vip);  // return address
                ctx.vip += offset;
                calc_jmp(engine, ctx);
            });

        // RET - pop return address
        table.register_handler(OP_RET, [](
            VMEngine& engine, VMContext& ctx) {
                ctx.vip = ctx.pop64();
                calc_jmp(engine, ctx);
            });

        // ========================================================================
        // Special
        // ========================================================================
        table.register_handler(OP_READ_KEY, [](
            VMEngine& engine, VMContext& ctx) {
                ctx.push64(ctx.rolling_key);
                calc_jmp(engine, ctx);
            });

        // LREGS - push all scratch registers
        table.register_handler(OP_LREGS, [](
            VMEngine& engine, VMContext& ctx) {
                for (int i = kScratchRegCount - 1; i >= 0; --i)
                    ctx.push64(ctx.regs[i]);
                calc_jmp(engine, ctx);
            });

        // SREGS - pop all scratch registers
        table.register_handler(OP_SREGS, [](
            VMEngine& engine, VMContext& ctx) {
                for (size_t i = 0; i < kScratchRegCount; ++i)
                    ctx.regs[i] = ctx.pop64();
                calc_jmp(engine, ctx);
            });

        // VMEXIT - explicit VM exit
        table.register_handler(OP_VMEXIT, [](
            VMEngine& engine, VMContext& ctx) {
                engine.vm_exit(ctx);
                // No calc_jmp - VM execution ends
            });
    }

} // namespace vmp



