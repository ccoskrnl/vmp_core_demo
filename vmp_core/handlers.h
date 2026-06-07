#pragma once
// ============================================================================
// Handler Implementations
// ============================================================================
// Each handler implements one virtual instruction. These mirror what you'd
// see in a real VMProtect 2 disassembly when you've identified handler
// routines by their dispatch patterns.
//
// Key patterns to recognize in reverse engineering:
//   - Stack operations: MOV [RBP+off], reg / MOV reg, [RBP+off]
//   - Operand fetch: MOVZX reg, byte [RSI]; ADD RSI, 1
//   - Key update: XOR RBX, reg; ROL RBX, imm; etc.
//   - Dispatch: MOV reg, [R12 + opcode*8]; JMP reg
// ============================================================================

#include "dispatch.h"

namespace vmp {

// ============================================================================
// Register all handlers into the table
// ============================================================================
inline void register_all_handlers(HandlerTable& table) {

    // ========================================================================
    // HALT - Stop VM execution
    // ========================================================================
    table.register_handler(OP_HALT, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        engine.halt();
        return false;
    });

    // ========================================================================
    // NOP
    // ========================================================================
    table.register_handler(OP_NOP, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        return true;
    });

    // ========================================================================
    // PUSH IMM - Load immediate value onto virtual stack
    // ========================================================================

    // PUSH IMM8:  push 8-bit immediate (sign-extended to 64)
    table.register_handler(OP_PUSH_IMM8, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t imm = static_cast<int64_t>(static_cast<int8_t>(reader.read_u8()));
        ctx.push64(imm);
        return true;
    });

    // PUSH IMM16
    table.register_handler(OP_PUSH_IMM16, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t imm = static_cast<int64_t>(static_cast<int16_t>(reader.read_u16()));
        ctx.push64(imm);
        return true;
    });

    // PUSH IMM32
    table.register_handler(OP_PUSH_IMM32, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t imm = static_cast<int64_t>(static_cast<int32_t>(reader.read_u32()));
        ctx.push64(imm);
        return true;
    });

    // PUSH IMM64
    table.register_handler(OP_PUSH_IMM64, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t imm = reader.read_u64();
        ctx.push64(imm);
        return true;
    });

    // ========================================================================
    // POP - Discard top of stack
    // ========================================================================
    table.register_handler(OP_POP, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        ctx.pop64();
        return true;
    });

    // ========================================================================
    // DUP - Duplicate top of stack
    // ========================================================================
    table.register_handler(OP_DUP, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t val = ctx.read_vsp<uint64_t>(0);
        ctx.push64(val);
        return true;
    });

    // ========================================================================
    // LREG - Load scratch register onto stack
    // Operand: register index (1 byte)
    // Stack effect: push(regs[index])
    // ========================================================================
    table.register_handler(OP_LREG, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint8_t reg_idx = reader.read_u8();
        uint64_t value = ctx.regs[reg_idx];
        ctx.push64(value);
        return true;
    });

    // ========================================================================
    // SREG - Store top of stack into scratch register
    // Operand: register index (1 byte)
    // Stack effect: regs[index] = pop()
    // ========================================================================
    table.register_handler(OP_SREG, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint8_t reg_idx = reader.read_u8();
        ctx.regs[reg_idx] = ctx.pop64();
        return true;
    });

    // ========================================================================
    // LCONST - Load constant from bytecode into scratch register
    // Operand: register index (1 byte) + immediate value (size varies)
    // ========================================================================
    table.register_handler(OP_LCONST, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint8_t reg_idx = reader.read_u8();
        uint64_t value = reader.read_u64();  // full 64-bit constant
        ctx.regs[reg_idx] = value;
        return true;
    });

    // ========================================================================
    // Memory Load operations
    // Stack effect: addr = pop(); push(mem[addr])
    // ========================================================================

    table.register_handler(OP_LD8, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t addr = ctx.pop64();
        uint8_t val = *reinterpret_cast<const uint8_t*>(addr);
        ctx.push64(val);
        return true;
    });

    table.register_handler(OP_LD16, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t addr = ctx.pop64();
        uint16_t val = *reinterpret_cast<const uint16_t*>(addr);
        ctx.push64(val);
        return true;
    });

    table.register_handler(OP_LD32, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t addr = ctx.pop64();
        uint32_t val = *reinterpret_cast<const uint32_t*>(addr);
        ctx.push64(val);
        return true;
    });

    table.register_handler(OP_LD64, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t addr = ctx.pop64();
        uint64_t val = *reinterpret_cast<const uint64_t*>(addr);
        ctx.push64(val);
        return true;
    });

    // ========================================================================
    // Memory Store operations
    // Stack effect: val = pop(); addr = pop(); mem[addr] = val
    // ========================================================================

    table.register_handler(OP_ST8, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t val  = ctx.pop64();
        uint64_t addr = ctx.pop64();
        *reinterpret_cast<uint8_t*>(addr) = static_cast<uint8_t>(val);
        return true;
    });

    table.register_handler(OP_ST16, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t val  = ctx.pop64();
        uint64_t addr = ctx.pop64();
        *reinterpret_cast<uint16_t*>(addr) = static_cast<uint16_t>(val);
        return true;
    });

    table.register_handler(OP_ST32, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t val  = ctx.pop64();
        uint64_t addr = ctx.pop64();
        *reinterpret_cast<uint32_t*>(addr) = static_cast<uint32_t>(val);
        return true;
    });

    table.register_handler(OP_ST64, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t val  = ctx.pop64();
        uint64_t addr = ctx.pop64();
        *reinterpret_cast<uint64_t*>(addr) = val;
        return true;
    });

    // ========================================================================
    // Arithmetic Operations
    // Stack effect: b = pop(); a = pop(); push(result); push(flags)
    // This is critical: VMP pushes BOTH result AND RFLAGS onto the stack.
    // This is a key fingerprint for identifying VM arithmetic in disassembly.
    // ========================================================================

    table.register_handler(OP_ADD, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t b = ctx.pop64();
        uint64_t a = ctx.pop64();
        uint64_t result = a + b;
        VFlags flags = compute_flags(a, b, result, false, true);
        ctx.push64(result);
        ctx.push64(flags.raw);
        return true;
    });

    table.register_handler(OP_SUB, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t b = ctx.pop64();
        uint64_t a = ctx.pop64();
        uint64_t result = a - b;
        VFlags flags = compute_flags(a, b, result, true, true);
        ctx.push64(result);
        ctx.push64(flags.raw);
        return true;
    });

    table.register_handler(OP_MUL, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t b = ctx.pop64();
        uint64_t a = ctx.pop64();
        // Unsigned multiply, low 64 bits
        uint64_t result = a * b;
        VFlags flags{};
        flags.raw = 0x2;
        // CF and OF are set if upper 64 bits of 128-bit result are non-zero
        // For simplicity, we don't compute the full 128-bit result here.
        // In real VMP: MUL sets CF=OF=(high_half != 0)
        flags.CF = 0;  // simplified
        flags.OF = 0;
        ctx.push64(result);
        ctx.push64(flags.raw);
        return true;
    });

    table.register_handler(OP_AND, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t b = ctx.pop64();
        uint64_t a = ctx.pop64();
        uint64_t result = a & b;
        VFlags flags{};
        flags.raw = 0x2;
        flags.ZF = (result == 0);
        flags.SF = (result & 0x8000000000000000ULL) != 0;
        flags.CF = 0;
        flags.OF = 0;
        ctx.push64(result);
        ctx.push64(flags.raw);
        return true;
    });

    table.register_handler(OP_OR, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t b = ctx.pop64();
        uint64_t a = ctx.pop64();
        uint64_t result = a | b;
        VFlags flags{};
        flags.raw = 0x2;
        flags.ZF = (result == 0);
        flags.SF = (result & 0x8000000000000000ULL) != 0;
        flags.CF = 0;
        flags.OF = 0;
        ctx.push64(result);
        ctx.push64(flags.raw);
        return true;
    });

    table.register_handler(OP_XOR, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t b = ctx.pop64();
        uint64_t a = ctx.pop64();
        uint64_t result = a ^ b;
        VFlags flags{};
        flags.raw = 0x2;
        flags.ZF = (result == 0);
        flags.SF = (result & 0x8000000000000000ULL) != 0;
        flags.CF = 0;
        flags.OF = 0;
        ctx.push64(result);
        ctx.push64(flags.raw);
        return true;
    });

    table.register_handler(OP_NOT, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t a = ctx.pop64();
        uint64_t result = ~a;
        ctx.push64(result);
        // NOT doesn't affect flags in x86
        return true;
    });

    table.register_handler(OP_NEG, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t a = ctx.pop64();
        uint64_t result = static_cast<uint64_t>(-static_cast<int64_t>(a));
        VFlags flags{};
        flags.raw = 0x2;
        flags.CF = (a != 0);
        flags.ZF = (result == 0);
        flags.SF = (result & 0x8000000000000000ULL) != 0;
        ctx.push64(result);
        ctx.push64(flags.raw);
        return true;
    });

    table.register_handler(OP_SHL, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t count = ctx.pop64();
        uint64_t a = ctx.pop64();
        uint8_t c = count & 63;
        uint64_t result = (c < 64) ? (a << c) : 0;
        VFlags flags{};
        flags.raw = 0x2;
        flags.ZF = (result == 0);
        flags.SF = (result & 0x8000000000000000ULL) != 0;
        // CF = last bit shifted out
        if (c > 0 && c <= 64) {
            flags.CF = (a >> (64 - c)) & 1;
        }
        ctx.push64(result);
        ctx.push64(flags.raw);
        return true;
    });

    table.register_handler(OP_SHR, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t count = ctx.pop64();
        uint64_t a = ctx.pop64();
        uint8_t c = count & 63;
        uint64_t result = (c < 64) ? (a >> c) : 0;
        VFlags flags{};
        flags.raw = 0x2;
        flags.ZF = (result == 0);
        flags.SF = (result & 0x8000000000000000ULL) != 0;
        if (c > 0 && c <= 64) {
            flags.CF = (a >> (c - 1)) & 1;
        }
        ctx.push64(result);
        ctx.push64(flags.raw);
        return true;
    });

    table.register_handler(OP_INC, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t a = ctx.pop64();
        uint64_t result = a + 1;
        VFlags flags{};
        flags.raw = 0x2;
        flags.ZF = (result == 0);
        flags.SF = (result & 0x8000000000000000ULL) != 0;
        flags.OF = (a == 0x7FFFFFFFFFFFFFFFULL);
        // INC doesn't affect CF in x86
        ctx.push64(result);
        ctx.push64(flags.raw);
        return true;
    });

    table.register_handler(OP_DEC, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t a = ctx.pop64();
        uint64_t result = a - 1;
        VFlags flags{};
        flags.raw = 0x2;
        flags.ZF = (result == 0);
        flags.SF = (result & 0x8000000000000000ULL) != 0;
        flags.OF = (a == 0x8000000000000000ULL);
        ctx.push64(result);
        ctx.push64(flags.raw);
        return true;
    });

    // ========================================================================
    // PUSHF / POPF - RFLAGS management
    // ========================================================================

    table.register_handler(OP_PUSHF, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        ctx.push64(ctx.rflags);
        return true;
    });

    table.register_handler(OP_POPF, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        ctx.rflags = ctx.pop64();
        return true;
    });

    // ========================================================================
    // Control Flow
    // ========================================================================

    // JMP: unconditional jump. VIP = popped address from stack.
    // In some VMP variants, the jump target is an encrypted operand, not a
    // stack value. We support both patterns.
    table.register_handler(OP_JMP, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        // Read encrypted offset from bytecode (relative to current VIP)
        int32_t offset = static_cast<int32_t>(reader.read_u32());
        ctx.vip += offset;
        return true;
    });

    // JCC: conditional jump
    // Operand: condition code (1 byte) + relative offset (4 bytes)
    table.register_handler(OP_JCC, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint8_t cc = reader.read_u8();
        int32_t offset = static_cast<int32_t>(reader.read_u32());

        bool take = false;
        VFlags f;
        f.raw = ctx.rflags;

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

        if (take) {
            ctx.vip += offset;
        }
        return true;
    });

    // CALL: push current VIP, then jump
    table.register_handler(OP_CALL, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        uint64_t return_vip = ctx.vip;  // VIP already advanced past operands
        int32_t offset = static_cast<int32_t>(reader.read_u32());
        ctx.push64(return_vip);
        ctx.vip += offset;
        return true;
    });

    // RET: pop VIP
    table.register_handler(OP_RET, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        ctx.vip = ctx.pop64();
        return true;
    });

    // ========================================================================
    // Special: READ_KEY - push current rolling key onto stack
    // Used in key-dependent computations (anti-analysis)
    // ========================================================================
    table.register_handler(OP_READ_KEY, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        ctx.push64(ctx.rolling_key);
        return true;
    });

    // ========================================================================
    // SREGS / LREGS - bulk register save/restore
    // These push/pop all scratch registers in a single instruction.
    // ========================================================================

    // LREGS: push all scratch registers onto stack
    table.register_handler(OP_LREGS, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        // Push registers in reverse order (like PUSHAD)
        for (int i = kScratchRegCount - 1; i >= 0; --i) {
            ctx.push64(ctx.regs[i]);
        }
        return true;
    });

    // SREGS: pop all scratch registers from stack
    table.register_handler(OP_SREGS, [](
        VMEngine& engine, BytecodeReader& reader, VMContext& ctx) -> bool {
        // Pop registers in forward order (reverse of LREGS push order)
        for (size_t i = 0; i < kScratchRegCount; ++i) {
            ctx.regs[i] = ctx.pop64();
        }
        return true;
    });
}

} // namespace vmp
