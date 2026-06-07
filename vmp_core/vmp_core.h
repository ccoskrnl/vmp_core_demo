#pragma once

// ============================================================================
// VMP Core Architecture - Educational Implementation
// Based on VMProtect 2.x internals
// ============================================================================
//
// Register mapping (VMProtect 2):
//   RSI = VIP (Virtual Instruction Pointer) - points to next bytecode operand
//   RBP = VSP (Virtual Stack Pointer)       - points to virtual stack top
//   RDI = Scratch register area             - local register file on stack
//   R12 = Handler table base address
//   R13 = Module base address
//   RBX = Rolling decryption key
//
// The VM interprets a custom bytecode stream. Each instruction:
//   [encrypted opcode] [encrypted operand(s)...]
//
// The opcode selects a handler from the handler table (indexed by byte).
// Operands are decrypted using RBX (rolling key) with various transforms.
// After each operand decryption, RBX is updated: RBX ^= decrypted_operand
// or via a more complex transformation.
// ============================================================================

#include <cstdint>
#include <cstring>
#include <array>
#include <functional>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>

namespace vmp {

    // ============================================================================
    // Transform types - operand/key transformations used in VMProtect
    // ============================================================================
    enum class TransformType : uint8_t {
        NONE = 0,
        ADD,
        SUB,
        XOR,
        NOT,
        NEG,
        ROL,
        ROR,
        SHL,
        SHR,
        BSWAP,
        INC,
        DEC,
    };

    struct Transform {
        TransformType type;
        uint64_t      imm;        // immediate constant (0 if none)
        uint8_t       size;       // operand size: 1, 2, 4, 8

        uint64_t apply(uint64_t value) const {
            switch (type) {
            case TransformType::ADD:   return value + imm;
            case TransformType::SUB:   return value - imm;
            case TransformType::XOR:   return value ^ imm;
            case TransformType::NOT:   return ~value;
            case TransformType::NEG:   return -static_cast<int64_t>(value);
            case TransformType::ROL:   return rol(value, static_cast<uint8_t>(imm & 63));
            case TransformType::ROR:   return ror(value, static_cast<uint8_t>(imm & 63));
            case TransformType::SHL:   return value << (imm & 63);
            case TransformType::SHR:   return value >> (imm & 63);
            case TransformType::BSWAP: return bswap(value, size);
            case TransformType::INC:   return value + 1;
            case TransformType::DEC:   return value - 1;
            default:                   return value;
            }
        }

        // Size-aware apply: rotates/shifts at the operand's bit width
        // This is critical for sub-64-bit operand encryption to be invertible.
        uint64_t apply_sized(uint64_t value, uint8_t op_size) const {
            switch (type) {
            case TransformType::ROL:   return rol_sized(value, static_cast<uint8_t>(imm & 63), op_size);
            case TransformType::ROR:   return ror_sized(value, static_cast<uint8_t>(imm & 63), op_size);
            case TransformType::NOT:   return ~value;
            case TransformType::BSWAP: return bswap(value, op_size);
            default:                   return apply(value);
            }
        }

        uint64_t apply_inverse_sized(uint64_t value, uint8_t op_size) const {
            switch (type) {
            case TransformType::ROL:   return ror_sized(value, static_cast<uint8_t>(imm & 63), op_size);
            case TransformType::ROR:   return rol_sized(value, static_cast<uint8_t>(imm & 63), op_size);
            case TransformType::NOT:   return ~value;
            case TransformType::BSWAP: return bswap(value, op_size);
            case TransformType::ADD:   return value - imm;
            case TransformType::SUB:   return value + imm;
            case TransformType::XOR:   return value ^ imm;
            case TransformType::NEG:   return -static_cast<int64_t>(value);
            case TransformType::SHL:   return value >> (imm & 63);
            case TransformType::SHR:   return value << (imm & 63);
            case TransformType::INC:   return value - 1;
            case TransformType::DEC:   return value + 1;
            default:                   return value;
            }
        }

        // Apply inverse transform (for encryption, when we need to reverse)
        uint64_t apply_inverse(uint64_t value) const {
            switch (type) {
            case TransformType::ADD:   return value - imm;
            case TransformType::SUB:   return value + imm;
            case TransformType::XOR:   return value ^ imm;  // XOR is self-inverse
            case TransformType::NOT:   return ~value;
            case TransformType::NEG:   return -static_cast<int64_t>(value);
            case TransformType::ROL:   return ror(value, static_cast<uint8_t>(imm & 63));
            case TransformType::ROR:   return rol(value, static_cast<uint8_t>(imm & 63));
            case TransformType::SHL:   return value >> (imm & 63);
            case TransformType::SHR:   return value << (imm & 63);
            case TransformType::BSWAP: return bswap(value, size);  // BSWAP is self-inverse
            case TransformType::INC:   return value - 1;
            case TransformType::DEC:   return value + 1;
            default:                   return value;
            }
        }

    private:
        static uint64_t rol(uint64_t v, uint8_t n) {
            n &= 63;
            return n ? (v << n) | (v >> (64 - n)) : v;
        }
        static uint64_t ror(uint64_t v, uint8_t n) {
            n &= 63;
            return n ? (v >> n) | (v << (64 - n)) : v;
        }
        // Size-aware rotation: rotates within the operand's bit width
        static uint64_t rol_sized(uint64_t v, uint8_t n, uint8_t bits) {
            if (bits >= 64) return rol(v, n);
            n %= bits;
            if (n == 0) return v;
            uint64_t mask = (1ULL << bits) - 1;
            v &= mask;
            return ((v << n) | (v >> (bits - n))) & mask;
        }
        static uint64_t ror_sized(uint64_t v, uint8_t n, uint8_t bits) {
            if (bits >= 64) return ror(v, n);
            n %= bits;
            if (n == 0) return v;
            uint64_t mask = (1ULL << bits) - 1;
            v &= mask;
            return ((v >> n) | (v << (bits - n))) & mask;
        }
        static uint64_t bswap(uint64_t v, uint8_t sz) {
            switch (sz) {
            case 2: return (v >> 8) | (v << 8);
            case 4: {
                uint32_t x = static_cast<uint32_t>(v);
                x = ((x & 0xFF00FF00) >> 8) | ((x & 0x00FF00FF) << 8);
                x = (x >> 16) | (x << 16);
                return x;
            }
            case 8: {
                v = ((v & 0xFF00FF00FF00FF00ULL) >> 8) | ((v & 0x00FF00FF00FF00FFULL) << 8);
                v = ((v & 0xFFFF0000FFFF0000ULL) >> 16) | ((v & 0x0000FFFF0000FFFFULL) << 16);
                v = (v >> 32) | (v << 32);
                return v;
            }
            default: return v;
            }
        }
    };

    // ============================================================================
    // RFLAGS layout (for virtual flags register)
    // ============================================================================
    struct VFlags {
        union {
            uint64_t raw;
            struct {
                uint64_t CF : 1;  // bit 0
                uint64_t : 1;  // bit 1 (always 1)
                uint64_t PF : 1;  // bit 2
                uint64_t : 1;  // bit 3
                uint64_t AF : 1;  // bit 4
                uint64_t : 1;  // bit 5
                uint64_t ZF : 1;  // bit 6
                uint64_t SF : 1;  // bit 7
                uint64_t TF : 1;  // bit 8
                uint64_t IF : 1;  // bit 9
                uint64_t DF : 1;  // bit 10
                uint64_t OF : 1;  // bit 11
                uint64_t : 2;  // bits 12-13
                uint64_t NT : 1;  // bit 14
                uint64_t : 1;  // bit 15
                uint64_t RF : 1;  // bit 16
                uint64_t VM : 1;  // bit 17
                uint64_t AC : 1;  // bit 18
                uint64_t VIF : 1;  // bit 19
                uint64_t VIP : 1;  // bit 20
                uint64_t ID : 1;  // bit 21
            };
        };
    };

    // ============================================================================
    // VM Context - the complete state of the virtual machine
    // ============================================================================
    // Mirrors the register usage described in the prompt.
    // In VMProtect 2, registers RDI..R11 are mapped as scratch registers
    // stored on the stack via [RDI + offset].
    //
    // The scratch register file (pointed to by RDI) stores saved native regs:
    //   [RDI+0x00] = saved R15
    //   [RDI+0x08] = saved R14
    //   [RDI+0x10] = saved R13
    //   [RDI+0x18] = saved R12
    //   [RDI+0x20] = saved R11
    //   [RDI+0x28] = saved R10
    //   [RDI+0x30] = saved R9
    //   [RDI+0x38] = saved R8
    //   [RDI+0x40] = saved RBP  (native, not virtual)
    //   [RDI+0x48] = saved RDI
    //   [RDI+0x50] = saved RSI
    //   [RDI+0x58] = saved RBX
    //   [RDI+0x60] = saved RDX
    //   [RDI+0x68] = saved RCX
    //   [RDI+0x70] = saved RAX
    //   [RDI+0x78] = saved RFLAGS
    // ============================================================================

    // Maximum number of scratch registers saved by the VM
    static constexpr size_t kScratchRegCount = 16;
    static constexpr size_t kScratchRegSlotSize = 8;  // 64-bit each

    struct VMContext {
        // === Volatile: set up by vm_entry, used during dispatch ===
        uint64_t vip;       // RSI - virtual instruction pointer
        uint64_t vsp;       // RBP - virtual stack pointer
        uint64_t scratch;   // RDI - scratch register file base
        uint64_t handler_table; // R12 - handler table base
        uint64_t image_base;    // R13 - module base address
        uint64_t rolling_key;   // RBX - rolling decryption key

        // === Temporary (volatile) registers used by handlers ===
        uint64_t rax;
        uint64_t rcx;
        uint64_t rdx;
        uint64_t rflags;    // native flags used by VM for flag operations

        // === Virtual stack memory ===
        // In real VMP, this is the native stack. We simulate it.
        static constexpr size_t kStackSize = 0x10000;  // 64KB virtual stack
        alignas(16) uint8_t stack[kStackSize];

        // === Scratch register file (simulates [RDI+off] accesses) ===
        uint64_t regs[kScratchRegCount];  // maps to [RDI+0..0x78]

        // Initialize context for execution
        void init(uint64_t entry_vip, uint64_t handler_tbl, uint64_t mod_base, uint64_t initial_key) {
            vip = entry_vip;
            handler_table = handler_tbl;
            image_base = mod_base;
            rolling_key = initial_key;

            // VSP points to top of our stack (stack grows downward in x64)
            vsp = reinterpret_cast<uint64_t>(stack + kStackSize);
            scratch = reinterpret_cast<uint64_t>(regs);

            rax = rcx = rdx = rflags = 0;
            memset(regs, 0, sizeof(regs));
        }

        // Stack push (64-bit)
        void push64(uint64_t val) {
            vsp -= 8;
            *reinterpret_cast<uint64_t*>(vsp) = val;
        }

        // Stack pop (64-bit)
        uint64_t pop64() {
            uint64_t val = *reinterpret_cast<uint64_t*>(vsp);
            vsp += 8;
            return val;
        }

        // Stack push (32-bit)
        void push32(uint32_t val) {
            vsp -= 4;
            *reinterpret_cast<uint32_t*>(vsp) = val;
        }

        uint32_t pop32() {
            uint32_t val = *reinterpret_cast<uint32_t*>(vsp);
            vsp += 4;
            return val;
        }

        // Read/write at VSP-relative offset
        template<typename T>
        T read_vsp(int32_t offset) const {
            return *reinterpret_cast<const T*>(vsp + offset);
        }

        template<typename T>
        void write_vsp(int32_t offset, T val) {
            *reinterpret_cast<T*>(vsp + offset) = val;
        }
    };

    // ============================================================================
    // Virtual Opcode Definitions
    // ============================================================================
    // Each opcode maps to a handler index in the handler table.
    // In VMProtect, the actual mapping is obfuscated (handler table entries are
    // shuffled and encrypted). We use a clean mapping here for clarity.
    // ============================================================================
    enum VOpcode : uint8_t {
        OP_HALT = 0x00,  // Stop VM execution
        OP_NOP = 0x01,  // No operation

        // Stack operations
        OP_PUSH_IMM8 = 0x10,  // Push 8-bit immediate
        OP_PUSH_IMM16 = 0x11,  // Push 16-bit immediate
        OP_PUSH_IMM32 = 0x12,  // Push 32-bit immediate
        OP_PUSH_IMM64 = 0x13,  // Push 64-bit immediate
        OP_POP = 0x14,  // Pop value (discard)
        OP_DUP = 0x15,  // Duplicate top of stack

        // Register load/store (scratch regs via [RDI+offset])
        OP_LREG = 0x20,  // Load scratch reg onto stack
        OP_SREG = 0x21,  // Store top of stack into scratch reg
        OP_LCONST = 0x22,  // Load constant from bytecode into scratch reg

        // Memory operations
        OP_LD8 = 0x30,  // Load 8-bit from [addr]
        OP_LD16 = 0x31,  // Load 16-bit from [addr]
        OP_LD32 = 0x32,  // Load 32-bit from [addr]
        OP_LD64 = 0x33,  // Load 64-bit from [addr]
        OP_ST8 = 0x34,  // Store 8-bit to [addr]
        OP_ST16 = 0x35,  // Store 16-bit to [addr]
        OP_ST32 = 0x36,  // Store 32-bit to [addr]
        OP_ST64 = 0x37,  // Store 64-bit to [addr]

        // Arithmetic (result + RFLAGS pushed to stack)
        OP_ADD = 0x40,
        OP_SUB = 0x41,
        OP_MUL = 0x42,
        OP_DIV = 0x43,
        OP_AND = 0x44,
        OP_OR = 0x45,
        OP_XOR = 0x46,
        OP_NOT = 0x47,
        OP_SHL = 0x48,
        OP_SHR = 0x49,
        OP_NEG = 0x4A,
        OP_INC = 0x4B,
        OP_DEC = 0x4C,

        // Flags
        OP_PUSHF = 0x50,  // Push RFLAGS
        OP_POPF = 0x51,  // Pop into RFLAGS

        // Control flow
        OP_JMP = 0x60,  // Unconditional jump (VIP = popped address)
        OP_JCC = 0x61,  // Conditional jump (reads condition from bytecode)
        OP_CALL = 0x62,  // Push return VIP, jump
        OP_RET = 0x63,  // Pop VIP

        // Special
        OP_READ_KEY = 0x70,  // Push current rolling key
        OP_SREGS = 0x71,  // Store all scratch regs from stack
        OP_LREGS = 0x72,  // Load all scratch regs onto stack
        OP_VMENTER = 0x73,  // Nested VM entry (push context, reinit)
        OP_VMEXIT = 0x74,  // VM exit - restore native context

        OP_MAX = 0xFF,
    };

    // ============================================================================
    // Condition codes for JCC (matches x86 condition encoding)
    // ============================================================================
    enum ConditionCode : uint8_t {
        CC_O = 0x0,  // Overflow
        CC_NO = 0x1,  // Not overflow
        CC_B = 0x2,  // Below (CF=1)
        CC_NB = 0x3,  // Not below (CF=0)
        CC_Z = 0x4,  // Zero (ZF=1)
        CC_NZ = 0x5,  // Not zero (ZF=0)
        CC_BE = 0x6,  // Below or equal
        CC_NBE = 0x7,  // Not below or equal
        CC_S = 0x8,  // Sign (SF=1)
        CC_NS = 0x9,  // Not sign
        CC_L = 0xA,  // Less (SF != OF)
        CC_NL = 0xB,  // Not less
        CC_LE = 0xC,  // Less or equal
        CC_NLE = 0xD,  // Not less or equal
        CC_P = 0xE,  // Parity
        CC_NP = 0xF,  // Not parity
    };

} // namespace vmp

