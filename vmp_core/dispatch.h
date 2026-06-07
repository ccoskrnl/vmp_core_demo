#pragma once
// ============================================================================
// Handler Table & Dispatch Engine
// ============================================================================
// The heart of the VM: the fetch-decode-execute loop.
//
// In VMProtect 2, the handler table is an array of native code addresses.
// The opcode byte is used as an index into this table. The actual table is
// encrypted: each entry is XORed/transformed with a key derived from the
// handler's position.
//
// Dispatch pattern (VMProtect 2):
//   1. Read 1 encrypted byte from [RSI] (VIP)
//   2. Decrypt using RBX (rolling key) -> handler index
//   3. Update RBX
//   4. Use index to look up handler address from [R12 + index * entry_size]
//   5. The table entry itself may be encrypted and needs decryption
//   6. JMP to handler
//   7. Handler executes, then falls through or JMPs back to dispatch
//
// The dispatch loop is NOT a centralized loop in real VMP - each handler
// ends with the dispatch code (threaded dispatch / direct threading).
// We simulate this with function pointers for clarity.
// ============================================================================

#include "vmp_core.h"
#include "operand_decrypt.h"
#include <unordered_map>

#if defined(_MSC_VER)
#include <intrin.h>
#define BUILTIN_POPCOUNT32(x) __popcnt(x)
#define BUILTIN_POPCOUNT64(x) __popcnt64(x)
#else
#define BUILTIN_POPCOUNT32(x) __builtin_popcount(x)
#define BUILTIN_POPCOUNT64(x) __builtin_popcountll(x)
#endif



namespace vmp {

// Forward declaration
class VMEngine;

// Handler function signature
// Each handler receives the engine, reader, and context.
// Handlers return true to continue execution, false to halt.
using HandlerFunc = std::function<bool(VMEngine&, BytecodeReader&, VMContext&)>;

// ============================================================================
// Handler Table - maps opcode index to handler function
// ============================================================================
class HandlerTable {
public:
    void register_handler(uint8_t index, HandlerFunc fn) {
        handlers_[index] = std::move(fn);
    }

    HandlerFunc* get(uint8_t index) {
        auto it = handlers_.find(index);
        return (it != handlers_.end()) ? &it->second : nullptr;
    }

    // In real VMP, the table entries are encrypted.
    // We provide a simulation of table entry decryption.
    static uint64_t decrypt_table_entry(uint64_t encrypted_entry, uint8_t index,
                                         uint64_t table_key) {
        // Real VMP: each entry is XORed with (table_key + index * constant)
        // or similar. Simplified here.
        return encrypted_entry ^ (table_key + index * 0x1337);
    }

private:
    std::unordered_map<uint8_t, HandlerFunc> handlers_;
};

// ============================================================================
// VM Engine - the main execution engine
// ============================================================================
class VMEngine {
public:
    VMEngine() : running_(false) {}

    // Initialize with a handler table
    void set_handlers(HandlerTable& table) {
        handler_table_ = &table;
    }

    // Run the VM until HALT
    bool run(VMContext& ctx, const DecryptChain& opcode_chain,
             const DecryptChain& operand_chain) {
        BytecodeReader reader(ctx, opcode_chain, operand_chain);
        running_ = true;
        uint64_t step_count = 0;

        while (running_) {
            // === FETCH & DECODE ===
            // Read encrypted opcode from VIP, decrypt using rolling key
            uint8_t opcode = reader.read_opcode();

            // === LOOKUP HANDLER ===
            HandlerFunc* handler = handler_table_->get(opcode);
            if (!handler) {
                std::cerr << "[VM] Unknown opcode 0x" << std::hex
                          << (int)opcode << " at VIP 0x"
                          << (ctx.vip - 1) << std::dec << std::endl;
                return false;
            }

            // === EXECUTE ===
            // In real VMP, this is a JMP to the handler's native code.
            // The handler ends with the dispatch code (direct threading).
            if (!(*handler)(*this, reader, ctx)) {
                break;
            }

            step_count++;
        }

        return true;
    }

    void halt() { running_ = false; }

private:
    HandlerTable* handler_table_;
    bool          running_;
};

// ============================================================================
// Arithmetic helper - computes result and updates RFLAGS
// ============================================================================
struct ArithResult {
    uint64_t value;
    uint64_t flags;  // RFLAGS
};

// Compute flags for an arithmetic operation
inline VFlags compute_flags(uint64_t a, uint64_t b, uint64_t result,
                            bool is_sub, bool is_64bit) {
    VFlags f{};
    f.raw = 0x2;  // bit 1 always set (reserved)

    uint64_t sign_mask = is_64bit ? 0x8000000000000000ULL : 0x80000000ULL;
    uint64_t max_val   = is_64bit ? 0xFFFFFFFFFFFFFFFFULL : 0xFFFFFFFFULL;

    // Zero flag
    if (is_64bit) {
        f.ZF = (result == 0);
    } else {
        f.ZF = ((result & 0xFFFFFFFF) == 0);
    }

    // Sign flag
    f.SF = (result & sign_mask) != 0;

    // Carry flag
    if (is_sub) {
        f.CF = (a < b);
    } else {
        f.CF = (result < a);  // unsigned overflow
    }

    // Overflow flag (signed)
    if (is_sub) {
        // Subtraction overflow: signs differ and result sign differs from a
        f.OF = ((a ^ b) & sign_mask) && ((a ^ result) & sign_mask);
    } else {
        // Addition overflow: same signs and result sign differs
        f.OF = !((a ^ b) & sign_mask) && ((a ^ result) & sign_mask);
    }

    // Parity flag (low 8 bits)
    uint8_t low8 = static_cast<uint8_t>(result);
    f.PF = !(BUILTIN_POPCOUNT32(low8) & 1);  // even parity

    return f;
}

} // namespace vmp
