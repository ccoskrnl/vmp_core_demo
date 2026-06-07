#pragma once
// ============================================================================
// VMP Core Architecture - Enhanced Implementation
// ============================================================================
// Key additions over the basic version:
//
// 1. Handler Table with Encrypted Entries
//    - Each opcode maps to N handler variants (real VMP uses shuffled table)
//    - Table entries are encrypted: actual_addr = decrypt(table[opcode])
//    - The decrypt transform is applied at runtime in calc_jmp
//
// 2. calc_jmp - The Dispatch mechanism
//    - Reads encrypted opcode from [RSI] (VIP)
//    - Decrypts opcode using rolling key (RBX)
//    - Indexes into handler table: [R12 + opcode * 8]
//    - Decrypts the table entry to get native handler address
//    - Updates rolling key
//    - JMPs to the handler
//
// 3. vm_entry - VM Entry Point
//    - Saves native context (all registers) onto stack
//    - Initializes RSI=VIP, RBP=VSP, R12=handler_table, R13=image_base
//    - Sets up scratch register area (RDI)
//    - Loads initial rolling key (RBX)
//    - Falls through to calc_jmp
//
// 4. vm_exit - VM Exit Point
//    - Restores native registers from scratch area
//    - Restores RSP
//    - Returns to native code
//
// 5. vmlaunch - Initial VM Entry from Native Code
//    - Pushes native context
//    - Sets up VM entry parameters
//    - JMPs to vm_entry
// ============================================================================

#include <cstdint>
#include <cstring>
#include <array>
#include <functional>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <unordered_map>
#include <random>
#include <algorithm>

#if defined(_MSC_VER)
#include <intrin.h>
#define BUILTIN_POPCOUNT32(x) __popcnt(x)
#define BUILTIN_POPCOUNT64(x) __popcnt64(x)
#else
#define BUILTIN_POPCOUNT32(x) __builtin_popcount(x)
#define BUILTIN_POPCOUNT64(x) __builtin_popcountll(x)
#endif


namespace vmp {

    // ============================================================================
    // Transform types
    // ============================================================================
    enum class TransformType : uint8_t {
        NONE = 0,
        ADD, SUB, XOR, NOT, NEG, ROL, ROR, SHL, SHR, BSWAP, INC, DEC,
    };

    struct Transform {
        TransformType type;
        uint64_t      imm;
        uint8_t       size;  // 1, 2, 4, 8

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

        uint64_t apply_inverse(uint64_t value) const {
            switch (type) {
            case TransformType::ADD:   return value - imm;
            case TransformType::SUB:   return value + imm;
            case TransformType::XOR:   return value ^ imm;
            case TransformType::NOT:   return ~value;
            case TransformType::NEG:   return -static_cast<int64_t>(value);
            case TransformType::ROL:   return ror(value, static_cast<uint8_t>(imm & 63));
            case TransformType::ROR:   return rol(value, static_cast<uint8_t>(imm & 63));
            case TransformType::SHL:   return value >> (imm & 63);
            case TransformType::SHR:   return value << (imm & 63);
            case TransformType::BSWAP: return bswap(value, size);
            case TransformType::INC:   return value - 1;
            case TransformType::DEC:   return value + 1;
            default:                   return value;
            }
        }

        // Size-aware variants for sub-64-bit operand encryption
        uint64_t apply_sized(uint64_t value, uint8_t bits) const {
            switch (type) {
            case TransformType::ROL:   return rol_sized(value, static_cast<uint8_t>(imm & 63), bits);
            case TransformType::ROR:   return ror_sized(value, static_cast<uint8_t>(imm & 63), bits);
            case TransformType::NOT:   return ~value;
            case TransformType::BSWAP: return bswap(value, bits / 8);
            default:                   return apply(value);
            }
        }

        uint64_t apply_inverse_sized(uint64_t value, uint8_t bits) const {
            switch (type) {
            case TransformType::ROL:   return ror_sized(value, static_cast<uint8_t>(imm & 63), bits);
            case TransformType::ROR:   return rol_sized(value, static_cast<uint8_t>(imm & 63), bits);
            case TransformType::NOT:   return ~value;
            case TransformType::BSWAP: return bswap(value, bits / 8);
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

    private:
        static uint64_t rol(uint64_t v, uint8_t n) {
            n &= 63; return n ? (v << n) | (v >> (64 - n)) : v;
        }
        static uint64_t ror(uint64_t v, uint8_t n) {
            n &= 63; return n ? (v >> n) | (v << (64 - n)) : v;
        }
        static uint64_t rol_sized(uint64_t v, uint8_t n, uint8_t bits) {
            if (bits >= 64) return rol(v, n);
            n %= bits; if (n == 0) return v;
            uint64_t mask = (1ULL << bits) - 1; v &= mask;
            return ((v << n) | (v >> (bits - n))) & mask;
        }
        static uint64_t ror_sized(uint64_t v, uint8_t n, uint8_t bits) {
            if (bits >= 64) return ror(v, n);
            n %= bits; if (n == 0) return v;
            uint64_t mask = (1ULL << bits) - 1; v &= mask;
            return ((v >> n) | (v << (bits - n))) & mask;
        }
        static uint64_t bswap(uint64_t v, uint8_t sz) {
            switch (sz) {
            case 2: return (v >> 8) | (v << 8);
            case 4: {
                uint32_t x = (uint32_t)v;
                x = ((x & 0xFF00FF00) >> 8) | ((x & 0x00FF00FF) << 8);
                return (x >> 16) | (x << 16);
            }
            case 8: v = ((v & 0xFF00FF00FF00FF00ULL) >> 8) | ((v & 0x00FF00FF00FF00FFULL) << 8);
                v = ((v & 0xFFFF0000FFFF0000ULL) >> 16) | ((v & 0x0000FFFF0000FFFFULL) << 16);
                return (v >> 32) | (v << 32);
            default: return v;
            }
        }
    };

    // ============================================================================
    // VFlags
    // ============================================================================
    struct VFlags {
        union {
            uint64_t raw;
            struct {
                uint64_t CF : 1; uint64_t : 1; uint64_t PF : 1; uint64_t : 1;
                uint64_t AF : 1; uint64_t : 1; uint64_t ZF : 1; uint64_t SF : 1;
                uint64_t TF : 1; uint64_t IF : 1; uint64_t DF : 1; uint64_t OF : 1;
            };
        };
    };

    // Compute flags for arithmetic
    inline VFlags compute_flags(uint64_t a, uint64_t b, uint64_t result, bool is_sub) {
        VFlags f{}; f.raw = 0x2;
        f.ZF = (result == 0);
        f.SF = (result & 0x8000000000000000ULL) != 0;
        f.CF = is_sub ? (a < b) : (result < a);
        if (is_sub) f.OF = ((a ^ b) & 0x8000000000000000ULL) && ((a ^ result) & 0x8000000000000000ULL);
        else        f.OF = !((a ^ b) & 0x8000000000000000ULL) && ((a ^ result) & 0x8000000000000000ULL);
        uint8_t low8 = (uint8_t)result;
        f.PF = !(BUILTIN_POPCOUNT32(low8) & 1);
        return f;
    }

    // ============================================================================
    // Operand Decryption Chain
    // ============================================================================
    struct DecryptChain {
        std::vector<Transform> decrypt_transforms;
        Transform              key_update;

        static uint64_t size_mask(uint8_t size) {
            switch (size) {
            case 1: return 0xFF; case 2: return 0xFFFF;
            case 4: return 0xFFFFFFFF; default: return 0xFFFFFFFFFFFFFFFF;
            }
        }

        uint64_t decrypt(uint64_t encrypted, uint64_t key, uint8_t size = 8) const {
            uint64_t mask = size_mask(size);
            uint8_t bits = size * 8;
            // XOR with key masked to operand size (only low N bytes of key used)
            uint64_t value = (encrypted ^ (key & mask)) & mask;
            for (const auto& t : decrypt_transforms)
                value = t.apply_sized(value, bits) & mask;
            return value;
        }

        uint64_t encrypt(uint64_t plaintext, uint64_t key, uint8_t size = 8) const {
            uint64_t mask = size_mask(size);
            uint8_t bits = size * 8;
            uint64_t value = plaintext & mask;
            for (auto it = decrypt_transforms.crbegin(); it != decrypt_transforms.crend(); ++it)
                value = it->apply_inverse_sized(value, bits) & mask;
            // XOR with key masked to operand size
            return (value ^ (key & mask)) & mask;
        }

        uint64_t update_key(uint64_t current_key, uint64_t decrypted_operand) const {
            return key_update.apply(current_key ^ decrypted_operand);
        }
    };

    // ============================================================================
    // Virtual Opcode Definitions
    // ============================================================================
    enum VOpcode : uint8_t {
        OP_HALT = 0x00, OP_NOP = 0x01,
        OP_PUSH_IMM8 = 0x10, OP_PUSH_IMM16 = 0x11, OP_PUSH_IMM32 = 0x12, OP_PUSH_IMM64 = 0x13,
        OP_POP = 0x14, OP_DUP = 0x15,
        OP_LREG = 0x20, OP_SREG = 0x21, OP_LCONST = 0x22,
        OP_LD8 = 0x30, OP_LD16 = 0x31, OP_LD32 = 0x32, OP_LD64 = 0x33,
        OP_ST8 = 0x34, OP_ST16 = 0x35, OP_ST32 = 0x36, OP_ST64 = 0x37,
        OP_ADD = 0x40, OP_SUB = 0x41, OP_MUL = 0x42, OP_AND = 0x44,
        OP_OR = 0x45, OP_XOR = 0x46, OP_NOT = 0x47, OP_SHL = 0x48,
        OP_SHR = 0x49, OP_NEG = 0x4A, OP_INC = 0x4B, OP_DEC = 0x4C,
        OP_PUSHF = 0x50, OP_POPF = 0x51,
        OP_JMP = 0x60, OP_JCC = 0x61, OP_CALL = 0x62, OP_RET = 0x63,
        OP_READ_KEY = 0x70, OP_SREGS = 0x71, OP_LREGS = 0x72,
        OP_VMEXIT = 0x74,
        OP_MAX = 0xFF,
    };

    enum ConditionCode : uint8_t {
        CC_O = 0x0, CC_NO = 0x1, CC_B = 0x2, CC_NB = 0x3,
        CC_Z = 0x4, CC_NZ = 0x5, CC_BE = 0x6, CC_NBE = 0x7,
        CC_S = 0x8, CC_NS = 0x9, CC_L = 0xA, CC_NL = 0xB,
        CC_LE = 0xC, CC_NLE = 0xD, CC_P = 0xE, CC_NP = 0xF,
    };

    // ============================================================================
    // Handler Function Signature
    // ============================================================================
    // In real VMP, each handler is native x64 code. We use function pointers.
    // The handler receives the VM context and returns nothing (it ends with
    // calc_jmp which dispatches to the next handler).
    // ============================================================================
    class VMContext;
    class VMEngine;

    using HandlerFunc = void(*)(VMEngine&, VMContext&);

    // ============================================================================
    // VM Context
    // ============================================================================
    static constexpr size_t kScratchRegCount = 16;

    struct VMContext {
        // VM registers (mapped to native registers in real VMP)
        uint64_t vip;           // RSI - virtual instruction pointer
        uint64_t vsp;           // RBP - virtual stack pointer
        uint64_t scratch;       // RDI - scratch register file base
        uint64_t handler_table; // R12 - handler table base (encrypted entries)
        uint64_t image_base;    // R13 - module base address
        uint64_t rolling_key;   // RBX - rolling decryption key

        // Temporary registers (volatile)
        uint64_t rax, rcx, rdx, rflags;

        // Scratch register file ([RDI+offset])
        uint64_t regs[kScratchRegCount];

        // Virtual stack
        static constexpr size_t kStackSize = 0x10000;
        alignas(16) uint8_t stack[kStackSize];

        // VM state
        bool     running;
        uint64_t vm_entry_rip;  // native RIP to return to on vm_exit

        void init(uint64_t entry_vip, uint64_t handler_tbl, uint64_t mod_base, uint64_t initial_key) {
            vip = entry_vip;
            handler_table = handler_tbl;
            image_base = mod_base;
            rolling_key = initial_key;
            vsp = reinterpret_cast<uint64_t>(stack + kStackSize);
            scratch = reinterpret_cast<uint64_t>(regs);
            rax = rcx = rdx = rflags = 0;
            running = true;
            vm_entry_rip = 0;
            memset(regs, 0, sizeof(regs));
        }

        void push64(uint64_t val) { vsp -= 8; *reinterpret_cast<uint64_t*>(vsp) = val; }
        uint64_t pop64() { uint64_t v = *reinterpret_cast<uint64_t*>(vsp); vsp += 8; return v; }

        template<typename T> T read_vsp(int32_t off) const { return *reinterpret_cast<const T*>(vsp + off); }
        template<typename T> void write_vsp(int32_t off, T val) { *reinterpret_cast<T*>(vsp + off) = val; }
    };

    // ============================================================================
    // Handler Table with Encrypted Entries
    // ============================================================================
    // In VMProtect 2:
    //   - The handler table is an array of 8-byte entries at [R12]
    //   - Each entry is the encrypted native address of a handler
    //   - Decryption: real_addr = entry ^ handler_decrypt_key
    //   - The decrypt key is derived from the handler index and a base key
    //   - Each opcode can map to multiple handlers (shuffled table)
    //
    // We model this with:
    //   - A table of encrypted 64-bit entries
    //   - A table entry decryption transform
    //   - Multiple handler variants per opcode
    // ============================================================================
    class HandlerTable {
    public:
        // Register a handler for an opcode. Multiple registrations = multiple variants.
        void register_handler(uint8_t opcode, HandlerFunc fn) {
            handlers_[opcode].push_back(fn);
        }

        // Build the encrypted handler table.
        // In real VMP, this is done at pack time. We simulate it.
        void build_table(uint64_t table_key) {
            table_key_ = table_key;
            entries_.clear();
            entry_opcodes_.clear();

            // Build a flat table of all handler variants, shuffled
            std::vector<std::pair<uint8_t, HandlerFunc>> flat;
            for (auto& [opcode, funcs] : handlers_) {
                for (auto& fn : funcs) {
                    flat.push_back({ opcode, fn });
                }
            }

            // Shuffle the table (in real VMP, the table order is obfuscated)
            std::mt19937 rng(0x1337);
            std::shuffle(flat.begin(), flat.end(), rng);

            table_size_ = flat.size();
            for (size_t i = 0; i < flat.size(); ++i) {
                // Store the handler function pointer (in real VMP, this is a native address)
                uint64_t raw_addr = reinterpret_cast<uint64_t>(flat[i].second);
                // Encrypt the entry
                uint64_t encrypted = encrypt_entry(raw_addr, i);
                entries_.push_back(encrypted);
                entry_opcodes_.push_back(flat[i].first);
                // Build reverse map: opcode -> list of table indices
                opcode_indices_[flat[i].first].push_back(i);
            }
        }

        // Decrypt a table entry (simulates: mov rdx, [r12+rax*8]; xor rdx, key)
        uint64_t decrypt_entry(uint64_t encrypted_entry, uint8_t index) const {
            // Real VMP: the transform varies (XOR, ADD, SUB, etc.)
            // We use XOR with (table_key + index * constant)
            return encrypted_entry ^ (table_key_ + index * 0x1337);
        }

        // Get handler function from decrypted address
        // In real VMP, the decrypted address IS the native code address.
        // We simulate by looking up the function pointer.
        HandlerFunc get_handler(uint8_t opcode) const {
            auto it = opcode_indices_.find(opcode);
            if (it == opcode_indices_.end() || it->second.empty()) return nullptr;
            // Pick the first variant (in real VMP, the index is determined by the opcode)
            size_t idx = it->second[0];
            // Return the raw function pointer (stored as the decrypted entry)
            uint64_t decrypted = decrypt_entry(entries_[idx], idx);
            return reinterpret_cast<HandlerFunc>(decrypted);
        }

        // Get a random handler variant for an opcode (demonstrates polymorphism)
        HandlerFunc get_random_handler(uint8_t opcode, uint64_t key) const {
            auto it = opcode_indices_.find(opcode);
            if (it == opcode_indices_.end() || it->second.empty()) return nullptr;
            size_t variant = key % it->second.size();
            size_t idx = it->second[variant];
            uint64_t decrypted = decrypt_entry(entries_[idx], idx);
            return reinterpret_cast<HandlerFunc>(decrypted);
        }

        const std::vector<uint64_t>& entries() const { return entries_; }
        size_t size() const { return table_size_; }
        uint64_t table_key() const { return table_key_; }

    private:
        uint64_t encrypt_entry(uint64_t raw_addr, size_t index) const {
            return raw_addr ^ (table_key_ + index * 0x1337);
        }

        std::unordered_map<uint8_t, std::vector<HandlerFunc>> handlers_;
        std::vector<uint64_t>    entries_;          // encrypted handler addresses
        std::vector<uint8_t>     entry_opcodes_;    // opcode for each entry
        std::unordered_map<uint8_t, std::vector<size_t>> opcode_indices_; // opcode -> table indices
        size_t                   table_size_ = 0;
        uint64_t                 table_key_ = 0;
    };

    // ============================================================================
    // Forward declarations for dispatch functions
    // ============================================================================
    inline void calc_jmp(VMEngine& engine, VMContext& ctx);

    // ============================================================================
    // VMEngine - manages the VM lifecycle
    // ============================================================================
    class VMEngine {
    public:
        void set_handlers(HandlerTable& table) { handler_table_ = &table; }

        // vmlaunch: entry from native code into the VM
        // This simulates the native CALL to vmlaunch that sets up the VM
        void vmlaunch(VMContext& ctx, const DecryptChain& opcode_chain,
            const DecryptChain& operand_chain) {
            opcode_chain_ = &opcode_chain;
            operand_chain_ = &operand_chain;

            // In real VMP, vmlaunch:
            //   1. PUSHF
            //   2. PUSH all registers (RAX..R15)
            //   3. PUSH the virtual instruction pointer (RVA of bytecode)
            //   4. CALL vm_entry
            //
            // We've already set up ctx.init() so we just mark running and dispatch.
            ctx.running = true;

            // Enter the dispatch loop (calc_jmp)
            while (ctx.running) {
                calc_jmp(*this, ctx);
            }
        }

        // vm_exit: restore native context and return
        void vm_exit(VMContext& ctx) {
            // In real VMP, vm_exit:
            //   1. MOV RSP, RDI (restore scratch area pointer)
            //   2. POP all registers (R15..RAX)
            //   3. POPF
            //   4. ADD RSP, 0x28 (clean shadow space)
            //   5. RET (return to native code)
            //
            // We just stop the VM and restore the scratch registers.
            ctx.running = false;

            // Restore native registers from scratch area
            // In real VMP, the scratch area contains saved native registers
            // that were pushed during vm_entry.
            // For simulation, we just mark VM as stopped.
        }

        HandlerTable* handler_table() { return handler_table_; }
        const DecryptChain* opcode_chain() { return opcode_chain_; }
        const DecryptChain* operand_chain() { return operand_chain_; }

    private:
        HandlerTable* handler_table_ = nullptr;
        const DecryptChain* opcode_chain_ = nullptr;
        const DecryptChain* operand_chain_ = nullptr;
    };

    // ============================================================================
    // calc_jmp - The Heart of VM Dispatch
    // ============================================================================
    // This is the most critical piece of the VM. In VMProtect 2, calc_jmp is
    // a snippet of obfuscated native code that:
    //
    //   1. MOVZX EAX, BYTE PTR [RSI]     ; read encrypted opcode from VIP
    //   2. MOV RDX, [R12 + RAX*8]        ; fetch encrypted handler address
    //   3. <transform RDX>               ; decrypt handler table entry
    //   4. <transform RAX with RBX>      ; decrypt opcode (update rolling key)
    //   5. LEA RSI, [RSI + 1]            ; advance VIP
    //   6. JMP RDX                       ; dispatch to handler
    //
    // The handler then executes and ends with another calc_jmp (direct threading).
    // ============================================================================
    inline void calc_jmp(VMEngine& engine, VMContext& ctx) {
        // Step 1: Read encrypted opcode from VIP (RSI)
        uint8_t encrypted_opcode = *reinterpret_cast<const uint8_t*>(ctx.vip);
        ctx.vip += 1;  // LEA RSI, [RSI+1]

        // Step 2: Decrypt opcode using rolling key (RBX)
        const auto* oc = engine.opcode_chain();
        uint8_t opcode = static_cast<uint8_t>(oc->decrypt(encrypted_opcode, ctx.rolling_key, 1));

        // Step 3: Update rolling key with decrypted opcode
        ctx.rolling_key = oc->update_key(ctx.rolling_key, opcode);

        // Step 4: Fetch encrypted handler address from table
        // Simulates: MOV RDX, [R12 + RAX*8]
        auto* table = engine.handler_table();
        HandlerFunc handler = table->get_handler(opcode);

        if (!handler) {
            std::cerr << "[VM] Unknown opcode 0x" << std::hex << (int)opcode
                << " (encrypted: 0x" << (int)encrypted_opcode << ")"
                << " at VIP 0x" << (ctx.vip - 1) << std::dec << std::endl;
            ctx.running = false;
            return;
        }

        // Step 5: JMP to handler (the handler will end with calc_jmp)
        handler(engine, ctx);
    }

    // ============================================================================
    // BytecodeReader - reads and decrypts operands from VIP
    // ============================================================================
    class BytecodeReader {
    public:
        BytecodeReader(VMContext& ctx, const DecryptChain& operand_chain)
            : ctx_(ctx), chain_(operand_chain) {
        }

        uint8_t  read_u8() { return (uint8_t)read_operand(1); }
        uint16_t read_u16() { return (uint16_t)read_operand(2); }
        uint32_t read_u32() { return (uint32_t)read_operand(4); }
        uint64_t read_u64() { return read_operand(8); }

    private:
        uint64_t read_operand(uint8_t size) {
            uint64_t encrypted = 0;
            switch (size) {
            case 1: encrypted = *(const uint8_t*)ctx_.vip;  ctx_.vip += 1; break;
            case 2: encrypted = *(const uint16_t*)ctx_.vip; ctx_.vip += 2; break;
            case 4: encrypted = *(const uint32_t*)ctx_.vip; ctx_.vip += 4; break;
            case 8: encrypted = *(const uint64_t*)ctx_.vip; ctx_.vip += 8; break;
            }
            uint64_t decrypted = chain_.decrypt(encrypted, ctx_.rolling_key, size);
            ctx_.rolling_key = chain_.update_key(ctx_.rolling_key, decrypted);
            return decrypted;
        }

        VMContext& ctx_;
        const DecryptChain& chain_;
    };

} // namespace vmp

