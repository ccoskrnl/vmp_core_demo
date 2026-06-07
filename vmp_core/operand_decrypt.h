#pragma once
// ============================================================================
// Operand Decryption Engine
// ============================================================================
// In VMProtect 2, every operand (opcode AND data operands) is encrypted
// using a chain of transforms with the rolling key (RBX).
//
// Decryption flow for each operand:
//   1. Read encrypted bytes from VIP (size depends on operand type)
//   2. Apply key-dependent transform: operand ^= rolling_key
//   3. Apply additional transforms (add, sub, xor, not, neg, rol, ror, etc.)
//   4. The specific transform sequence is per-VM-instance (compiled into the VM)
//   5. After decryption, update rolling_key:
//      rolling_key = transform(rolling_key, decrypted_operand)
//
// For opcodes, only 1 byte is read. For immediate operands, 1/2/4/8 bytes.
// ============================================================================

#include "vmp_core.h"
#include <vector>

namespace vmp {

// ============================================================================
// Operand decryption descriptor
// ============================================================================
// Each VM instance has a unique sequence of transforms for operand decryption.
// We model this as a chain of transforms applied in order.
// ============================================================================
struct DecryptChain {
    // Transform applied to decrypt (applied to encrypted_value in order)
    std::vector<Transform> decrypt_transforms;

    // Transform applied to update rolling key after decryption
    Transform key_update;

    // Size mask helper
    static uint64_t size_mask(uint8_t size) {
        switch (size) {
        case 1: return 0xFF;
        case 2: return 0xFFFF;
        case 4: return 0xFFFFFFFF;
        case 8: return 0xFFFFFFFFFFFFFFFF;
        default: return 0xFFFFFFFFFFFFFFFF;
        }
    }

    // Decrypt an operand (size-aware)
    // size is in BYTES (1, 2, 4, 8). Transforms operate at (size*8) bits.
    uint64_t decrypt(uint64_t encrypted, uint64_t key, uint8_t size = 8) const {
        uint64_t mask = size_mask(size);
        uint8_t bits = size * 8;  // convert bytes to bits for rotation width
        uint64_t value = (encrypted ^ key) & mask;

        for (const auto& t : decrypt_transforms) {
            value = t.apply_sized(value, bits) & mask;
        }

        return value;
    }

    // Encrypt a plaintext operand (inverse of decrypt, size-aware)
    uint64_t encrypt(uint64_t plaintext, uint64_t key, uint8_t size = 8) const {
        uint64_t mask = size_mask(size);
        uint8_t bits = size * 8;
        uint64_t value = plaintext & mask;
        for (auto it = decrypt_transforms.crbegin(); it != decrypt_transforms.crend(); ++it) {
            value = it->apply_inverse_sized(value, bits) & mask;
        }
        return (value ^ key) & mask;
    }

    // Update rolling key with the decrypted operand
    uint64_t update_key(uint64_t current_key, uint64_t decrypted_operand) const {
        return key_update.apply(current_key ^ decrypted_operand);
    }
};

// ============================================================================
// BytecodeReader - reads and decrypts operands from the bytecode stream
// ============================================================================
class BytecodeReader {
public:
    BytecodeReader(VMContext& ctx, const DecryptChain& opcode_chain,
                   const DecryptChain& operand_chain)
        : ctx_(ctx), opcode_chain_(opcode_chain), operand_chain_(operand_chain) {}

    // Read and decrypt a 1-byte opcode
    uint8_t read_opcode() {
        uint8_t encrypted = *reinterpret_cast<const uint8_t*>(ctx_.vip);
        ctx_.vip += 1;

        uint64_t decrypted = opcode_chain_.decrypt(encrypted, ctx_.rolling_key, 1);
        ctx_.rolling_key = opcode_chain_.update_key(ctx_.rolling_key, decrypted);

        return static_cast<uint8_t>(decrypted);
    }

    // Read and decrypt a multi-byte operand
    uint64_t read_operand(uint8_t size) {
        uint64_t encrypted = 0;
        switch (size) {
        case 1:
            encrypted = *reinterpret_cast<const uint8_t*>(ctx_.vip);
            ctx_.vip += 1;
            break;
        case 2:
            encrypted = *reinterpret_cast<const uint16_t*>(ctx_.vip);
            ctx_.vip += 2;
            break;
        case 4:
            encrypted = *reinterpret_cast<const uint32_t*>(ctx_.vip);
            ctx_.vip += 4;
            break;
        case 8:
            encrypted = *reinterpret_cast<const uint64_t*>(ctx_.vip);
            ctx_.vip += 8;
            break;
        }

        uint64_t decrypted = operand_chain_.decrypt(encrypted, ctx_.rolling_key, size);
        ctx_.rolling_key = operand_chain_.update_key(ctx_.rolling_key, decrypted);

        return decrypted;
    }

    uint8_t  read_u8()  { return static_cast<uint8_t>(read_operand(1)); }
    uint16_t read_u16() { return static_cast<uint16_t>(read_operand(2)); }
    uint32_t read_u32() { return static_cast<uint32_t>(read_operand(4)); }
    uint64_t read_u64() { return read_operand(8); }

private:
    VMContext&       ctx_;
    const DecryptChain& opcode_chain_;
    const DecryptChain& operand_chain_;
};

} // namespace vmp
