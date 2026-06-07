#pragma once

// ============================================================================
// Bytecode Encoder
// ============================================================================
// Encodes VM instructions into encrypted bytecode. In real VMProtect, this
// is done by the compiler/packer. We need it to create test cases.
//
// The encryption mirrors the decryption in BytecodeReader, but applies
// transforms in reverse order.
// ============================================================================

#include "vmp_core.h"
#include "operand_decrypt.h"
#include <vector>

namespace vmp {

    class BytecodeEncoder {
    public:
        BytecodeEncoder(const DecryptChain& opcode_chain,
            const DecryptChain& operand_chain,
            uint64_t initial_key)
            : opcode_chain_(opcode_chain)
            , operand_chain_(operand_chain)
            , rolling_key_(initial_key) {
        }

        // Encode a 1-byte opcode
        void emit_opcode(uint8_t opcode) {
            uint64_t encrypted = opcode_chain_.encrypt(opcode, rolling_key_, 1);
            rolling_key_ = opcode_chain_.update_key(rolling_key_, opcode);
            bytecode_.push_back(static_cast<uint8_t>(encrypted));
        }

        // Encode an 8-bit operand
        void emit_u8(uint8_t val) {
            uint64_t encrypted = operand_chain_.encrypt(val, rolling_key_, 1);
            rolling_key_ = operand_chain_.update_key(rolling_key_, val);
            bytecode_.push_back(static_cast<uint8_t>(encrypted));
        }

        // Encode a 16-bit operand
        void emit_u16(uint16_t val) {
            uint64_t encrypted = operand_chain_.encrypt(val, rolling_key_, 2);
            rolling_key_ = operand_chain_.update_key(rolling_key_, val);
            bytecode_.push_back(static_cast<uint8_t>(encrypted & 0xFF));
            bytecode_.push_back(static_cast<uint8_t>((encrypted >> 8) & 0xFF));
        }

        // Encode a 32-bit operand
        void emit_u32(uint32_t val) {
            uint64_t encrypted = operand_chain_.encrypt(val, rolling_key_, 4);
            rolling_key_ = operand_chain_.update_key(rolling_key_, val);
            for (int i = 0; i < 4; ++i) {
                bytecode_.push_back(static_cast<uint8_t>((encrypted >> (i * 8)) & 0xFF));
            }
        }

        // Encode a 64-bit operand
        void emit_u64(uint64_t val) {
            uint64_t encrypted = operand_chain_.encrypt(val, rolling_key_, 8);
            rolling_key_ = operand_chain_.update_key(rolling_key_, val);
            for (int i = 0; i < 8; ++i) {
                bytecode_.push_back(static_cast<uint8_t>((encrypted >> (i * 8)) & 0xFF));
            }
        }

        // Emit a complete PUSH IMM64 instruction
        void emit_push_imm64(uint64_t val) {
            emit_opcode(OP_PUSH_IMM64);
            emit_u64(val);
        }

        // Emit a complete PUSH IMM32 instruction
        void emit_push_imm32(uint32_t val) {
            emit_opcode(OP_PUSH_IMM32);
            emit_u32(val);
        }

        // Emit SREG instruction
        void emit_sreg(uint8_t reg_idx) {
            emit_opcode(OP_SREG);
            emit_u8(reg_idx);
        }

        // Emit LREG instruction
        void emit_lreg(uint8_t reg_idx) {
            emit_opcode(OP_LREG);
            emit_u8(reg_idx);
        }

        // Emit a simple opcode (no operands)
        void emit_simple(uint8_t opcode) {
            emit_opcode(opcode);
        }

        // Emit arithmetic operation (no operands, operates on stack)
        void emit_arith(uint8_t opcode) {
            emit_opcode(opcode);
        }

        // Emit JCC with condition and offset
        void emit_jcc(uint8_t cc, int32_t offset) {
            emit_opcode(OP_JCC);
            emit_u8(cc);
            emit_u32(static_cast<uint32_t>(offset));
        }

        // Emit JMP with offset
        void emit_jmp(int32_t offset) {
            emit_opcode(OP_JMP);
            emit_u32(static_cast<uint32_t>(offset));
        }

        const std::vector<uint8_t>& bytecode() const { return bytecode_; }

        // Get current offset (for computing jump targets)
        size_t offset() const { return bytecode_.size(); }

        // Patch a 32-bit value at a specific offset
        void patch_u32(size_t pos, uint32_t val) {
            for (int i = 0; i < 4; ++i) {
                bytecode_[pos + i] = static_cast<uint8_t>((val >> (i * 8)) & 0xFF);
            }
        }

    private:
        const DecryptChain& opcode_chain_;
        const DecryptChain& operand_chain_;
        uint64_t            rolling_key_;
        std::vector<uint8_t> bytecode_;
    };

} // namespace vmp

