#pragma once
// ============================================================================
// Bytecode Encoder - Creates encrypted bytecode for testing
// ============================================================================
// This simulates what VMProtect's compiler/packer does at protect time.
// It encrypts opcodes and operands using the rolling key mechanism.
// ============================================================================

#include "vmp_core.h"
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

        void emit_opcode(uint8_t opcode) {
            uint64_t enc = opcode_chain_.encrypt(opcode, rolling_key_, 1);
            rolling_key_ = opcode_chain_.update_key(rolling_key_, opcode);
            bytecode_.push_back((uint8_t)enc);
        }

        void emit_u8(uint8_t val) {
            uint64_t enc = operand_chain_.encrypt(val, rolling_key_, 1);
            rolling_key_ = operand_chain_.update_key(rolling_key_, val);
            bytecode_.push_back((uint8_t)enc);
        }

        void emit_u16(uint16_t val) {
            uint64_t enc = operand_chain_.encrypt(val, rolling_key_, 2);
            rolling_key_ = operand_chain_.update_key(rolling_key_, val);
            bytecode_.push_back((uint8_t)(enc & 0xFF));
            bytecode_.push_back((uint8_t)((enc >> 8) & 0xFF));
        }

        void emit_u32(uint32_t val) {
            uint64_t enc = operand_chain_.encrypt(val, rolling_key_, 4);
            rolling_key_ = operand_chain_.update_key(rolling_key_, val);
            for (int i = 0; i < 4; ++i)
                bytecode_.push_back((uint8_t)((enc >> (i * 8)) & 0xFF));
        }

        void emit_u64(uint64_t val) {
            uint64_t enc = operand_chain_.encrypt(val, rolling_key_, 8);
            rolling_key_ = operand_chain_.update_key(rolling_key_, val);
            for (int i = 0; i < 8; ++i)
                bytecode_.push_back((uint8_t)((enc >> (i * 8)) & 0xFF));
        }

        // Convenience emitters
        void emit_push_imm64(uint64_t val) { emit_opcode(OP_PUSH_IMM64); emit_u64(val); }
        void emit_push_imm32(uint32_t val) { emit_opcode(OP_PUSH_IMM32); emit_u32(val); }
        void emit_sreg(uint8_t idx) { emit_opcode(OP_SREG); emit_u8(idx); }
        void emit_lreg(uint8_t idx) { emit_opcode(OP_LREG); emit_u8(idx); }
        void emit_simple(uint8_t opcode) { emit_opcode(opcode); }
        void emit_arith(uint8_t opcode) { emit_opcode(opcode); }

        void emit_jcc(uint8_t cc, int32_t offset) {
            emit_opcode(OP_JCC); emit_u8(cc); emit_u32((uint32_t)offset);
        }
        void emit_jmp(int32_t offset) { emit_opcode(OP_JMP); emit_u32((uint32_t)offset); }
        void emit_call(int32_t offset) { emit_opcode(OP_CALL); emit_u32((uint32_t)offset); }
        void emit_ret() { emit_opcode(OP_RET); }

        const std::vector<uint8_t>& bytecode() const { return bytecode_; }
        size_t offset() const { return bytecode_.size(); }

    private:
        const DecryptChain& opcode_chain_;
        const DecryptChain& operand_chain_;
        uint64_t            rolling_key_;
        std::vector<uint8_t> bytecode_;
    };

} // namespace vmp
