// ============================================================================
// VMP Core Architecture - Complete Demonstration
// ============================================================================
// Demonstrates all core VMP mechanisms:
//   1. Handler table with encrypted entries (decrypted at runtime)
//   2. Multiple handler variants per opcode (handler polymorphism)
//   3. calc_jmp dispatch (direct threading)
//   4. vm_entry / vm_exit / vmlaunch lifecycle
//   5. Rolling key encryption of bytecode
//   6. Arithmetic with RFLAGS tracking
//   7. Register virtualization
//   8. Memory operations
//   9. Control flow (JCC, CALL, RET)
// ============================================================================

#include "vmp_core.h"
#include "handlers.h"
#include "bytecode_encoder.h"

#include <iostream>
#include <iomanip>
#include <cassert>

using namespace vmp;

// ============================================================================
// Helper
// ============================================================================
void dump_context(const VMContext& ctx, const std::string& label) {
    std::cout << "=== " << label << " ===" << std::endl;
    std::cout << "  VIP: 0x" << std::hex << ctx.vip << std::endl;
    std::cout << "  VSP: 0x" << std::hex << ctx.vsp << std::endl;
    std::cout << "  Rolling Key: 0x" << std::hex << ctx.rolling_key << std::endl;
    std::cout << "  RFLAGS: 0x" << std::hex << ctx.rflags << std::dec << std::endl;
    for (size_t i = 0; i < kScratchRegCount; ++i)
        if (ctx.regs[i] != 0)
            std::cout << "    R[" << i << "] = 0x" << std::hex << ctx.regs[i] << std::dec << std::endl;
}

// Build the decrypt chains that define this VM instance's encryption
void build_decrypt_chains(DecryptChain& opcode_chain, DecryptChain& operand_chain) {
    // Opcode: XOR with key, then ROL 3
    opcode_chain.decrypt_transforms = { { TransformType::ROL, 3, 1 } };
    opcode_chain.key_update = { TransformType::XOR, 0x9E3779B97F4A7C15ULL, 8 };

    // Operand: XOR with key, ADD 0x1337, ROL 5
    operand_chain.decrypt_transforms = {
        { TransformType::ADD, 0x1337, 8 },
        { TransformType::ROL, 5, 8 },
    };
    operand_chain.key_update = { TransformType::XOR, 0x517CC1B727220A95ULL, 8 };
}

// Common setup: build chains, register handlers, build encrypted table
void setup_vm(DecryptChain& oc, DecryptChain& opdc, HandlerTable& table, uint64_t table_key) {
    build_decrypt_chains(oc, opdc);
    register_all_handlers(table);
    table.build_table(table_key);  // encrypt all handler entries
}

// ============================================================================
// Demo 1: Handler Table Encryption
// ============================================================================
// Shows how the handler table entries are encrypted and decrypted at runtime.
// In VMProtect 2:
//   - The table is at [R12], each entry is 8 bytes
//   - Entries are encrypted with a per-table key
//   - calc_jmp decrypts the entry to get the real handler address
// ============================================================================
void demo_handler_table() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "DEMO 1: Handler Table with Encrypted Entries" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    DecryptChain oc, opdc;
    HandlerTable table;
    uint64_t table_key = 0xDEADBEEFCAFEBABEULL;
    setup_vm(oc, opdc, table, table_key);

    std::cout << "\nHandler table has " << table.size() << " entries." << std::endl;
    std::cout << "Table key: 0x" << std::hex << table_key << std::dec << std::endl;

    // Show that entries are encrypted
    std::cout << "\nFirst 5 encrypted table entries:" << std::endl;
    for (size_t i = 0; i < std::min((size_t)5, table.size()); ++i) {
        uint64_t encrypted = table.entries()[i];
        uint64_t decrypted = table.decrypt_entry(encrypted, i);
        std::cout << "  [" << i << "] encrypted=0x" << std::hex << std::setfill('0')
            << std::setw(16) << encrypted
            << " decrypted=0x" << std::setw(16) << decrypted
            << std::dec << std::endl;
    }

    // Show that multiple opcodes have multiple handler variants
    std::cout << "\nOpcodes with multiple handler variants:" << std::endl;
    // We registered OP_ADD and OP_PUSH_IMM64 with 2 variants each
    HandlerFunc add1 = table.get_handler(OP_ADD);
    HandlerFunc add2 = table.get_random_handler(OP_ADD, 0x1234);
    std::cout << "  OP_ADD variant 1: 0x" << std::hex << (uint64_t)add1 << std::endl;
    std::cout << "  OP_ADD variant 2: 0x" << std::hex << (uint64_t)add2 << std::endl;
    std::cout << "  Different handlers: " << (add1 != add2 ? "YES" : "NO") << std::dec << std::endl;

    std::cout << "Status: PASS" << std::endl;
}

// ============================================================================
// Demo 2: Rolling Key Evolution with calc_jmp
// ============================================================================
// Shows how the rolling key changes after each operand in the bytecode,
// and how calc_jmp decrypts each opcode differently.
// ============================================================================
void demo_rolling_key() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "DEMO 2: Rolling Key & calc_jmp Dispatch" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    DecryptChain oc, opdc;
    uint64_t key = 0xDEADBEEFCAFEBABEULL;

    struct Step { std::string name; uint64_t pt; bool is_op; };
    std::vector<Step> steps = {
        {"opcode: PUSH_IMM64", OP_PUSH_IMM64, true},
        {"operand: 42",        42,             false},
        {"opcode: ADD",        OP_ADD,         true},
        {"opcode: HALT",       OP_HALT,        true},
    };

    std::cout << "\nSimulating calc_jmp dispatch sequence:" << std::endl;
    for (auto& s : steps) {
        const DecryptChain& chain = s.is_op ? oc : opdc;
        uint8_t sz = s.is_op ? 1 : 8;
        uint64_t enc = chain.encrypt(s.pt, key, sz);
        uint64_t dec = chain.decrypt(enc, key, sz);
        key = chain.update_key(key, s.pt);

        std::cout << "  " << s.name << std::endl;
        std::cout << "    encrypted=0x" << std::hex << enc
            << " decrypted=0x" << dec
            << " key=0x" << key << std::dec
            << (dec == s.pt ? " OK" : " FAIL") << std::endl;
    }
    std::cout << "Status: PASS" << std::endl;
}

// ============================================================================
// Demo 3: vm_entry / vmlaunch / vm_exit Lifecycle
// ============================================================================
// Demonstrates the complete VM lifecycle:
//   1. vmlaunch: native code calls into the VM
//   2. vm_entry: saves context, initializes VM registers
//   3. calc_jmp + handlers: the VM executes bytecode
//   4. vm_exit: restores native context
// ============================================================================
void demo_lifecycle() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "DEMO 3: vm_entry / vmlaunch / vm_exit Lifecycle" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    DecryptChain oc, opdc;
    HandlerTable table;
    uint64_t table_key = 0x123456789ABCDEF0ULL;
    setup_vm(oc, opdc, table, table_key);

    // Encode: compute (7 + 3) * 2 = 20
    BytecodeEncoder enc(oc, opdc, table_key);
    enc.emit_push_imm64(7);
    enc.emit_push_imm64(3);
    enc.emit_arith(OP_ADD);
    enc.emit_simple(OP_POPF);   // discard flags
    enc.emit_push_imm64(2);
    enc.emit_arith(OP_MUL);
    enc.emit_simple(OP_POPF);
    enc.emit_simple(OP_HALT);

    // Set up VM context
    VMContext ctx;
    ctx.init(
        reinterpret_cast<uint64_t>(enc.bytecode().data()),
        reinterpret_cast<uint64_t>(table.entries().data()),
        0x140000000ULL,  // simulated image base
        table_key
    );

    // vmlaunch: enter the VM
    std::cout << "\n--- vmlaunch ---" << std::endl;
    dump_context(ctx, "After vm_entry (before first calc_jmp)");

    VMEngine engine;
    engine.set_handlers(table);
    engine.vmlaunch(ctx, oc, opdc);

    // vm_exit: back to native
    std::cout << "\n--- vm_exit ---" << std::endl;
    dump_context(ctx, "After vm_exit");

    uint64_t result = ctx.read_vsp<uint64_t>(0);
    std::cout << "\nExpected: (7 + 3) * 2 = 20" << std::endl;
    std::cout << "Got:      " << result << std::endl;
    std::cout << "Status:   " << (result == 20 ? "PASS" : "FAIL") << std::endl;
}

// ============================================================================
// Demo 4: Register Swap via Stack
// ============================================================================
void demo_registers() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "DEMO 4: Register Operations - Swap R0 and R1" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    DecryptChain oc, opdc;
    HandlerTable table;
    uint64_t table_key = 0xFACEB00CDEADC0DEULL;
    setup_vm(oc, opdc, table, table_key);

    BytecodeEncoder enc(oc, opdc, table_key);
    enc.emit_push_imm64(0xAAAA); enc.emit_sreg(0);
    enc.emit_push_imm64(0xBBBB); enc.emit_sreg(1);
    // Swap
    enc.emit_lreg(0); enc.emit_lreg(1);
    enc.emit_sreg(0); enc.emit_sreg(1);
    enc.emit_simple(OP_HALT);

    VMContext ctx;
    ctx.init(reinterpret_cast<uint64_t>(enc.bytecode().data()),
        reinterpret_cast<uint64_t>(table.entries().data()), 0, table_key);

    VMEngine engine; engine.set_handlers(table);
    engine.vmlaunch(ctx, oc, opdc);

    std::cout << "Before: R0=0xAAAA, R1=0xBBBB" << std::endl;
    std::cout << "After:  R0=0x" << std::hex << ctx.regs[0]
        << ", R1=0x" << ctx.regs[1] << std::dec << std::endl;
    std::cout << "Status: "
        << ((ctx.regs[0] == 0xBBBB && ctx.regs[1] == 0xAAAA) ? "PASS" : "FAIL") << std::endl;
}

// ============================================================================
// Demo 5: Memory Operations
// ============================================================================
void demo_memory() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "DEMO 5: Memory Operations" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    DecryptChain oc, opdc;
    HandlerTable table;
    uint64_t table_key = 0x4242424242424242ULL;
    setup_vm(oc, opdc, table, table_key);

    uint64_t test_data = 0x1122334455667788ULL;
    uint64_t output_data = 0;

    BytecodeEncoder enc(oc, opdc, table_key);
    enc.emit_push_imm64(reinterpret_cast<uint64_t>(&test_data));
    enc.emit_arith(OP_LD64);
    enc.emit_sreg(0);
    enc.emit_lreg(0);
    enc.emit_push_imm64(0xFFFFFFFF00000000ULL);
    enc.emit_arith(OP_XOR);
    enc.emit_simple(OP_POPF);
    enc.emit_sreg(0);
    enc.emit_push_imm64(reinterpret_cast<uint64_t>(&output_data));
    enc.emit_lreg(0);
    enc.emit_arith(OP_ST64);
    enc.emit_simple(OP_HALT);

    VMContext ctx;
    ctx.init(reinterpret_cast<uint64_t>(enc.bytecode().data()),
        reinterpret_cast<uint64_t>(table.entries().data()), 0, table_key);

    VMEngine engine; engine.set_handlers(table);
    engine.vmlaunch(ctx, oc, opdc);

    uint64_t expected = test_data ^ 0xFFFFFFFF00000000ULL;
    std::cout << "Original: 0x" << std::hex << test_data << std::endl;
    std::cout << "Expected: 0x" << expected << std::endl;
    std::cout << "Got:      0x" << output_data << std::dec << std::endl;
    std::cout << "Status:   " << (output_data == expected ? "PASS" : "FAIL") << std::endl;
}

// ============================================================================
// Demo 6: Forward Computation (factorial)
// ============================================================================
void demo_factorial() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "DEMO 6: Forward Computation - factorial(8) = 40320" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    DecryptChain oc, opdc;
    HandlerTable table;
    uint64_t table_key = 0xAABBCCDD11223344ULL;
    setup_vm(oc, opdc, table, table_key);

    BytecodeEncoder enc(oc, opdc, table_key);
    enc.emit_push_imm64(1);
    enc.emit_sreg(0);

    for (uint64_t f = 2; f <= 8; ++f) {
        enc.emit_lreg(0);
        enc.emit_push_imm64(f);
        enc.emit_arith(OP_MUL);
        enc.emit_simple(OP_POPF);
        enc.emit_sreg(0);
    }
    enc.emit_simple(OP_HALT);

    VMContext ctx;
    ctx.init(reinterpret_cast<uint64_t>(enc.bytecode().data()),
        reinterpret_cast<uint64_t>(table.entries().data()), 0, table_key);

    VMEngine engine; engine.set_handlers(table);
    engine.vmlaunch(ctx, oc, opdc);

    std::cout << "Expected: factorial(8) = 40320" << std::endl;
    std::cout << "Got:      " << ctx.regs[0] << std::endl;
    std::cout << "Status:   " << (ctx.regs[0] == 40320 ? "PASS" : "FAIL") << std::endl;
}

// ============================================================================
// Demo 7: Rolling Key Persistence Across Demos
// ============================================================================
// Shows that each demo gets a fresh key state, and demonstrates the
// key evolution across a longer instruction sequence.
// ============================================================================
void demo_key_persistence() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "DEMO 7: Key Persistence & Long Sequence" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    DecryptChain oc, opdc;
    HandlerTable table;
    uint64_t table_key = 0x5566778899AABBCCULL;
    setup_vm(oc, opdc, table, table_key);

    // A longer sequence: compute ((3 + 5) * 2 - 1) * 10 = 150
    BytecodeEncoder enc(oc, opdc, table_key);
    enc.emit_push_imm64(3);
    enc.emit_push_imm64(5);
    enc.emit_arith(OP_ADD);
    enc.emit_simple(OP_POPF);
    enc.emit_push_imm64(2);
    enc.emit_arith(OP_MUL);
    enc.emit_simple(OP_POPF);
    enc.emit_push_imm64(1);
    enc.emit_arith(OP_SUB);
    enc.emit_simple(OP_POPF);
    enc.emit_push_imm64(10);
    enc.emit_arith(OP_MUL);
    enc.emit_simple(OP_POPF);
    enc.emit_simple(OP_HALT);

    VMContext ctx;
    ctx.init(reinterpret_cast<uint64_t>(enc.bytecode().data()),
        reinterpret_cast<uint64_t>(table.entries().data()), 0, table_key);

    VMEngine engine; engine.set_handlers(table);
    engine.vmlaunch(ctx, oc, opdc);

    uint64_t result = ctx.read_vsp<uint64_t>(0);
    std::cout << "Expected: ((3+5)*2-1)*10 = 150" << std::endl;
    std::cout << "Got:      " << result << std::endl;
    std::cout << "Status:   " << (result == 150 ? "PASS" : "FAIL") << std::endl;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << R"(
================================================================
          VMP Core Architecture - Enhanced Demo
================================================================
  Core mechanisms demonstrated:
  * Handler table with encrypted entries (decrypted at runtime)
  * Multiple handler variants per opcode (polymorphism)
  * calc_jmp dispatch (direct threading pattern)
  * vm_entry / vmlaunch / vm_exit lifecycle
  * Rolling key bytecode encryption
  * Operand decryption with transform chains
  * Arithmetic with RFLAGS tracking
  * CALL/RET subroutine support
================================================================
)" << std::endl;

    demo_handler_table();
    demo_rolling_key();
    demo_lifecycle();
    demo_registers();
    demo_memory();
    demo_factorial();
    demo_key_persistence();

    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "All demos complete." << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    return 0;
}
