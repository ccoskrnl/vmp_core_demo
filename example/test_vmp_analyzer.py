import struct
import logging
import pefile
import os
from typing import Dict, Optional
from triton import TritonContext, ARCH, Instruction, MemoryAccess, EXCEPTION, CALLBACK, MODE, OPERAND, OPCODE

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
# logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

def load_target_to_memory(file_path: str, dump_load_base: int = 0) -> tuple[bytes, int]:
    """
    通用装载器：智能识别 EXE 文件或原始 Memory Dump，并将其转换为展平的内存映像。

    Returns:
        tuple: (展平后的完整内存字节, 加载基址 ImageBase)
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target file not found: {file_path}")

    with open(file_path, 'rb') as f:
        header = f.read(2)

    # 1. 处理 PE 文件 (.exe / .dll)
    if header == b'MZ':
        logging.info("[*] Detected PE format. Simulating OS loader to map sections...")
        pe = pefile.PE(file_path)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        size_of_image = pe.OPTIONAL_HEADER.SizeOfImage

        # 创建一个足够大的空字节数组，模拟该进程的整个虚拟内存空间
        mapped_memory = bytearray(size_of_image)

        # 将 PE 头复制到内存（通常占用前 0x1000 字节）
        header_size = pe.OPTIONAL_HEADER.SizeOfHeaders
        with open(file_path, 'rb') as f:
            mapped_memory[:header_size] = f.read(header_size)

        # 遍历所有节区并按照 VirtualAddress 展开
        for section in pe.sections:
            if section.SizeOfRawData == 0:
                continue

            v_addr = section.VirtualAddress
            r_addr = section.PointerToRawData
            r_size = section.SizeOfRawData

            # 将文件中的节区数据拷贝到模拟内存的对应虚拟地址偏移处
            with open(file_path, 'rb') as f:
                f.seek(r_addr)
                mapped_memory[v_addr: v_addr + r_size] = f.read(r_size)

            logging.info(f"    -> Mapped {section.Name.decode('utf-8').strip(chr(0))} at offset {hex(v_addr)}")

        return bytes(mapped_memory), image_base

    # 2. 处理原始 Memory Dump (.bin)
    else:
        logging.info("[*] Detected Raw Memory Dump. Loading as-is...")
        if dump_load_base == 0:
            raise ValueError("A valid dump_load_base must be provided for raw memory dumps.")

        with open(file_path, 'rb') as f:
            mapped_memory = f.read()

        return mapped_memory, dump_load_base

class VMPEntryAnalyzer:
    def __init__(self, dump_file: str, load_base: int, memory_dump: bytes):
        self.ctx = TritonContext()
        self.ctx.setArchitecture(ARCH.X86_64)

        self.ctx.setMode(MODE.ALIGNED_MEMORY, False)
        self.ctx.setMode(MODE.AST_OPTIMIZATIONS, True)
        self.ctx.setMode(MODE.CONSTANT_FOLDING, True)

        self.load_base = load_base
        self.memory_dump = memory_dump

        # 符号变量出生地追踪字典
        self.symvar_trace: Dict[str, dict] = {}
        # 用于在回调中暂存当前正在处理的指令对象
        self.current_inst: Optional[Instruction] = None
        # 手动补丁内存池
        self.manual_patches: Dict[int, int] = {}

        self.ctx.addCallback(CALLBACK.GET_CONCRETE_MEMORY_VALUE, self._on_unmapped_memory_read)
        self.ctx.addCallback(CALLBACK.SET_CONCRETE_MEMORY_VALUE, self._on_memory_write_audit)

    def _read_memory(self, addr: int, size: int) -> bytes:
        """从 Dump 中读取字节码"""
        offset = addr - self.load_base
        if offset < 0 or offset + size > len(self.memory_dump):
            raise ValueError(f"Address {hex(addr)} is out of bounds.")
        return self.memory_dump[offset: offset + size]

    def patch_memory(self, addr: int, data: bytes):
        """记录手动补丁的内存，并同步到 Triton，防止被回调覆盖"""
        # self.manual_patches[addr] = data
        self.ctx.setConcreteMemoryAreaValue(addr, data)

    def _on_memory_write_audit(self, ctx: TritonContext, mem: MemoryAccess, value: int):
        """
        当程序遇到 push 或任何内存写入指令时，Triton 会在实际修改内存前触发此函数。
        """
        addr = mem.getAddress()
        size = mem.getSize()

        # 将写入的具体数值(int) 准确转化为小端序字节数组(bytes)
        written_bytes = value.to_bytes(size, byteorder='little')

        # 记录或追加到我们的手动/影子内存池中
        # 如果连续写入，这里会覆盖或新建对应地址的字节快照
        for i, b in enumerate(written_bytes):
            self.manual_patches[addr + i] = int(b)

        # 打印写入审计日志
        if self.current_inst:
            logging.debug(f"[Audit Write] PC: {hex(self.current_inst.getAddress())} | "
                          f"Addr: {hex(addr)} ({size} bytes) = {hex(value)} | "
                          f"Inst: {self.current_inst.getDisassembly()}")

    def _on_unmapped_memory_read(self, ctx: TritonContext, mem: MemoryAccess):
        """处理模拟执行中对未知内存的读取：将其符号化"""
        addr = mem.getAddress()
        size = mem.getSize()

        # 1. 检查该地址是否落在 PE 文件内存镜像范围内 (.data, .vmp0 等)
        offset = addr - self.load_base
        if 0 <= offset and (offset + size) <= len(self.memory_dump):
            real_bytes = self.memory_dump[offset: offset + size]
            value = int.from_bytes(real_bytes, byteorder='little')
            hex_str = " ".join(f"{b:02X}" for b in real_bytes)
            logging.debug(f"[PE READ] Engine requested {hex(addr)} ({size} bytes) -> Returned from PE: [{hex_str}] = {hex(value)}")
            # 直接返回 PE 中的真实物理数据，引擎会将其作为常量处理，绝不符号化！
            ctx.setConcreteMemoryAreaValue(addr, real_bytes)
            return value

        # 2. 检查是否命中了我们手动注入的数据
        has_all_bytes = True
        extracted_bytes = bytearray()
        for i in range(size):
            if (addr + i) in self.manual_patches:
                extracted_bytes.append(self.manual_patches[addr + i])
            else:
                has_all_bytes = False
                break

        if has_all_bytes:
            return int.from_bytes(extracted_bytes, byteorder='little')

        current_pc = ctx.getConcreteRegisterValue(self.ctx.registers.rip)
        sym_var = ctx.symbolizeMemory(mem)
        sym_name = sym_var.getName()
        sym_var.setComment(f"sym_mem_{hex(addr)}")

        # 从暂存的当前指令中提取字符串与硬编码
        if self.current_inst and self.current_inst.getAddress() == current_pc:
            disasm = self.current_inst.getDisassembly()
            # 将 bytes 转换为易读的十六进制大写字符串，例如 "48 8B 05"
            opcodes = " ".join(f"{b:02X}" for b in self.current_inst.getOpcode())
        else:
            disasm = "Unknown Mnemonic"
            opcodes = "Unknown Opcodes"

        self.symvar_trace[sym_name] = {
            "trigger_pc": hex(current_pc),
            "memory_addr": hex(addr),
            "size": size,
            "disasm": disasm,  # 指令字符串信息
            "opcodes": opcodes  # 指令硬编码信息
        }


        logging.warning(f"Unmapped memory read at {hex(addr)} (size: {size}). Symbolizing it.")

        # 返回 0 作为具体值让引擎继续执行，但公式中会保留符号变量
        return 0

    def analyze_vm_entry(self, start_addr: int, end_addrs: set[int], target_regs: set[str]):
        pc = start_addr

        logging.info(f"Starting symbolic execution from {hex(start_addr)}...")

        # 初始化 RIP
        self.ctx.setConcreteRegisterValue(self.ctx.registers.rip, pc)

        instruction_count = 0
        while True:
            try:
                # 获取最大可能指令长度 (x86_64最长15字节)
                opcodes = self._read_memory(pc, 15)
            except ValueError as e:
                logging.error(f"Memory read error at {hex(pc)}: {e}")
                break

            # 包含边界指令

            inst = Instruction(pc, opcodes)

            # 在处理指令前，将当前指令对象挂载到类属性上，供回调函数读取
            self.current_inst = inst

            self.ctx.processing(inst)
            instruction_count += 1

            # 打印当前执行的指令
            logging.debug(f"{hex(inst.getAddress())}: {inst.getDisassembly()}")

            if pc in end_addrs:
                logging.info(f"[+] Execution reached inclusive end address: {hex(pc)}")
                break

            if inst.isBranch() and len(inst.getOperands()) > 0:
                first_operand = inst.getOperands()[0]
                # 检查指令类型是否为 JMP 且 操作数类型为寄存器
                if inst.getType() == OPCODE.X86.JMP and first_operand.getType() == OPERAND.REG:
                    logging.info(f"[+] Detected VMP Dispatcher indirect jump at {hex(pc)}: {inst.getDisassembly()}")
                    break

            # 获取下一条指令的地址
            pc = self.ctx.getConcreteRegisterValue(self.ctx.registers.rip)

            # 防止死循环或执行失控的保护机制
            if instruction_count > 10000:
                logging.warning("Execution limit reached. Possible infinite loop or complex obfuscation.")
                break

        logging.info(f"Execution finished. Total instructions processed: {instruction_count}")

        ast_ctx = self.ctx.getAstContext()
        formula_results = {}

        for reg_name in target_regs:
            # 动态获取寄存器对象
            try:
                target_reg = getattr(self.ctx.registers, reg_name)
            except AttributeError as e:
                logging.error(f"Invalid register name: {reg_name}")
                continue

            # 获取寄存器的 AST 节点
            reg_ast = self.ctx.getRegisterAst(target_reg)
            # 将深层引用的 AST 节点完全展开为具体的数学表达式
            unrolled_ast = ast_ctx.unroll(reg_ast)
            # 化简表达式
            simplified_ast = self.ctx.simplify(unrolled_ast)

            # 判断是否被完全具体化 (化简为常数)
            if not simplified_ast.isSymbolized():
                final_value = simplified_ast.evaluate()
                formula_results[reg_name] = f"[Constant] {hex(final_value)}"
            else:
                # 如果完全没有符号变量，说明它是一串可以被计算出确定值的常量树
                # evaluate() 会执行这棵树的数学运算，返回最终的整数结果
                final_value = simplified_ast.evaluate()
                final_value_str = f"{hex(final_value)}"
                formula_results[reg_name] = final_value_str

        return formula_results, self.symvar_trace

    def analyze_vm_step(self, target_regs: set[str]):
        instruction_count = 0
        next_handler_addr = 0

        # 此时的 PC 位于刚被 JMP 进来的 Handler 头部
        initial_rsi = self.ctx.getConcreteRegisterValue(self.ctx.registers.rsi)
        initial_rbp = self.ctx.getConcreteRegisterValue(self.ctx.registers.rbp)



        while True:
            pc = self.ctx.getConcreteRegisterValue(self.ctx.registers.rip)

            try:
                opcodes = self._read_memory(pc, 15)
            except ValueError:
                logging.error(f"Invaild Memory Address: {hex(pc)}")
                break

            inst = Instruction(pc, opcodes)

            self.ctx.processing(inst)
            instruction_count += 1

            # 打印当前执行的指令
            logging.debug(f"{hex(inst.getAddress())}: {inst.getDisassembly()}")

            self.current_inst = inst


            # [边界探测] 间接跳转 JMP REG
            if inst.isBranch() and inst.getType() == OPCODE.X86.JMP:
                operands = inst.getOperands()
                if len(operands) > 0 and operands[0].getType() == OPERAND.REG:
                    reg_name = operands[0].getName()
                    next_handler_addr = self.ctx.getConcreteRegisterValue(getattr(self.ctx.registers, reg_name))
                    break

            # 防止死循环或执行失控的保护机制
            if instruction_count > 10000:
                logging.error("Execution limit reached.")
                break

        final_rsi = self.ctx.getConcreteRegisterValue(self.ctx.registers.rsi)
        final_rbp = self.ctx.getConcreteRegisterValue(self.ctx.registers.rbp)

        vip_advanced = final_rsi - initial_rsi
        vsp_delta = final_rbp - initial_rbp


        fetched_opcodes = []
        if vip_advanced > 0:
            raw_bytes = self._read_memory(initial_rsi, vip_advanced)
            fetched_opcodes = [hex(b) for b in raw_bytes]


        # Heuristic Inference
        stack_action = "None"
        tos_semantics = "None"  # Top of Stack Semantics

        ast_ctx = self.ctx.getAstContext()

        if vsp_delta > 0:
            stack_action = f"POP {vsp_delta} bytes"
        elif vsp_delta < 0:
            push_size = abs(vsp_delta)
            stack_action = f"PUSH {push_size} bytes"

            # 提取刚刚被PUSH到栈顶的数据的AST公式
            try:
                # 假设压入的是 8 字节数据
                mem_access = MemoryAccess(final_rbp, push_size)
                mem_ast = self.ctx.getMemoryAst(mem_access)
                simplified_mem_ast = self.ctx.simplify(ast_ctx.unroll(mem_ast))

                if simplified_mem_ast.isSymbolized():
                    tos_semantics = f"[Formula] {str(simplified_mem_ast)}"
                else:
                    tos_semantics = f"[Constant] {hex(simplified_mem_ast.evaluate())}"

            except Exception as e:
                tos_semantics = "[Error computing TOS AST] {e}"

        # AST 提取
        results = { }
        ast_ctx = self.ctx.getAstContext()
        for reg_name in target_regs:
            try:
                reg = getattr(self.ctx.registers, reg_name)
                simplified_reg_ast = self.ctx.simplify(ast_ctx.unroll(self.ctx.getRegisterAst(reg)))

                if simplified_reg_ast.isSymbolized():
                    results[reg_name] = f"[Symbolic] {str(simplified_reg_ast)}"
                else:
                    results[reg_name] = f"[Constant] {hex(simplified_reg_ast.evaluate())}"
            except Exception as e:
                pass

        # 封装语义报告
        semantic_report = {
            "Instruction Count": instruction_count,
            "VIP Advanced (RSI)": f"+{vip_advanced} bytes",
            "Fetched Opcodes": fetched_opcodes,
            "VSP Delta": vsp_delta,
            "Virtual Stack (RBP)": stack_action,
            "Top of Stack (TOS)": tos_semantics,
            "Target Registers": results
        }

        return next_handler_addr, semantic_report


def classify_vmp_handler(report):
    try:
        # 强制转换为整数进行判断，去掉字符串带来的干扰
        vip = int(str(report["VIP Advanced (RSI)"]).replace('+', '').replace(' bytes', '').strip())
        vsp = int(str(report["VSP Delta"]).replace('+', '').replace(' bytes', '').strip())
    except ValueError:
        return "vParseError"

    if vip == 2 and vsp > 0: return "vPopReg"
    if vip == 2 and vsp < 0: return "vPushReg"
    if vip == 5 and vsp < 0: return "vPushImm32"
    if vip == 9 and vsp < 0: return "vPushImm64"
    if vip == 1 and vsp == 0: return "vStackModify"
    if vip == 1 and vsp > 0: return "vMath/Logic (Consume)"
    if vip == 1 and vsp < 0: return "vMath/Logic (Produce)"

    return f"vUnknown(VIP:{vip}, VSP:{vsp})"



VIP = 0
NATIVE_STACK_ADDR = 0
VM_HANDLER_TALBE = 0
ROLLING_DECRYPTION_KEY = 0

def vmp_analyzer(dump_file: str, load_base: int, memory_dump: bytes):

    # RSI is always used for the virtual instruction pointer. Operands are fetched from the address stored in RSI. The initial value loaded into RSI is done by vm_entry.
    # RBP is loaded with RSP prior to allocation of scratch registers. This brings us to RDI which contains scratch registers. The address in RDI is initialized as well in vm_entry and is set to an address landing inside of the native stack.
    # R12 is loaded with the linear virtual address of the vm handler table. This is done inside of vm_entry and throughout the entire duration of execution inside of the virtual machine R12 will contain this address.
    # R13 is loaded with the linear virtual address of the module base address inside of vm_entry and is not altered throughout execution inside of the virtual machine.
    # RBX is a very special register which contains the rolling decryption key. After every decryption of every operand of every virtual instruction RBX is updated by applying a transformation to it with the decrypted operand’s value.
    target_regs = {'rax', 'rcx', 'rsi', 'rbp', 'r12', 'r13', 'rbx'}

    analyzer = VMPEntryAnalyzer(dump_file, load_base, memory_dump)

    # VMP Entry的入口地址
    start_addr = actual_load_base + 0xA2A6

    # VMP Entry函数的三个结束地址
    end_addrs = {
        actual_load_base + 0x64FA,
        actual_load_base + 0x641D,
        actual_load_base + 0x8857,
    }

    STACK_BASE = 0x150000000
    analyzer.ctx.setConcreteRegisterValue(analyzer.ctx.registers.rsp, STACK_BASE)
    analyzer.ctx.setConcreteRegisterValue(analyzer.ctx.registers.rbp, STACK_BASE)

    # 手动内存补丁
    # key_bytes = struct.pack("<I", 0x6B912CE0)
    # analyzer.patch_memory(0x14ffffff8, key_bytes)

    initial_registers = {
        'rax': 0x0000000140001000,
        'rbx': 0x0000000000000000,
        'rcx': 0x00000000002FC000,
        'rsi': 0x0000000000000000,
        'rdi': 0x0000000000000000,
        'r8': 0x00000000002FC000,
        'r9': 0x0000000140001000,
        'r10': 0x0000000000000000,
        'r11': 0x0000000000000000,
        'r12': 0x0000000000000000,
        'r13': 0x0000000000000000,
        'r14': 0x0000000000000000,
        'r15': 0x0000000000000000,
        'rbp': 0x0000000000000000  # RBP 通常在进入前是 0 或原栈底
    }

    for reg_name, value in initial_registers.items():
        reg_obj = getattr(analyzer.ctx.registers, reg_name)
        analyzer.ctx.setConcreteRegisterValue(reg_obj, value)

    formula_results, trace = analyzer.analyze_vm_entry(start_addr, end_addrs, target_regs)

    # =========================================================
    # VMP 反汇编追踪启动
    # =========================================================
    handler_table = {}  # 维护的映射表：Handler Addr -> 语义
    virtual_inst_stream = []  # 存放最终的虚拟指令流

    current_handler = analyzer.ctx.getConcreteRegisterValue(analyzer.ctx.registers.rcx)

    print("\n" + "=" * 80)
    print("                [ VMP DECOMPILER ENGINE RUNNING ]")
    print("=" * 80)

    for step in range(50):
        print(f"[*] Tracing Step {step + 1} at Handler: {hex(current_handler)}")

        next_addr, report = analyzer.analyze_vm_step(target_regs)

        if next_addr == 0 or next_addr is None:
            print("[!] 追踪中断！")
            break

        vip_delta = report["VIP Advanced (RSI)"]
        vsp_delta = report["VSP Delta"]
        fetched = report["Fetched Opcodes"]
        tos = report["Top of Stack (TOS)"]

        # 1. 如果这个 Handler 是第一次遇到，加入映射表
        if current_handler not in handler_table:
            semantics = classify_vmp_handler(report)
            handler_table[current_handler] = semantics

        # 2. 格式化并加入指令流
        mnemonic = handler_table[current_handler]
        opcodes_str = " ".join(fetched) if fetched else "N/A"

        # 为了可读性，如果是 PUSH 操作，把压入的值放在操作数位置展示
        operand_hint = ""
        if "vPushImm" in mnemonic:
            operand_hint = f" ; Pushed: {tos}"
        elif "vMath/Logic (Produce)" in mnemonic:
            operand_hint = f" ; Formula: {tos}"

        stream_line = f"0x{current_handler:08X} | {mnemonic:<20} | Bytes: [{opcodes_str:<20}] {operand_hint}"
        virtual_inst_stream.append(stream_line)

        # 准备下一步
        current_handler = next_addr

    # =========================================================
    # 打印最终的反汇编结果与映射表
    # =========================================================
    print("\n" + "#" * 80)
    print(">>> HANDLER MAPPING TABLE <<<")
    print("#" * 80)
    for addr, sem in handler_table.items():
        print(f"Handler {hex(addr)} -> {sem}")

    print("\n" + "#" * 80)
    print(">>> VIRTUAL INSTRUCTION STREAM (IL) <<<")
    print("#" * 80)
    for i, line in enumerate(virtual_inst_stream):
        print(f"IL_{i:03d}: {line}")

if __name__ == '__main__':

    TARGET_FILE = "test.vmp.exe"
    DUMP_LOAD_BASE = 0x140000000

    memory_image, actual_load_base = load_target_to_memory(TARGET_FILE, DUMP_LOAD_BASE)
    logging.info(f"[+] Final Load Base: {hex(actual_load_base)}")
    logging.info(f"[+] Mapped Memory Size: {hex(len(memory_image))} bytes")


    vmp_analyzer(TARGET_FILE, actual_load_base, memory_image)

