import argparse
import csv
import math
from src.utils import mask
from pathlib import Path

def get_instr_size(opcode):
    """Определяет размер инструкции по опкоду"""
    if opcode == 104:  # LOAD_CONST
        return 7
    elif opcode == 209:  # READ_MEM
        return 6
    elif opcode == 26:  # WRITE_MEM
        return 6
    elif opcode == 79:  # BIN_OP
        return 9
    else:
        raise ValueError(f"Unknown opcode: {opcode}")

def run_binary_bytes(code_bytes, data_mem_size=1<<16, regs_count=32):
    """Альтернативная функция для запуска из байтов (без файла)"""
    # Инициализация состояния
    state = {
        "regs": [0]*regs_count,
        "data_mem": [0]*data_mem_size
    }

    # Выполнение инструкций последовательно
    pc = 0
    code_len = len(code_bytes)
    while pc < code_len:
        if pc >= code_len:
            break
        opcode = code_bytes[pc]  # First byte is opcode
        instr_size = get_instr_size(opcode)
        if pc + instr_size > code_len:
            break
        instr_bytes = code_bytes[pc:pc+instr_size]
        decode_and_execute_one(instr_bytes, state)
        pc += instr_size

    return state

def decode_and_execute_one(instr_bytes, state):
    """
    instr_bytes: bytes of instruction (variable length)
    state: dict with keys:
       regs: list of int (registers)
       data_mem: list of ints (word-addressable)
    Returns None.
    """
    cmd_int = int.from_bytes(instr_bytes, "little")
    A = cmd_int & mask(8)  # Opcode is 8 bits (bits 0-7)
    
    if A == 104:  # LOAD_CONST - 7 bytes
        # Bits 0-7: opcode, 8-29: constant (22 bits), 30-49: address (20 bits)
        B = (cmd_int >> 8) & mask(22)   # constant
        C = (cmd_int >> 30) & mask(20)  # destination address
        state["data_mem"][C] = B
    elif A == 209:  # READ_MEM - 6 bytes
        # Bits 0-7: opcode, 8-27: address (20 bits), 28-47: address (20 bits)
        B = (cmd_int >> 8) & mask(20)   # address for double indirect operand
        C = (cmd_int >> 28) & mask(20)  # address for result
        # Operand: value in memory at address which is value in memory at address B
        indirect_addr = state["data_mem"][B]
        operand_value = state["data_mem"][indirect_addr]
        # Result: value in memory at address C
        state["data_mem"][C] = operand_value
    elif A == 26:  # WRITE_MEM - 6 bytes
        # Bits 0-7: opcode, 8-27: address (20 bits), 28-47: address (20 bits)
        B = (cmd_int >> 8) & mask(20)   # address for operand
        C = (cmd_int >> 28) & mask(20)  # address for double indirect result
        # Operand: value in memory at address B
        operand_value = state["data_mem"][B]
        # Result: value in memory at address which is value in memory at address C
        indirect_addr = state["data_mem"][C]
        state["data_mem"][indirect_addr] = operand_value
    elif A == 79:  # BIN_OP - 9 bytes
        # Bits 0-7: opcode, 8-27: result addr (20 bits), 28-47: op2 addr (20 bits), 48-67: op1 addr (20 bits)
        B = (cmd_int >> 8) & mask(20)   # result address
        C = (cmd_int >> 28) & mask(20)  # second operand address
        D = (cmd_int >> 48) & mask(20)  # first operand address
        op1 = state["data_mem"][D]
        op2 = state["data_mem"][C]
        # Default operation: addition (can be extended)
        result = op1 + op2
        state["data_mem"][B] = result
    else:
        raise ValueError(f"Unknown opcode A={A}")

def run_program(bin_path, data_mem_size=1<<16, regs_count=32, dump_csv=None, dump_range=None):
    # read binary
    p = Path(bin_path)
    if not p.exists():
        raise FileNotFoundError(bin_path)
    with open(p, "rb") as f:
        code = f.read()

    # initialize state
    state = {
        "regs": [0]*regs_count,
        "data_mem": [0]*data_mem_size
    }

    # execute instructions sequentially
    pc = 0
    code_len = len(code)
    while pc < code_len:
        if pc >= code_len:
            break
        opcode = code[pc]  # First byte is opcode
        instr_size = get_instr_size(opcode)
        if pc + instr_size > code_len:
            break
        instr_bytes = code[pc:pc+instr_size]
        decode_and_execute_one(instr_bytes, state)
        pc += instr_size

    # dump CSV if requested
    if dump_csv is not None and dump_range is not None:
        start, end = dump_range
        with open(dump_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["address", "value"])
            if start < 0 or end >= data_mem_size:
                raise IndexError("Dump range out of bounds")
            for addr in range(start, end+1):
                writer.writerow([addr, state["data_mem"][addr]])
    return state

def parse_range(s):
    # format "start-end"
    if "-" not in s:
        raise argparse.ArgumentTypeError("Range must be start-end")
    a,b = s.split("-",1)
    return (int(a), int(b))

def main():
    parser = argparse.ArgumentParser(description="Interpreter for UVM Variant #9")
    parser.add_argument("binary", help="Path to binary program")
    parser.add_argument("dump_csv", help="Path to CSV dump file (address,value)")
    parser.add_argument("range", help="Memory dump range start-end (e.g. 100-220)")
    parser.add_argument("--mem-size", type=int, default=1<<16, help="Data memory size (words)")
    parser.add_argument("--regs", type=int, default=32, help="Number of registers")
    args = parser.parse_args()

    dump_range = parse_range(args.range)
    state = run_program(args.binary, data_mem_size=args.mem_size, regs_count=args.regs,
                        dump_csv=args.dump_csv, dump_range=dump_range)
    print("Program executed. Dump written to", args.dump_csv)

if __name__ == "__main__":
    main()
