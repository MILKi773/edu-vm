import argparse
import yaml
from src.utils import pack_fields, mask
from pathlib import Path

def encode_instr(ir):
    cmd_name = ir["cmd"]
    if cmd_name == "LOAD_CONST":
        # Opcode 104, 7 bytes: bits 0-7=opcode, 8-29=constant (22 bits), 30-49=address (20 bits)
        A = 104
        B = int(ir["value"])  # constant
        C = int(ir["addr"])   # address where to store
        val = pack_fields([(A, 0, 8), (B, 8, 22), (C, 30, 20)])
        # Need 50 bits total, so 7 bytes (56 bits)
        return val.to_bytes(7, "little")
    elif cmd_name == "READ_MEM":
        # Opcode 209, 6 bytes: bits 0-7=opcode, 8-27=address (20 bits), 28-47=address (20 bits)
        A = 209
        B = int(ir["addr"])   # address for double indirect operand
        C = int(ir["dest"])   # address for result
        val = pack_fields([(A, 0, 8), (B, 8, 20), (C, 28, 20)])
        # Need 48 bits total, so 6 bytes
        return val.to_bytes(6, "little")
    elif cmd_name == "WRITE_MEM":
        # Opcode 26, 6 bytes: bits 0-7=opcode, 8-27=address (20 bits), 28-47=address (20 bits)
        A = 26
        B = int(ir["src_addr"])  # address for operand
        C = int(ir["dest_addr"]) # address for double indirect result
        val = pack_fields([(A, 0, 8), (B, 8, 20), (C, 28, 20)])
        # Need 48 bits total, so 6 bytes
        return val.to_bytes(6, "little")
    elif cmd_name == "BIN_OP":
        # Opcode 79, 9 bytes: bits 0-7=opcode, 8-27=result addr (20 bits), 28-47=op2 addr (20 bits), 48-67=op1 addr (20 bits)
        A = 79
        B = int(ir["result_addr"])  # result address
        C = int(ir["op2_addr"])     # second operand address
        D = int(ir["op1_addr"])     # first operand address
        val = pack_fields([(A, 0, 8), (B, 8, 20), (C, 28, 20), (D, 48, 20)])
        # Need 68 bits total, so 9 bytes (72 bits)
        return val.to_bytes(9, "little")
    else:
        raise ValueError(f"Unknown IR command: {cmd_name}")

def parse_yaml(path):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    with open(p, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or "program" not in data:
        raise ValueError("YAML must contain top-level 'program' list")
    return data["program"]

def to_ir(yaml_program):
    ir = []
    for idx, instr in enumerate(yaml_program):
        cmd = instr.get("cmd")
        if cmd == "LOAD_CONST":
            if "value" not in instr:
                raise ValueError(f"LOAD_CONST missing 'value' field at instr {idx}")
            # Поддержка обоих форматов: 'addr' (новый) и 'reg' (старый для обратной совместимости)
            addr = instr.get("addr") or instr.get("reg")
            if addr is None:
                raise ValueError(f"LOAD_CONST missing 'addr' or 'reg' field at instr {idx}")
            ir.append({"cmd":"LOAD_CONST", "addr":int(addr), "value":int(instr["value"])})
        elif cmd == "READ_MEM":
            # Новый формат: addr (для двойной косвенной адресации) и dest (адрес результата)
            # Старый формат: reg (регистр назначения) и addr (адрес памяти)
            if "addr" in instr and "dest" in instr:
                # Новый формат
                ir.append({"cmd":"READ_MEM", "addr":int(instr["addr"]), "dest":int(instr["dest"])})
            elif "reg" in instr and "addr" in instr:
                # Старый формат: используем addr как адрес для двойной косвенной адресации,
                # и reg как адрес результата (для обратной совместимости)
                ir.append({"cmd":"READ_MEM", "addr":int(instr["addr"]), "dest":int(instr["reg"])})
            else:
                raise ValueError(f"READ_MEM missing required fields at instr {idx}")
        elif cmd == "WRITE_MEM":
            # Новый формат: src_addr и dest_addr
            # Старый формат: offset/addr и src_reg
            if "src_addr" in instr and "dest_addr" in instr:
                # Новый формат
                ir.append({"cmd":"WRITE_MEM", "src_addr":int(instr["src_addr"]), "dest_addr":int(instr["dest_addr"])})
            elif ("offset" in instr or "addr" in instr) and "src_reg" in instr:
                # Старый формат: используем offset/addr как src_addr,
                # и src_reg как dest_addr (для обратной совместимости)
                src_addr = int(instr.get("offset") or instr.get("addr"))
                ir.append({"cmd":"WRITE_MEM", "src_addr":src_addr, "dest_addr":int(instr["src_reg"])})
            else:
                raise ValueError(f"WRITE_MEM missing required fields at instr {idx}")
        elif cmd == "BIN_OP":
            if "result_addr" not in instr or "op1_addr" not in instr or "op2_addr" not in instr:
                raise ValueError(f"BIN_OP missing fields at instr {idx}")
            ir.append({"cmd":"BIN_OP", "result_addr":int(instr["result_addr"]), "op1_addr":int(instr["op1_addr"]), "op2_addr":int(instr["op2_addr"])})
        else:
            raise ValueError(f"Unknown command '{cmd}' at index {idx}")
    return ir

def assemble(ir_list):
    binary = bytearray()
    for instr in ir_list:
        binary.extend(encode_instr(instr))
    return binary

def fmt_bytes_hex(b: bytes):
    return ", ".join(f"0x{x:02X}" for x in b)

def main():
    parser = argparse.ArgumentParser(description="Assembler for UVM Variant #9 (YAML -> BIN)")
    parser.add_argument("input", help="Path to YAML input (program)")
    parser.add_argument("output", help="Path to binary output")
    parser.add_argument("--test", action="store_true", help="Test mode: print IR and bytes")
    args = parser.parse_args()

    prog = parse_yaml(args.input)
    ir = to_ir(prog)

    if args.test:
        print("=== IR ===")
        for i, instr in enumerate(ir):
            print(f"{i:03}: {instr}")
    binary = assemble(ir)
    with open(args.output, "wb") as f:
        f.write(binary)

    print(f"Wrote binary '{args.output}' ({len(binary)} bytes).")

    if args.test:
        print("Bytes (hex):")
        print(fmt_bytes_hex(binary))

if __name__ == "__main__":
    main()
