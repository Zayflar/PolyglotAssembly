from capstone import *

def parse_assembly_file_with_capstone(file_path):
    instructions = []
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            try:
                instructions.append(line)
            except Exception as e:
                print(f"err: {line} | Error: {e}")

    return instructions

def query_instructions(instructions, mnemonic=None, dest_reg=None):
    results = []

    for instr in instructions:
        if mnemonic and not instr.split()[0] == mnemonic:
            continue
        if dest_reg and not instr.startswith(dest_reg):
            continue
        results.append(instr)

    return results

if __name__ == "__main__":
    file_path = "nop_ret_*.txt"
    instructions = parse_assembly_file_with_capstone(file_path)

    sub_instructions = query_instructions(instructions, mnemonic="sub")
    print("intsr :")
    for line in sub_instructions:
        print(line)

