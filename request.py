import pandas as pd
from capstone import *

def filter_instructions(register, num_bytes=None, csv_file="x86_instructions.csv"):
    df = pd.read_csv(csv_file)
    filtered = df[df["Instruction"].str.contains(register, case=False)] 
    if num_bytes is not None:
        filtered = filtered[filtered["Type"] == num_bytes] 
    return filtered["Hexa"].tolist()  


def filter_instructions_by_name(instructions_list, keyword):
    filtered_instructions = []
    for instruction in instructions_list:
        instruction_words = instruction.lower().split()
        if keyword.lower() in instruction_words:
            filtered_instructions.append(instruction)
    return filtered_instructions



def generate_2_combined_instructions(instr_list):
	result = []
	for i in range(len(instr_list)):
		for j in range(len(instr_list)):
			result.append(instr_list[i]+instr_list[j])
			result.append(instr_list[j]+instr_list[i])
	return result


def is_arm_instruction(instruction_hex):
    try:
        instruction_bytes = bytes.fromhex(instruction_hex)
    except ValueError:
        return "pas possible"
    
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    disasm = list(md.disasm(instruction_bytes, 0x1000))
    
    if disasm:
        return f"{disasm[0].mnemonic} {disasm[0].op_str}"
    else:
        return False


def generate_polyglot_instructions(csv_file="x86_instructions.csv", output_file="a_etudier.txt"):
    df = pd.read_csv(csv_file)
    ret_instruction = df[df["Instruction"].str.contains("ret", case=False, na=False)]
    if ret_instruction.empty:
        
        raise ValueError("Aucune instruction 'ret' trouvée dans le fichier CSV.")
    ret_hex = ret_instruction["Hexa"].iloc[0]
    one_byte_instructions = df[df["Type"] == "1-byte"]["Hexa"].tolist()
    two_byte_instructions = df[df["Type"] == "2-byte"]["Hexa"].tolist()
    combinations = []

    for b1 in one_byte_instructions:
        combinations.append(ret_hex + b1 + b1 + b1)
        for b2 in two_byte_instructions:
            combinations.append(ret_hex + b2 + b1)
            combinations.append(ret_hex + b1 + b2)

    arm64_instructions = []
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for combo in combinations:
        try:
            instruction_bytes = bytes.fromhex(combo)
            disasm = list(md.disasm(instruction_bytes, 0x1000))
            if disasm:
                arm64_instructions.append(f"{disasm[0].mnemonic} {disasm[0].op_str}")
        except ValueError:
            continue

    with open(output_file, "w") as f:
        f.write("\n".join(arm64_instructions))

    return arm64_instructions



def generate_arm64_instructions_for_x28(csv_file="x86_instructions.csv"):

    df = pd.read_csv(csv_file)
    one_byte_instructions = df[df["Type"] == "1-byte"]["Hexa"].tolist()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    for byte in one_byte_instructions:
        try:
            instruction_bytes = bytes.fromhex(byte)
            disasm = list(md.disasm(instruction_bytes, 0x1000))
            for insn in disasm:
                if "x28" in insn.op_str:
                    print(f"{insn.mnemonic} {insn.op_str}")
        except ValueError:
            continue



def main():
    csv_file = "x86_instructions.csv"
    output_file = "nop_ret_*.txt"

    try:
        polyglot_instructions = generate_polyglot_instructions(csv_file, output_file)
        print(f"{output_file}.")
    except ValueError as e:
        print(f"Erreur : {e}")
        return

    print("\nx28")
    try:
        generate_arm64_instructions_for_x28(csv_file)
    except Exception as e:
        print(f"Erreur lors de la recherche : {e}")

if __name__ == "__main__":
    main()

# register = input("Register: ")
# num_bytes = input("Number of Byts: ")
# num_bytes = str(num_bytes)+"-byte" if num_bytes else None
# result = filter_instructions(register, num_bytes)
# if result:
#     prelist = generate_2_combined_instructions(result)
#     arm_list = []
#     k=0
#     l=0
#     for i in range(len(prelist)):
#     	x = is_arm_instruction(prelist[i])
#     	l += 1
#     	if x:
#     		k += 1
#     		print(x)
#     		arm_list.append(x)
#     print("\n\n", k)
#     print("\n", l)

#     filtered_instructions = filter_instructions_by_name(arm_list, input("Arm instr :"))
#     print("\n".join(filtered_instructions))
# else:
#     print(f"No instruction'{register}' / {num_bytes}")