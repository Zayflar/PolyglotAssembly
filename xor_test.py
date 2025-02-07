import capstone


md_arm64 = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md_x86 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


registers = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15"]


eor_instructions = []
for rd in registers:
    for rn in registers:
        for rm in registers:
            eor_instructions.append(f"EOR {rd}, {rn}, {rm}")

for instruction in eor_instructions:
    print(f"Testing ARM64: {instruction}")
    


    if encoded:
        arm_hex = encoded.bytes.hex()
        print(f"-> ARM64 Hex: {arm_hex}")

        disasm_x86 = list(md_x86.disasm(bytes.fromhex(arm_hex), 0))
        if disasm_x86:
            print(f"-> x86 Instruction: {disasm_x86[0].mnemonic} {disasm_x86[0].op_str}")
        else:
            print("-> No valid x86 instruction found.")

    print("-" * 40)

# Modif -> rajouter la convert