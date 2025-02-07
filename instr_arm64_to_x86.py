import random
from capstone import *

# Check for ARM64 support
try:
    cs_arm64 = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    print("ARM64 is supported")
except Exception as e:
    print("ARM64 is not supported:", e)

# Check for x86 support
try:
    cs_x86 = Cs(CS_ARCH_X86, CS_MODE_32)
    print("x86 is supported")
except Exception as e:
    print("x86 is not supported:", e)


def generate_random_instruction_arm64():
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    
    while True:
        instruction_bytes = random.getrandbits(32).to_bytes(4, byteorder='little')
        disasm = list(md.disasm(instruction_bytes, 0x1000))
        if disasm: 
            instruction_bits = []
            for byte in instruction_bytes:
                for i in range(8):
                    instruction_bits.append((byte >> (7 - i)) & 1)
            return instruction_bits



def is_x86_instruction(instruction_bits):
    byte_value = 0
    for i, bit in enumerate(instruction_bits):
        byte_value |= (bit << (7 - (i % 8)))
        if (i + 1) % 8 == 0:
            instruction_bytes = byte_value.to_bytes(1, byteorder='little')
            byte_value = 0
    instruction_bytes = bytes(instruction_bytes) 

    md = Cs(CS_ARCH_X86, CS_MODE_64)

    disasm = list(md.disasm(instruction_bytes, 0x1000))
    
    if disasm:
        return f"{disasm[0].mnemonic} {disasm[0].op_str}"
    else:
        return False


def is_arm_instruction(instruction_bits):

    byte_value = 0
    instruction_bytes = []
    for i, bit in enumerate(instruction_bits):
        byte_value |= (bit << (7 - (i % 8)))
        if (i + 1) % 8 == 0:
            instruction_bytes.append(byte_value)
            byte_value = 0
    instruction_bytes = bytes(instruction_bytes) 

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    disasm = list(md.disasm(instruction_bytes, 0x1000))
    
    if disasm:
        return f"{disasm[0].mnemonic} {disasm[0].op_str}"
    else:
        return False



def test_arm_instruction_to_x86_nop():
    for i in range(1000):
        arm64_instruction_bits = generate_random_instruction_arm64()
        result = is_x86_instruction(arm64_instruction_bits)
        if result and result[0:3].lower() == "nop":
            print("ARM64 :", is_arm_instruction(arm64_instruction_bits))
            print("X86 :", result)
            print("\n")


test_arm_instruction_to_x86_nop()