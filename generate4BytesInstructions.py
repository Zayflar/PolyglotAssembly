import csv
from capstone import *

arm64_disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
x64_disassembler = Cs(CS_ARCH_X86, CS_MODE_64)


#No argument -> NO_ARG


def disassemble_instruction(disassembler, hexa_value):
    try:
        binary_code = bytes.fromhex(hexa_value[2:])
        for instr in disassembler.disasm(binary_code, 0x1000):
            return instr.mnemonic, instr.op_str
        return "", ""
    except:
        return "", ""


def format_arguments(ops):
    argument = ops.split(', ') if ops else []
    while len(argument) < 3:
        argument.append("NO_ARG")
    return argument[:3]


with open('4Bytes.csv', 'r') as infile, open('4Bytes_filled.csv', 'w', newline='') as outfile:
    reader = csv.reader(infile, delimiter='|')
    writer = csv.writer(outfile, delimiter='|')
    
    headers = next(reader)
    writer.writerow(headers)
    
    for row in reader:
        hexa_value = row[0]
        arm_mnemonic, arm_ops = disassemble_instruction(arm64_disassembler, hexa_value) or ("", "")
        x64_mnemonic, x64_ops = disassemble_instruction(x64_disassembler, hexa_value) or ("", "")
        
        if arm_mnemonic and x64_mnemonic:
            row[1] = arm_mnemonic
            row[2:5] = format_arguments(arm_ops)
            row[5] = x64_mnemonic
            row[6:9] = format_arguments(x64_ops)
            writer.writerow(row)
