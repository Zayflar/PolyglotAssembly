import random
from capstone import *

LIST_1B = ["push rax", "push rcx", "push rdx", "push rbx", "push rsp", "push rbp", "push rsi", "push rdi", "pop rax", "pop rcx", "pop rdx", "pop rbx", "pop rsp", "pop rbp", "pop rsi", "pop rdi", "insb byte ptr [rdi], dx", "insd dword ptr [rdi], dx", "outsb dx, byte ptr [rsi]", "outsd dx, dword ptr [rsi]", "nop", "xchg ecx, eax", "xchg edx, eax", "xchg ebx, eax", "xchg esp, eax", "xchg ebp, eax", "xchg esi, eax", "xchg edi, eax", "cwde", "cdq", "wait", "pushfq", "popfq", "sahf", "lahf", "movsb byte ptr [rdi], byte ptr [rsi]", "movsd dword ptr [rdi], dword ptr [rsi]", "cmpsb byte ptr [rsi], byte ptr [rdi]", "cmpsd dword ptr [rsi], dword ptr [rdi]", "stosb byte ptr [rdi], al", "stosd dword ptr [rdi], eax", "lodsb al, byte ptr [rsi]", "lodsd eax, dword ptr [rsi]", "scasb al, byte ptr [rdi]", "scasd eax, dword ptr [rdi]", "ret", "leave", "retf", "int3", "iretd", "xlatb", "in al, dx", "in eax, dx", "out dx, al", "out dx, eax", "int1", "hlt", "cmc", "clc", "stc", "cli", "sti", "cld", "std"]

def hex_to_x86_instruction(hex_string):
    instruction_bytes = bytes.fromhex(hex_string)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    disasm = list(md.disasm(instruction_bytes, 0x1000))
    if disasm:
        result = []
        total_size = 0
        for insn in disasm:
            result.append(f"{insn.mnemonic} {insn.op_str}".strip())
            total_size += insn.size
        if result[0] in LIST_1B:
            return False
        # octest tous utilises ?
        if total_size < len(instruction_bytes):
            result.append("Invalid instruction")
            return False
        print("operandes : ", insn.op_str)
        return "\n        ".join(result)
    else:
        return False


def generate_all_x86_instructions(number_of_bytes):
    total_combinations = 16 ** (2 * number_of_bytes)

    for i in range(total_combinations):
        hex_code = f"{i:0{2 * number_of_bytes}x}"  
        result = hex_to_x86_instruction(hex_code)
        if result:  # Si instr valide
            print(f'"{result}"', end=', ')


generate_all_x86_instructions(2)
