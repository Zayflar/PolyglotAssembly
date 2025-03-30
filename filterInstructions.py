import csv
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

def classify_argument(arg, is_arm=True):
    if arg == "NO_ARG":
        return ""
    
    arm64_registers = {
        *[f"x{i}" for i in range(31)], "xzr",
        *[f"w{i}" for i in range(31)], "wzr",
        *[f"v{i}" for i in range(32)], *[f"q{i}" for i in range(32)],
        *[f"d{i}" for i in range(32)],
        *[f"s{i}" for i in range(32)],
        *[f"h{i}" for i in range(32)],
        *[f"b{i}" for i in range(32)],
        "sp", "pc",
    }
    
    x64_registers = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
        "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
        "rip", "eflags",
    }
    
    if is_arm and arg.lower() in arm64_registers:
        return "R"
    elif not is_arm and (arg.lower() in x64_registers or re.match(r'^(byte|word|dword|qword) ptr \[[a-z0-9_+\-]+\]$', arg, re.IGNORECASE)):
        return "R"
    
    if re.match(r'^#-?0x[0-9a-fA-F]+$', arg) or re.match(r'^#-?\d+$', arg):
        return "I"
    
    if '[' in arg and ']' in arg:
        return "M"
    
    if '{' in arg and '}' in arg:
        return "L"
    
    if re.match(r'^(lsl|lsr|asr|ror)\s+#', arg, re.IGNORECASE):
        return "S"
    
    if re.match(r'^p\d+/[zm]$', arg, re.IGNORECASE):
        return "P"
    
    return "UNK"

def format_arguments(ops):
    return ops.split(', ') if ops else []

def process_row(row):
    arm_operand = row[1]
    arm_args = [classify_argument(arg, is_arm=True) for arg in format_arguments(row[2])]
    x64_operand = row[5]
    x64_args = [classify_argument(arg, is_arm=False) for arg in format_arguments(row[6])]
    return [arm_operand] + arm_args + [x64_operand] + x64_args

def process_chunk(chunk):
    return [process_row(row) for row in chunk]

def read_csv_in_chunks(file_path, chunk_size):
    with open(file_path, 'r') as file:
        reader = csv.reader(file, delimiter='|')
        headers = next(reader)
        chunk = []
        for row in reader:
            chunk.append(row)
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk

def process_csv(input_file, output_file, chunk_size=1000, max_threads=12):
    with open(output_file, 'w', newline='') as outfile:
        writer = csv.writer(outfile, delimiter='|')
        with open(input_file, 'r') as infile:
            reader = csv.reader(infile, delimiter='|')
            headers = next(reader)
            new_headers = ["ARM64_operand"] + [f"ARM_arg{i+1}" for i in range(10)] + ["X64_operand"] + [f"X64_arg{i+1}" for i in range(10)]
            writer.writerow(new_headers)
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for chunk in read_csv_in_chunks(input_file, chunk_size):
                future = executor.submit(process_chunk, chunk)
                futures.append(future)
                for future in as_completed(futures):
                    for processed_row in future.result():
                        writer.writerow(processed_row)
                    futures.remove(future)

if __name__ == "__main__":
    input_file = '4Bytes_filled.csv'
    output_file = '4Bytes_processed.csv'
    process_csv(input_file, output_file, chunk_size=1000, max_threads=12)
