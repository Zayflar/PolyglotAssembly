import csv
import re
import multiprocessing
from multiprocessing import Pool, Manager

def classify_argument(arg, is_arm=True):
    if not arg or arg.strip() == "":
        return ""
    
    arg = arg.strip().lower()

    arm64_registers = {
        *[f"x{i}" for i in range(31)], "xzr",
        *[f"w{i}" for i in range(31)], "wzr",
        *[f"v{i}" for i in range(32)], *[f"q{i}" for i in range(32)],
        *[f"d{i}" for i in range(32)], *[f"s{i}" for i in range(32)],
        *[f"h{i}" for i in range(32)], *[f"b{i}" for i in range(32)],
        "sp", "pc", "zr",
        *[f"z{i}" for i in range(32)], *[f"p{i}" for i in range(16)]
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
        "rip", "eflags"
    }

    if is_arm:
        if arg.startswith('{') or arg.startswith('['):
            return "R"
        elif re.split(r'[\.\/\[]', arg)[0] in arm64_registers:
            return "R"
        elif re.match(r'^p\d+/[zm]$', arg):
            return "P"
        elif is_arm and re.match('^s', arg):
            return "S" 
        else: 
            pass

    else:
        if arg in x64_registers:
            return "R"
        elif re.match(r'^\s*(byte|word|dword|qword)\s+ptr\s*\[.*\]$', arg):
            return "R"
        elif '[' in arg and ']' in arg:
            return "M"
        else:
            pass

    if re.match(r'^#?-?0x[0-9a-f]+$', arg) or re.match(r'^#?-?\d+$', arg):
        return "I"

    if re.match(r'^(lsl|lsr|asr|ror)\s+#', arg):
        return "S"

    return "UNK"

def clean_arg(arg):
    return "" if arg == "NO_ARG" else arg.strip()

def process_row(row):
    try:
        row = [r.strip() for r in row]
        while len(row) < 9:
            row.append("")

        hex_val = row[0]
        arm_instr = row[1]
        arm_args = [clean_arg(row[2]), clean_arg(row[3]), clean_arg(row[4])]
        x64_instr = row[5]
        x64_args = [clean_arg(row[6]), clean_arg(row[7]), clean_arg(row[8])]

        arm_types = [classify_argument(arg, True) for arg in arm_args]
        x64_types = [classify_argument(arg, False) for arg in x64_args]

        return [hex_val, arm_instr] + arm_types + [x64_instr] + x64_types
    except Exception as e:
        print(f"Error processing row: {row}, error: {e}")
        return [row[0], row[1], "UNK", "UNK", "UNK", row[5], "UNK", "UNK", "UNK"]

def process_chunk(chunk):
    return [process_row(row) for row in chunk]

def reader(input_file, chunk_size=1000):
    with open(input_file, 'r') as fin:
        reader = csv.reader(fin, delimiter='|')
        next(reader)  # Skip header
        chunk = []
        for row in reader:
            chunk.append(row)
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk

def writer(output_file, queue):
    with open(output_file, 'w', newline='') as fout:
        writer = csv.writer(fout, delimiter='|')
        headers = ["oppcode", "ARM64_operand", "ARM_arg1", "ARM_arg2", "ARM_arg3",
                   "X64_operand", "X64_arg1", "X64_arg2", "X64_arg3"]
        writer.writerow(headers)
        
        while True:
            result = queue.get()
            if result == 'DONE':
                break
            writer.writerows(result)

def process_csv(input_file, output_file, num_workers=8, chunk_size=10000):
    manager = Manager()
    queue = manager.Queue()
    
    writer_pool = Pool(1)
    writer_pool.apply_async(writer, (output_file, queue))
    
    with Pool(num_workers) as pool:
        for chunk in reader(input_file, chunk_size):
            results = pool.map(process_row, chunk)
            queue.put(results)
    
    queue.put('DONE')
    writer_pool.close()
    writer_pool.join()

if __name__ == "__main__":
    process_csv("processed_csv/4Bytes_processed.csv", "4Bytes_filtered.csv", num_workers=8)