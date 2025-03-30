import csv
import re
import multiprocessing

def classify_argument(arg, is_arm=True):
    if arg == "NO_ARG":
        return ""
    
    arg = arg.strip().lower()
    
    arm64_registers = {
        *[f"x{i}" for i in range(31)], "xzr",
        *[f"w{i}" for i in range(31)], "wzr",
        *[f"v{i}" for i in range(32)], *[f"q{i}" for i in range(32)],
        *[f"d{i}" for i in range(32)],
        *[f"s{i}" for i in range(32)],
        *[f"h{i}" for i in range(32)],
        *[f"b{i}" for i in range(32)],
        "sp", "pc", "zr",
        *[f"z{i}" for i in range(32)],
        *[f"p{i}" for i in range(16)]
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
        base_reg = re.split(r'[\.\/\[]', arg)[0]
        if base_reg in arm64_registers:
            return "R"
        if re.match(r'^p\d+/[zm]$', arg):
            return "P"
    else:
        if arg in x64_registers:
            return "R"
        ptr_match = re.match(r'^\s*(byte|word|dword|qword)\s+ptr\s*\[([^\]]+)\]', arg)
        if ptr_match and ptr_match.group(2).strip() in x64_registers:
            return "R"

    if re.match(r'^#-?0x[0-9a-f]+$', arg) or re.match(r'^#-?\d+$', arg):
        return "I"
    
    if '[' in arg and ']' in arg:
        return "M"
    
    if '{' in arg and '}' in arg:
        return "L"
    
    if re.match(r'^(lsl|lsr|asr|ror)\s+#', arg):
        return "S"
    
    return "UNK"

def format_arguments(ops):
    if not ops or not ops.strip():
        return ["NO_ARG"] * 3
    
    ops = ops.strip()
    arguments = []
    current = ""
    in_brackets = 0
    in_braces = 0
    
    for char in ops:
        if char == '[':
            in_brackets += 1
        elif char == ']':
            in_brackets -= 1
        elif char == '{':
            in_braces += 1
        elif char == '}':
            in_braces -= 1
        
        if char == ',' and in_brackets == 0 and in_braces == 0:
            arguments.append(current.strip())
            current = ""
            if len(arguments) == 2:
                break
        else:
            current += char
    
    if current:
        arguments.append(current.strip())
    
    while len(arguments) < 3:
        arguments.append("NO_ARG")
    
    return arguments[:3]

def process_row(row):
    try:
        hex_val = row[0]
        arm_op = row[1]
        arm_ops = row[2]
        x64_op = row[5]
        x64_ops = row[6]
        
        arm_args = format_arguments(arm_ops)
        x64_args = format_arguments(x64_ops)
        
        arm_class = [classify_argument(arg, True) for arg in arm_args]
        x64_class = [classify_argument(arg, False) for arg in x64_args]
        
        return [hex_val, arm_op] + arm_class + [x64_op] + x64_class
    except:
        return []

def process_chunk(chunk):
    return [row for row in (process_row(r) for r in chunk) if row]

def worker(input_q, output_q):
    while True:
        chunk = input_q.get()
        if chunk == "STOP":
            output_q.put("DONE")
            break
        output_q.put(process_chunk(chunk))

def process_csv(input_file, output_file, chunk_size=10000, num_proc=32):
    manager = multiprocessing.Manager()
    input_q = manager.Queue()
    output_q = manager.Queue()

    procs = [multiprocessing.Process(target=worker, args=(input_q, output_q)) for _ in range(num_proc)]
    for p in procs:
        p.start()

    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f, delimiter='|')
        writer.writerow(["Hexa_Value", "ARM64_operand", "ARM_arg1", "ARM_arg2", "ARM_arg3",
                        "X64_operand", "X64_arg1", "X64_arg2", "X64_arg3"])

        def write_results():
            active = num_proc
            while active > 0:
                res = output_q.get()
                if res == "DONE":
                    active -= 1
                else:
                    writer.writerows(res)

        writer_proc = multiprocessing.Process(target=write_results)
        writer_proc.start()

        with open(input_file, 'r') as infile:
            reader = csv.reader(infile, delimiter='|')
            next(reader)
            chunk = []
            for row in reader:
                chunk.append(row)
                if len(chunk) >= chunk_size:
                    input_q.put(chunk)
                    chunk = []
            if chunk:
                input_q.put(chunk)

        for _ in range(num_proc):
            input_q.put("STOP")

        writer_proc.join()

    for p in procs:
        p.join()

if __name__ == "__main__":
    process_csv('processed_csv/4Bytes_processed.csv', '4Bytes_filtered.csv')