import csv
import re
import multiprocessing

def classify_argument(arg, is_arm=True):
    if arg == "NO_ARG":
        return ""
    
    arg = arg.strip()
    
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
    
    if not is_arm:
        ptr_match = re.match(r'^\s*(byte|word|dword|qword)\s+ptr\s*\[([^\]]+)\]', arg, re.IGNORECASE)
        if ptr_match:
            inner_arg = ptr_match.group(2)
            if inner_arg.lower() in x64_registers:
                return "R"
    
    if is_arm and arg.lower() in arm64_registers:
        return "R"
    elif not is_arm and arg.lower() in x64_registers:
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
    if not ops or ops.strip() == "":
        return ["NO_ARG", "NO_ARG", "NO_ARG"]
    
    arguments = []
    current_arg = ""
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
            arguments.append(current_arg.strip())
            current_arg = ""
        else:
            current_arg += char
    
    if current_arg:
        arguments.append(current_arg.strip())
    
    while len(arguments) < 3:
        arguments.append("NO_ARG")
    
    return arguments[:3]

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

def worker(input_queue, output_queue):
    while True:
        chunk = input_queue.get()
        if chunk is None:
            break
        result = process_chunk(chunk)
        output_queue.put(result)

def process_csv(input_file, output_file, chunk_size=1000, num_processes=12):
    input_queue = multiprocessing.Queue()
    output_queue = multiprocessing.Queue()

    processes = [
        multiprocessing.Process(target=worker, args=(input_queue, output_queue))
        for _ in range(num_processes)
    ]

    for p in processes:
        p.start()

    with open(output_file, 'w', newline='') as outfile:
        writer = csv.writer(outfile, delimiter='|')
        writer.writerow([
            "ARM64_operand", "ARM_arg1", "ARM_arg2", "ARM_arg3",
            "X64_operand", "X64_arg1", "X64_arg2", "X64_arg3"
        ])

        for chunk in read_csv_in_chunks(input_file, chunk_size):
            input_queue.put(chunk)

        for _ in range(num_processes):
            input_queue.put(None)

        processed = 0
        while processed < num_processes:
            result = output_queue.get()
            if result == "DONE":
                processed += 1
                continue
            for row in result:
                writer.writerow(row)

    for p in processes:
        p.join()

if __name__ == "__main__":
    input_file = 'processed_csv/4Bytes_processed.csv'
    output_file = '4Bytes_filtered.csv'
    process_csv(input_file, output_file, chunk_size=10000, num_processes=32)