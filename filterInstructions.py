import csv
import re
import multiprocessing

def classify_argument(arg, is_arm=True):
    if not arg or arg.strip() == "":
        return ""
    
    arg = arg.strip().lower()

    arm64_registers = ["xzr", "wzr", "sp", "pc", "zr", "spsel", "nzcv", "fpcr", "daif", "fpsr", "svcr", "pan", "currentel",
    "uao"]

    arm64_suffixes = [
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
    ]


    arm64_operators = ["add", "sub", "mul", "madd", "msub", "mulh", "udiv", "sdiv", "abs", "and", "orr", 
    "eor", "bic", "mvn", "cmp", "cmn", "tst", "lsl", "lsr", "asr", "ror", "clz", "mov", "neg", "rev", "sxtw",
     "inch", "fmov", "msr", "mrs", "ldp", "stp", "bfi", "b", "tbnz", "tbz", "lslv", "stlxr", "msl", "rndr", "vl8", "vl4",
     "pow2", "cigsw", "cigvac"]


    x64_registers = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
        "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
        "rip", "eflags", "ah", "bh", "ch", "dh",
        "es", "cs", "ss", "ds", "fs", "gs",
        "cf", "pf", "af", "zf", "sf", "tf", "if", "df", "of",
        "iopl", "nt", "rf", "vm", "ac", "vif", "vip", "id"
    ]





    #R : registers
    #M : memory
    #I : Immediate
    #S : Shift
    #SF : Suffixe
    #O : Operators
    #P : Prefetch

    if is_arm:
        if re.match(r'^(ps|pl|pldl)', arg):
            return "P"

        if re.match(r'^c[0-9]+$', arg):
            return "R"
        if re.match(r'^trc.*', arg):
            return "R"
        if re.match(r'^za', arg):
            return "R"
        if re.match(r'x[0-9]{1,2}.*', arg):
            return "R"
        if re.match(r'w[0-9]{1,2}.*', arg):
            return "R"
        if re.match(r'v[0-9]{1,2}.*', arg):
            return "R"
        if re.match(r'q[0-9]{1,2}.*', arg):
            return "R"
        if re.match(r'd[0-9]{1,2}.*', arg):
            return "R"
        if re.match(r's[0-9]{1,2}.*', arg):
            return "R"
        if re.match(r'h[0-9]{1,2}.*', arg):
            return "R"
        if re.match(r'b[0-9]{1,2}.*', arg):
            return "R"
        if re.match(r's[0-9]{1,2}.*', arg):
            return "R"
        if re.match(r'p[0-9]{1,2}.*', arg):
            return "R"
        if re.match(r'z[0-9]{1,2}.*', arg):
            return "R"
        if re.match(r'\bvl(?:\d+)?\b', arg):
            return "I"

        if arg.startswith('{'):
            return "R"

        if '[' in arg or ']' in arg:
            return "M"
        if '_' in arg:
            return "R"
        base_reg = re.split(r'[\.\/\[]', arg)[0]
        if base_reg in arm64_registers:
            return "R"

        if re.match(r'^w', arg):
            return "R"

        if arg in arm64_suffixes:
            return "SF"

        if re.search(r'(' + '|'.join(re.escape(s) for s in arm64_operators) + r')', arg):
            return "O"
        if re.match(r'.*vae.*', arg):
            return "O"   
        if re.match(r'.*(alle|ipas|iall|civac|vaae|aside|rpaos).*',arg):
            return "I"          
        if re.match(r'\bvl(?:\d+)?\b', arg):
            return "I"
        if re.match(r'^#', arg): 
            return "I"
        if re.match(r'\b(?:zva|cvac|cvap|civac|ivac|cvau|ivau|ialluis|iallu|isw|sw|cisw)\b', arg):
            return "I"


    else:
        if arg in x64_registers:
            return "R"
        if re.match(r'xmm[0-9]{1,2}.*', arg):
            return "R"
        if re.match(r'bnd[0-9].*', arg):
            return "R"
        if re.match(r'^st\([0-7]\)$', arg):
            return "R"
        if re.match(r'.*(ptr )?(cs|ds|es|ss|fs|gs):.*', arg):
            return "R"
        if re.match(r'(ptr \[).*', arg):
            return "M"
        if re.match(r'\[.*\]', arg):
            return "R"
        if re.match(r'^\s*(byte|word|dword|qword|ds)', arg):
            return "R"
        if re.match(r'^mm[0-9]', arg):
            return "R"
        if re.match(r'^dr[0-9].*', arg):
            return "R"

        if re.match(r'^cr[0-9].*', arg):
            return "R"
        if re.match(r'^(xmmword|tbyte|xword).*', arg):
            return "M"


    if re.match(r'^#?-?0x[0-9a-f]+$', arg) or re.match(r'^#?-?\d+$', arg):
        return "I"
    if re.match(r'^(lsl|lsr|asr|ror)\s+#', arg):
        return "S"


    return "UNK"

def clean_arg(arg):
    arg = arg.strip()
    return "" if arg == "NO_ARG" else arg

def process_row(row):
    try:
        row = [r.strip() for r in row]
        while len(row) < 9:
            row.append("")

        hex_val   = row[0]
        arm_instr = row[1]
        arm_args  = [clean_arg(row[2]), clean_arg(row[3]), clean_arg(row[4])]
        x64_instr = row[5]
        x64_args  = [clean_arg(row[6]), clean_arg(row[7]), clean_arg(row[8])]

        arm_types = [classify_argument(arg, True) for arg in arm_args]
        x64_types = [classify_argument(arg, False) for arg in x64_args]

        if arm_instr == "inch":
            return [hex_val, arm_instr] + ["R", "X", "X"] + [x64_instr] + x64_types

        return [hex_val, arm_instr] + arm_types + [x64_instr] + x64_types
    except Exception as e:
        print(f"Error processing row: {row}, error: {e}")
        return [row[0], row[1], "UNK", "UNK", "UNK", row[5], "UNK", "UNK", "UNK"]

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

def process_csv(input_file, output_file, chunk_size=1000, max_processes=32):
    lock = multiprocessing.Lock()

    def worker(chunk, output_file, lock):
        processed_chunk = process_chunk(chunk)
        with lock:
            with open(output_file, 'a', newline='') as outfile:
                writer = csv.writer(outfile, delimiter='|')
                writer.writerows(processed_chunk)

    with open(output_file, 'w', newline='') as outfile:
        writer = csv.writer(outfile, delimiter='|')
        with open(input_file, 'r') as infile:
            reader = csv.reader(infile, delimiter='|')
            headers = next(reader)
            writer.writerow(headers)

    processes = []
    for chunk in read_csv_in_chunks(input_file, chunk_size):
        if len(processes) >= max_processes:
            for p in processes:
                p.join()
            processes = []

        p = multiprocessing.Process(target=worker, args=(chunk, output_file, lock))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

if __name__ == "__main__":
    input_file = 'processed_csv/4Bytes_processed_1.csv'
    output_file = '4Bytes_filtered_1.csv'
    process_csv(input_file, output_file, chunk_size=1000, max_processes=32)
