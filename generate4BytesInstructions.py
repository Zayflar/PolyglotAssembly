import csv
from capstone import *
import multiprocessing

arm64_disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
x64_disassembler = Cs(CS_ARCH_X86, CS_MODE_64)

def disassemble_instruction(disassembler, hexa_value):
    try:
        binary_code = bytes.fromhex(hexa_value[2:])
        for instr in disassembler.disasm(binary_code, 0x1000):
            return instr.mnemonic, instr.op_str
        return None, None
    except:
        return None, None

def format_arguments(ops):
    argument = ops.split(', ') if ops else []
    while len(argument) < 3:
        argument.append("NO_ARG")
    return argument[:3]

def process_row(row):
    hexa_value = row[0]
    arm_mnemonic, arm_ops = disassemble_instruction(arm64_disassembler, hexa_value)
    x64_mnemonic, x64_ops = disassemble_instruction(x64_disassembler, hexa_value)
    if arm_mnemonic is not None and x64_mnemonic is not None:
        row[1] = arm_mnemonic
        row[2:5] = format_arguments(arm_ops)
        row[5] = x64_mnemonic
        row[6:9] = format_arguments(x64_ops)
        return row
    return None

def process_chunk(chunk):
    return [row for row in (process_row(row) for row in chunk) if row is not None]

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

def process_csv(input_file, output_file, chunk_size=1000, max_processes=12):
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
    input_file = '4Bytes.csv'
    output_file = '4Bytes_processed.csv'
    process_csv(input_file, output_file, chunk_size=1000, max_processes=12)