import multiprocessing
import csv

NUMBER_OF_PROCESSES = 12
START_HEXA = 0x00000000
END_HEXA = 0x7FFFFFFF + 1

def write_hexa_range_to_csv(start, count, filename):
    with open(filename, 'a', newline='') as file:
        writer = csv.writer(file, delimiter='|')
        for i in range(start, start + count):
            hexa_value = hex(i)
            writer.writerow([hexa_value, '', '', '', '', '', '', '', ''])

def main():
    chunk_size = (END_HEXA - START_HEXA) // NUMBER_OF_PROCESSES
    ranges = [(START_HEXA + i * chunk_size, chunk_size) for i in range(NUMBER_OF_PROCESSES)]

    with open('4Bytes.csv', 'w', newline='') as file:
        writer = csv.writer(file, delimiter='|')
        writer.writerow(["oppcode", "ARM64_operand", "ARM_arg1", "ARM_arg2", "ARM_arg3", 
                        "X64_operand", "X64_arg1", "X64_arg2", "X64_arg3"])

    processes = []
    for start, count in ranges:
        p = multiprocessing.Process(target=write_hexa_range_to_csv, 
                                  args=(start, count, '4Bytes.csv'))
        processes.append(p)
        p.start()
ent
    for p in processes:
        p.join()

if __name__ == '__main__':
    main()