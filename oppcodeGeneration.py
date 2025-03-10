import concurrent.futures
import csv

NUMBER_OF_THREADS = 8
START_HEXA = 0x0FFFFFFF
END_HEXA = (0xFFFFFFFF + 1) // 128

def generate_hexa_range(start, count):
    return [hex(i) for i in range(start, start + count)]

def main():
    chunk_size = END_HEXA // NUMBER_OF_THREADS
    ranges = [(START_HEXA + i * chunk_size, chunk_size) for i in range(NUMBER_OF_THREADS)]

    hexa_numbers = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=NUMBER_OF_THREADS) as executor:
        results = list(executor.map(lambda args: generate_hexa_range(*args), ranges))
        for result in results:
            hexa_numbers.extend(result)

    with open('4Bytes.csv', 'w', newline='') as file:
        writer = csv.writer(file, delimiter='|')
        writer.writerow(["oppcode", "ARM64_operand", "ARM_arg1", "ARM_arg2", "ARM_arg3", "X64_operand", "X64_arg1", "X64_arg2", "X64_arg3"])
        for hexa_value in hexa_numbers:
            writer.writerow([hexa_value, '', '', '', '', '', '', '', ''])
    
    return 0

if __name__ == "__main__":
    main()