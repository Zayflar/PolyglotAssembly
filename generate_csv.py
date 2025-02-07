import csv

def convert_to_csv(input_files, output_file):
    with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Hexa", "Instruction", "Type"])
        
        for file, instr_type in input_files:
            with open(file, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split(" : ")
                    if len(parts) == 2:
                        hex_value, instruction = parts
                        writer.writerow([hex_value, instruction, instr_type])


input_files = [("1byte.txt", "1-byte"), ("2byte.txt", "2-byte")]


convert_to_csv(input_files, "x86_instructions.csv")

