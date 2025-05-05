import csv
from collections import defaultdict

def count_duplicates(input_file, output_file):
    counts = defaultdict(int)
    examples = {}

    with open(input_file, 'r') as f:
        reader = csv.reader(f, delimiter='|')
        for row in reader:
            if not row:
                continue
            key = tuple(row[1:])
            counts[key] += 1
            if key not in examples:
                examples[key] = row[1:]

    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f, delimiter='|')
        for key, count in counts.items():
            writer.writerow([count] + list(examples[key]))

input_file = '4Bytes_filtered.csv'
output_file = '4Bytes_count_duplicates.csv'
count_duplicates(input_file, output_file)