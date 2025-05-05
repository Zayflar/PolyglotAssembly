import csv
import multiprocessing
from collections import defaultdict
import os

def process_chunk(chunk):
    counts = defaultdict(int)
    for row in chunk:
        key = tuple(row[1:])
        counts[key] += 1
    return dict(counts)

def process_file(input_file, output_file, chunk_size=300000):
    temp_file = output_file + '.tmp'
    if os.path.exists(temp_file):
        os.remove(temp_file)
    if os.path.exists(output_file):
        os.remove(output_file)

    def merge_results(result):
        existing = defaultdict(int)
        if os.path.exists(temp_file):
            with open(temp_file, 'r') as f:
                reader = csv.reader(f, delimiter='|')
                for row in reader:
                    if row:
                        existing[tuple(row[1:])] = int(row[0])
        for k, v in result.items():
            existing[k] += v
        with open(temp_file, 'w', newline='') as f:
            writer = csv.writer(f, delimiter='|')
            for k, v in existing.items():
                writer.writerow([v] + list(k))

    pool = multiprocessing.Pool()
    lock = multiprocessing.Lock()

    with open(input_file, 'r') as f:
        reader = csv.reader(f, delimiter='|')
        chunk = []
        for row in reader:
            chunk.append(row)
            if len(chunk) >= chunk_size:
                pool.apply_async(process_chunk, args=(chunk,), callback=merge_results)
                chunk = []
        if chunk:
            pool.apply_async(process_chunk, args=(chunk,), callback=merge_results)

    pool.close()
    pool.join()
    os.rename(temp_file, output_file)

input_file = '4Bytes_filtered.csv'
output_file = '4Bytes_count_duplicates.csv'
process_file(input_file, output_file)