import csv
import multiprocessing
from collections import defaultdict

def process_chunk(chunk):
    local_counts = defaultdict(int)
    for row in chunk:
        key = tuple(row[1:]) 
        local_counts[key] += 1
    return local_counts

def merge_counts(counts, result):
    for key, count in result.items():
        counts[key] += count

def write_results(output_file, counts):
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f, delimiter='|')
        for pattern, count in counts.items():
            writer.writerow([count] + list(pattern))

def process_file(input_file, output_file, chunk_size=1000):
    manager = multiprocessing.Manager()
    counts = manager.dict()
    pool = multiprocessing.Pool()

    def callback(result):
        merge_counts(counts, result)

    with open(input_file, 'r') as f:
        reader = csv.reader(f, delimiter='|')
        chunk = []
        for row in reader:
            chunk.append(row)
            if len(chunk) >= chunk_size:
                pool.apply_async(process_chunk, args=(chunk,), callback=callback)
                chunk = []
        
        if chunk:
            pool.apply_async(process_chunk, args=(chunk,), callback=callback)

    pool.close()
    pool.join()
    write_results(output_file, dict(counts))

input_file = '4Bytes_filtered.csv'
output_file = '4Bytes_count_duplicates.csv'
process_file(input_file, output_file)