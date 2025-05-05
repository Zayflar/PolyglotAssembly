import csv
import multiprocessing
from collections import defaultdict
import os

def process_chunk(chunk):
    counts = defaultdict(int)
    for row in chunk:
        counts[tuple(row[1:])] += 1
    return counts

def process_file(input_file, output_file, chunk_size=300000):
    temp_file = output_file + '.tmp'
    if os.path.exists(temp_file):
        os.remove(temp_file)
    if os.path.exists(output_file):
        os.remove(output_file)

    def merge_results(result):
        existing = defaultdict(int)
        if os.path.exists(temp_file):
            with open(temp_file, 'r', buffering=1<<24) as f:
                reader = csv.reader(f, delimiter='|')
                existing.update({tuple(row[1:]): int(row[0]) for row in reader if row})
        
        for k, v in result.items():
            existing[k] += v
            
        with open(temp_file, 'w', buffering=1<<24, newline='') as f:
            writer = csv.writer(f, delimiter='|')
            writer.writerows([v] + list(k) for k, v in existing.items())

    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count() * 2)
    results_queue = []

    with open(input_file, 'r', buffering=1<<24) as f:
        reader = csv.reader(f, delimiter='|')
        chunk = []
        for i, row in enumerate(reader):
            chunk.append(row)
            if len(chunk) >= chunk_size:
                results_queue.append(pool.apply_async(process_chunk, (chunk,), callback=merge_results))
                chunk = []
                if i % (chunk_size * 10) == 0:
                    [r.wait() for r in results_queue]
                    results_queue = []
        
        if chunk:
            pool.apply_async(process_chunk, (chunk,), callback=merge_results)

    pool.close()
    pool.join()
    os.replace(temp_file, output_file)

input_file = '4Bytes_filtered.csv'
output_file = '4Bytes_count_duplicates.csv'
process_file(input_file, output_file)