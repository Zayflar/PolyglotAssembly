import csv
import multiprocessing
from collections import defaultdict

def process_chunk(chunk):
    local_counts = defaultdict(int)
    for row in chunk:
        key = tuple(row[1:])
        local_counts[key] += 1
    return local_counts

def process_file(input_file, output_file, chunk_size=1000, update_interval=100):
    manager = multiprocessing.Manager()
    counts = manager.dict()
    lock = multiprocessing.Lock()
    processed_chunks = 0
    
    def callback(result):
        nonlocal processed_chunks
        with lock:
            for key, count in result.items():
                counts[key] = counts.get(key, 0) + count
            processed_chunks += 1
            
            if processed_chunks % update_interval == 0:
                with open(output_file, 'w', newline='') as f:
                    writer = csv.writer(f, delimiter='|')
                    for pattern, count in dict(counts).items():
                        writer.writerow([count] + list(pattern))

    pool = multiprocessing.Pool()

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
    
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f, delimiter='|')
        for pattern, count in dict(counts).items():
            writer.writerow([count] + list(pattern))

input_file = '4Bytes_filtered.csv'
output_file = '4Bytes_count_duplicates.csv'
process_file(input_file, output_file)