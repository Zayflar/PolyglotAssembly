import csv
import multiprocessing
from collections import defaultdict

def process_chunk(chunk):
    counts = defaultdict(int)
    for row in chunk:
        key = tuple(row[1:])
        counts[key] += 1
    return counts

def read_csv_chunks(file_path, chunk_size):
    with open(file_path, 'r') as f:
        reader = csv.reader(f, delimiter='|')
        chunk = []
        for row in reader:
            chunk.append(row)
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk

def process_file(input_file, output_file, chunk_size=10000, max_processes=32):
    lock = multiprocessing.Lock()
    manager = multiprocessing.Manager()
    global_counts = manager.dict()

    def worker(chunk):
        local_counts = process_chunk(chunk)
        with lock:
            for key, count in local_counts.items():
                if key in global_counts:
                    global_counts[key] += count
                else:
                    global_counts[key] = count

    processes = []
    for chunk in read_csv_chunks(input_file, chunk_size):
        if len(processes) >= max_processes:
            for p in processes:
                p.join()
            processes = []
        
        p = multiprocessing.Process(target=worker, args=(chunk,))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f, delimiter='|')
        for key, count in global_counts.items():
            writer.writerow([count] + list(key))

input_file = '4Bytes_filtered.csv'
output_file = '4Bytes_count_duplicates.csv'
process_file(input_file, output_file)