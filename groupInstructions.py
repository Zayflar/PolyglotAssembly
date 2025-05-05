import csv
import multiprocessing
from collections import defaultdict
import os

csv.field_size_limit(2**31-1) 

def process_chunk(chunk):
    counts = defaultdict(lambda: {'count': 0, 'opcodes': []})
    for row in chunk:
        key = tuple(row[1:])
        counts[key]['count'] += 1
        counts[key]['opcodes'].append(row[0])
    return dict(counts)

def process_file(input_file, output_file, chunk_size=100000, max_processes=32):
    temp_file = output_file + '.tmp'
    if os.path.exists(temp_file):
        os.remove(temp_file)
    if os.path.exists(output_file):
        os.remove(output_file)

    lock = multiprocessing.Lock()

    def worker(chunk, output, lock):
        local_counts = process_chunk(chunk)
        with lock:
            existing = defaultdict(lambda: {'count': 0, 'opcodes': []})
            if os.path.exists(output):
                with open(output, 'r', newline='') as f:
                    reader = csv.reader(f, delimiter='|')
                    try:
                        for row in reader:
                            if row:
                                key = tuple(row[1:-1])
                                existing[key]['count'] = int(row[0])
                                existing[key]['opcodes'] = row[-1].split(',') if row[-1] else []
                    except csv.Error as e:
                        print(f"CSV Error: {e}")
                        raise
            
            for k, v in local_counts.items():
                existing[k]['count'] += v['count']
                existing[k]['opcodes'].extend(v['opcodes'])
            
            with open(output, 'w', newline='') as f:
                writer = csv.writer(f, delimiter='|')
                for k, v in existing.items():
                    opcodes_str = ','.join(v['opcodes'])
                    writer.writerow([v['count']] + list(k) + [opcodes_str])

    processes = []
    with open(input_file, 'r', newline='') as f:
        reader = csv.reader(f, delimiter='|')
        chunk = []
        for row in reader:
            chunk.append(row)
            if len(chunk) >= chunk_size:
                if len(processes) >= max_processes:
                    for p in processes:
                        p.join()
                    processes = []
                p = multiprocessing.Process(target=worker, args=(chunk, temp_file, lock))
                p.start()
                processes.append(p)
                chunk = []
        
        if chunk:
            p = multiprocessing.Process(target=worker, args=(chunk, temp_file, lock))
            p.start()
            processes.append(p)

    for p in processes:
        p.join()
    
    os.replace(temp_file, output_file)

if __name__ == "__main__":
    input_file = '4Bytes_filtered.csv'
    output_file = '4Bytes_count_duplicates.csv'
    process_file(input_file, output_file)