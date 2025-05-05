import csv
from multiprocessing import Pool, cpu_count
from collections import defaultdict

def process_chunk(chunk):
    local_counts = defaultdict(int)
    for row in chunk:
        key = tuple(row[1:])
        local_counts[key] += 1
    return local_counts

def remove_duplicates(input_file, output_file, chunksize=10000):
    counts = defaultdict(int)
    
    with open(input_file, 'r') as f:
        reader = csv.reader(f, delimiter='|')
        with Pool(cpu_count()) as pool:
            chunk = []
            for row in reader:
                chunk.append(row)
                if len(chunk) == chunksize:
                    results = pool.map(process_chunk, [chunk])
                    for res in results:
                        for key, count in res.items():
                            counts[key] += count
                    chunk = []
            
            if chunk:
                results = pool.map(process_chunk, [chunk])
                for res in results:
                    for key, count in res.items():
                        counts[key] += count
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f, delimiter='|')
        for key, count in counts.items():
            writer.writerow([count] + list(key))

input_file = '4Bytes_filtered.csv'
output_file = '4Bytes_count_duplicates.csv'
remove_duplicates(input_file, output_file)