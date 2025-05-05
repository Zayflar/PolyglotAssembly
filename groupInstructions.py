import csv
from multiprocessing import Pool, cpu_count

def process_chunk(chunk, output_file):
    seen = set()
    unique_rows = []
    for row in chunk:
        key = tuple(row[1:])
        if key not in seen:
            seen.add(key)
            unique_rows.append(row)
    with open(output_file, 'a', newline='') as f:
        writer = csv.writer(f, delimiter='|')
        writer.writerows(unique_rows)

def remove_duplicates(input_file, output_file, chunksize=10000):
    with open(input_file, 'r') as f:
        reader = csv.reader(f, delimiter='|')
        with Pool(cpu_count()) as pool:
            chunk = []
            for i, row in enumerate(reader):
                chunk.append(row)
                if len(chunk) == chunksize:
                    pool.apply_async(process_chunk, args=(chunk, output_file))
                    chunk = []
            if chunk:
                pool.apply_async(process_chunk, args=(chunk, output_file))
            pool.close()
            pool.join()



input_file = '4Bytes_filtered.csv'
output_file = '4Bytes_no_duplicates.csv'
open(output_file, 'w').close()
remove_duplicates(input_file, output_file)