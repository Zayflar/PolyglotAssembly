import csv

def sort_csv(input_file, output_file):
    with open(input_file, 'r') as f:
        reader = csv.reader(f, delimiter='|')
        header = next(reader) 
        rows = list(reader)
    

    rows_sorted = sorted(rows, key=lambda x: int(x[0]), reverse=True)
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f, delimiter='|')
        writer.writerow(header)
        writer.writerows(rows_sorted)


input_file = '4Bytes_count.csv'
output_file = '4Bytes_count_sort.csv'
sort_csv(input_file, output_file)