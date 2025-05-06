(head -n 1 4Bytes_count.csv && 
 tail -n +2 4Bytes_count.csv 4Bytes_count_1.csv 4Bytes_count_2.csv 4Bytes_count_3.csv |
 awk -F '|' '{key=$2 FS $3 FS $4 FS $5 FS $6 FS $7 FS $8 FS $9; a[key]+=$1} END {for (i in a) print a[i] FS i}' |
 sort -t'|' -k1,1nr) > 4Bytes_total.csv
