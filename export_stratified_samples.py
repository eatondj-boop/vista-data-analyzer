import sqlite3
import csv

def export_findings_range(start_row, end_row, output_filename):
    conn = sqlite3.connect('data/dynamic_dataset.db')
    cursor = conn.cursor()
    
    limit = end_row - start_row + 1
    offset = start_row - 1
    
    cursor.execute('SELECT * FROM architectural_xrf LIMIT ? OFFSET ?', (limit, offset))
    rows = cursor.fetchall()
    column_names = [description[0] for description in cursor.description]
    
    with open(output_filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(column_names)
        writer.writerows(rows)
        
    conn.close()
    print(f'Exported rows {start_row} to {end_row} to {output_filename} (Total rows: {len(rows)})')

# Execute all requested stratified sample ranges
export_findings_range(30000, 31000, 'report_chunk_30000_31000.csv')
export_findings_range(40000, 41000, 'report_chunk_40000_41000.csv')
export_findings_range(70000, 71000, 'report_chunk_70000_71000.csv')
export_findings_range(100000, 101000, 'report_chunk_100000_101000.csv')
export_findings_range(120000, 121000, 'report_chunk_120000_121000.csv')
export_findings_range(140000, 141000, 'report_chunk_140000_141000.csv')
export_findings_range(160000, 161000, 'report_chunk_160000_161000.csv')
export_findings_range(180000, 181000, 'report_chunk_180000_181000.csv')
