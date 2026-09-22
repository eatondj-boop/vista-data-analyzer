import os
import re
import sqlite3

class RoutineExtractor:
    def __init__(self, db_path="data/vista_routines.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

    def parse_mumps_line(self, line):
        pattern = re.compile(r'^\^ROUTINE\("([^"]+)",(.+?)\)\s*=\s*(.*)$')
        match = pattern.match(line)
        if match:
            routine_name = match.group(1)
            subscript = match.group(2).strip()
            value = match.group(3)
            if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            return routine_name, subscript, value
        return None, None, None

    def extract_to_db(self, file_path, batch_size=2000):
        if not os.path.exists(file_path):
            print(f"Error: File not found at '{file_path}'")
            return False

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS raw_routines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                routine_name TEXT,
                subscript TEXT,
                node_value TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_routine_name ON raw_routines(routine_name);")
        conn.commit()

        print(f"Starting extraction of '{file_path}' into SQLite...")
        batch = []
        line_count = 0
        routine_count = set()

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                r_name, sub, val = self.parse_mumps_line(line)
                if r_name:
                    batch.append((r_name, sub, val))
                    routine_count.add(r_name)
                    line_count += 1

                if len(batch) >= batch_size:
                    cursor.executemany("""
                        INSERT INTO raw_routines (routine_name, subscript, node_value)
                        VALUES (?, ?, ?)
                    """, batch)
                    conn.commit()
                    batch.clear()
                    print(f"Processed {line_count} nodes...", end='\r')

        if batch:
            cursor.executemany("""
                INSERT INTO raw_routines (routine_name, subscript, node_value)
                VALUES (?, ?, ?)
            """, batch)
            conn.commit()

        conn.close()
        print(f"\nExtraction complete! Successfully stored {line_count} nodes across {len(routine_count)} routines in '{self.db_path}'.")
        return True
