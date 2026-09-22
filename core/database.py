import sqlite3
import os

DB_PATH = os.path.join('data', 'dynamic_dataset.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_active_table_name():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence' ORDER BY rowid DESC;")
    row = cursor.fetchone()
    conn.close()
    return row['name'] if row else 'vista_routines_clean'
