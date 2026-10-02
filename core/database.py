import os
import sqlite3

DATABASE_URL = os.environ.get('DATABASE_URL')

if DATABASE_URL:
    import psycopg2
    import psycopg2.extras

DB_PATH = os.path.join('data', 'dynamic_dataset.db')

def get_db_connection():
    if DATABASE_URL:
        # Connect to remote Neon PostgreSQL
        conn = psycopg2.connect(DATABASE_URL)
        conn.cursor_factory = psycopg2.extras.RealDictCursor
        return conn
    else:
        # Fall back to local SQLite file
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

def get_active_table_name():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE_URL:
        cursor.execute("""
            SELECT table_name AS name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            ORDER BY table_name DESC;
        """)
    else:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence' ORDER BY rowid DESC;")
        
    row = cursor.fetchone()
    conn.close()
    return row['name'] if row else 'vista_routines_clean'
