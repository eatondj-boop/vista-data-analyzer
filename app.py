import os
import sqlite3
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_folder='.', template_folder='.')

DB_PATH = 'dynamic_dataset.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Serve the main HTML Workbench UI at the root URL
@app.route('/')
def home():
    # If your main frontend file is test_inspector.html (or change to your preferred html file)
    html_file = 'test_inspector.html'
    if os.path.exists(html_file):
        return send_from_directory('.', html_file)
    
    # Fallback status message if the html file isn't present
    return jsonify({
        "message": "Unified VistA Analytics Workbench Active (Schemas + Routines)",
        "status": "online"
    })

# API endpoint for schemas/routines or general queries
@app.route('/api/query', methods=['GET', 'POST'])
def api_query():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Example generic query execution or custom logic
        cursor.name = "SELECT name FROM sqlite_master WHERE type='table';"
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row['name'] for row in cursor.fetchall()]
        conn.close()
        return jsonify({"tables": tables, "status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("Starting Unified VistA Analytics Workbench...")
    app.run(host="0.0.0.0", port=5002, debug=True)