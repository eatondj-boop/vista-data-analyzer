import os
import re
import sqlite3
from flask import Flask, redirect, render_template_string, request, url_for

app = Flask(__name__)
app.secret_key = "vista_transition_secret_key"
DATA_DIR = "data"
DB_NAME = "dynamic_dataset.db"

def get_db(db_filename=DB_NAME):
    db_path = os.path.join(DATA_DIR, db_filename)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    return db

DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Transitional Architecture - Resilient Staging Wizard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f9; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
        h1, h2, h3 { color: #111; }
        .nav-bar { display: flex; gap: 15px; margin-bottom: 30px; border-bottom: 2px solid #e2e8f0; padding-bottom: 15px; }
        .nav-bar a { text-decoration: none; padding: 10px 18px; background: #e2e8f0; color: #334155; border-radius: 6px; font-weight: 600; font-size: 14px; }
        .nav-bar a.active, .nav-bar a:hover { background: #2563eb; color: white; }
        .card { background: #f8fafc; border: 1px solid #e2e8f0; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .btn { padding: 12px 24px; background: #2563eb; color: white; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-block; font-size: 14px; }
        .btn:hover { background: #1d4ed8; }
        .btn-secondary { background: #475569; }
        .btn-secondary:hover { background: #334155; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
        th { background: #f1f5f9; color: #475569; }
        pre { background: #0f172a; color: #38bdf8; padding: 15px; border-radius: 6px; overflow-x: auto; font-family: monospace; font-size: 13px; }
        select, input, textarea { padding: 12px; width: 100%; border: 1px solid #cbd5e1; border-radius: 6px; margin-top: 5px; box-sizing: border-box; font-size: 14px; background: white; }
        label { font-weight: 600; font-size: 14px; color: #334155; display: block; margin-top: 15px; }
        .step-badge { background: #2563eb; color: white; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-right: 8px; }
        .alert-success { background: #dcfce7; border: 1px solid #bbf7d0; color: #166534; padding: 15px 20px; border-radius: 6px; margin-bottom: 20px; font-weight: 600; }
        .preview-box { background: #fff; border: 2px dashed #cbd5e1; padding: 15px; border-radius: 6px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Transitional Architecture Command Center</h1>
        <p style="color: #64748b;">Resilient State-Machine Parser & Live SQL Preview Engine</p>

        <div class="nav-bar">
            <a href="/">Command Dashboard</a>
            <a href="/wizard">1. Ingestion Wizard</a>
            <a href="/viewer">2. Database Inspector</a>
        </div>

        {% if active == "home" %}
            <div class="card">
                <h2>Welcome, Architect</h2>
                <p>Define custom schemas, inspect live transformation previews, and execute verified database staging runs.</p>
                <ul>
                    <li><strong>Active Target File:</strong> <code>data/ROUTINE.txt</code></li>
                    <li><strong>Active Staging DB:</strong> <code>data/dynamic_dataset.db</code></li>
                </ul>
                <a href="/wizard" class="btn">Launch Definition Wizard →</a>
            </div>

        {% elif active == "wizard" %}
            <h2><span class="step-badge">Step 1</span>Raw Preamble Inspection</h2>
            <div class="card">
                <p style="color: #64748b; font-size: 14px;">Review raw sample lines from your target dataset.</p>
                <pre>{% for line in raw_lines %}{{ line }}
{% endfor %}</pre>
                <div style="margin-top: 20px;">
                    <a href="/configure-contract" class="btn">Proceed to Schema & Rule Configuration →</a>
                </div>
            </div>

        {% elif active == "configure_contract" %}
            <h2><span class="step-badge">Step 2</span>Define Rules & Live SQL Preview</h2>
            <div class="card">
                <p style="color: #64748b; font-size: 13px;">Configure your SQL schema. Third subscript maps directly to line number.</p>
                
                <form method="POST" action="/preview-contract">
                    <label>Target SQLite Table Name:</label>
                    <input type="text" name="table_name" value="{{ form_data.get('table_name', 'vista_routines_clean') }}" required>

                    <label>Column 1 Definition:</label>
                    <input type="text" name="field_1" value="{{ form_data.get('field_1', 'routine_name TEXT') }}" required>

                    <label>Column 2 Definition:</label>
                    <input type="text" name="field_2" value="{{ form_data.get('field_2', 'node_type TEXT') }}" required>

                    <label>Column 3 Definition (Line Number):</label>
                    <input type="text" name="field_3" value="{{ form_data.get('field_3', 'line_number TEXT') }}" required>

                    <label>Column 4 Definition (Payload):</label>
                    <input type="text" name="field_4" value="{{ form_data.get('field_4', 'node_value TEXT') }}" required>

                    <label>Extraction Parsing Expression (Regex matching ^ROUTINE("name", node, line)):</label>
                    <input type="text" name="regex_pattern" value="{{ form_data.get('regex_pattern', '^\^ROUTINE\s*\(\s*\"([^"]+)\"\s*,\s*([^,]+)\s*,\s*([^)]+)\)$') }}" required>

                    <label>Pre-Ingestion Exclusion Filter:</label>
                    <input type="text" name="exclusion_filter" value="{{ form_data.get('exclusion_filter', 'VA routine global|Format=|^;;|^Cache') }}">

                    <div style="margin-top: 25px; display: flex; gap: 15px;">
                        <button type="submit" class="btn btn-secondary">🔍 Preview Live SQL Mapping →</button>
                    </div>
                </form>

                {% if preview_rows %}
                <div class="preview-box">
                    <h3>Live SQL Preview (Sample Output based on rules)</h3>
                    <p style="color: #64748b; font-size: 12px;">Review how your rules map clean source code records into columns.</p>
                    <table>
                        <thead>
                            <tr>
                                <th>Status</th>
                                <th>Routine Name</th>
                                <th>Node Type</th>
                                <th>Line #</th>
                                <th>Source Code Payload</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for p in preview_rows %}
                            <tr>
                                <td>
                                    {% if p.status == "FILTERED" %}<span style="color: #dc2626; font-weight: bold;">FILTERED OUT</span>
                                    {% elif p.status == "PARSED" %}<span style="color: #166534; font-weight: bold;">PARSED</span>
                                    {% else %}<span style="color: #d97706; font-weight: bold;">UNPARSED</span>{% endif %}
                                </td>
                                <td><strong>{{ p.v1 }}</strong></td>
                                <td>{{ p.v2 }}</td>
                                <td>{{ p.v3 }}</td>
                                <td><code>{{ p.v4 }}</code></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>

                    <form method="POST" action="/commit-wizard" style="margin-top: 20px;">
                        <input type="hidden" name="table_name" value="{{ form_data.get('table_name') }}">
                        <input type="hidden" name="field_1" value="{{ form_data.get('field_1') }}">
                        <input type="hidden" name="field_2" value="{{ form_data.get('field_2') }}">
                        <input type="hidden" name="field_3" value="{{ form_data.get('field_3') }}">
                        <input type="hidden" name="field_4" value="{{ form_data.get('field_4') }}">
                        <input type="hidden" name="regex_pattern" value="{{ form_data.get('regex_pattern') }}">
                        <input type="hidden" name="exclusion_filter" value="{{ form_data.get('exclusion_filter') }}">
                        
                        <button type="submit" class="btn">✅ Approve Contract & Execute Full Bulk Ingestion →</button>
                    </form>
                </div>
                {% endif %}
            </div>

        {% elif active == "viewer" %}
            <h2>Database Inspector Viewer</h2>
            
            {% if message %}
                <div class="alert-success">
                    {{ message }}
                </div>
            {% endif %}

            <div class="card">
                <form method="GET" action="/viewer" style="display: flex; gap: 10px;">
                    <input type="text" name="q" value="{{ search_query }}" placeholder="Filter rows..." style="padding: 10px; flex: 1; border: 1px solid #cbd5e1; border-radius: 6px;">
                    <button type="submit" class="btn" style="height: 44px;">Search</button>
                </form>
            </div>

            <p style="color: #64748b; font-size: 13px; margin-bottom: 10px;">
                Active Table: <strong>{{ target_table }}</strong> | Showing records:
            </p>

            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Routine Name</th>
                        <th>Node Type</th>
                        <th>Line #</th>
                        <th>Source Code Payload</th>
                    </tr>
                </thead>
                <tbody>
                    {% for row in rows %}
                    <tr>
                        <td>{{ row['id'] }}</td>
                        <td><strong>{{ row['routine_name'] }}</strong></td>
                        <td>{{ row['node_type'] }}</td>
                        <td>{{ row['line_number'] }}</td>
                        <td><code>{{ row['node_value'] }}</code></td>
                    </tr>
                    {% else %}
                    <tr><td colspan="5" style="text-align: center; color: #64748b; padding: 30px;">No data loaded or matching search. Run the Wizard first.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        {% endif %}
    </div>
</body>
</html>
"""

def parse_lines_resilient(lines, parser_pattern, exclusion_pattern, max_results=None):
    results = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue
            
        if exclusion_pattern and exclusion_pattern.search(line):
            results.append({'status': 'FILTERED', 'v1': 'EXCLUDED', 'v2': 'FILTER', 'v3': 'RULE', 'v4': line})
            i += 1
            if max_results and len(results) >= max_results: break
            continue
            
        if parser_pattern:
            match = parser_pattern.match(line)
            if match and len(match.groups()) >= 3:
                r_name = match.group(1).strip()
                n_type = match.group(2).strip()
                l_num = match.group(3).strip()
                
                payload = ""
                if i + 1 < len(lines):
                    next_line = lines[i + 1].strip()
                    if next_line and not next_line.startswith("^"):
                        payload = lines[i + 1].strip()
                        i += 2
                    else:
                        payload = ""
                        i += 1
                else:
                    i += 1
                    
                if (payload.startswith('"') and payload.endswith('"')) or (payload.startswith("'") and payload.endswith("'")):
                    payload = payload[1:-1]
                    
                results.append({'status': 'PARSED', 'v1': r_name, 'v2': n_type, 'v3': l_num, 'v4': payload})
                if max_results and len(results) >= max_results: break
                continue
                
        results.append({'status': 'UNPARSED', 'v1': 'UNPARSED', 'v2': '?', 'v3': 'line', 'v4': line})
        i += 1
        if max_results and len(results) >= max_results: break
        
    return results

@app.route("/")
def index():
    return render_template_string(DASHBOARD_TEMPLATE, active="home")

@app.route("/wizard")
def wizard():
    file_path = os.path.join(DATA_DIR, "ROUTINE.txt")
    raw_lines = []
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for _ in range(15):
                line = f.readline()
                if not line: break
                raw_lines.append(line.strip())
    else:
        raw_lines = [f"Error: ROUTINE.txt not found at '{file_path}'."]
    return render_template_string(DASHBOARD_TEMPLATE, active="wizard", filename="ROUTINE.txt", raw_lines=raw_lines)

@app.route("/configure-contract")
def configure_contract():
    default_form = {
        "table_name": "vista_routines_clean",
        "field_1": "routine_name TEXT",
        "field_2": "node_type TEXT",
        "field_3": "line_number TEXT",
        "field_4": "node_value TEXT",
        "regex_pattern": r'^\^ROUTINE\s*\(\s*"([^"]+)"\s*,\s*([^,]+)\s*,\s*([^)]+)\)$',
        "exclusion_filter": r'VA routine global|Format=|^;;|^Cache'
    }
    return render_template_string(DASHBOARD_TEMPLATE, active="configure_contract", form_data=default_form, preview_rows=None)

@app.route("/preview-contract", methods=["POST"])
def preview_contract():
    form_data = request.form
    regex_str = form_data.get("regex_pattern", "").strip()
    exclusion_str = form_data.get("exclusion_filter", "").strip()
    
    file_path = os.path.join(DATA_DIR, "ROUTINE.txt")
    lines = []
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            
    parser_pattern = re.compile(regex_str) if regex_str else None
    exclusion_pattern = re.compile(exclusion_str) if exclusion_str else None
    
    preview_rows = parse_lines_resilient(lines, parser_pattern, exclusion_pattern, max_results=25)
    return render_template_string(DASHBOARD_TEMPLATE, active="configure_contract", form_data=form_data, preview_rows=preview_rows)

@app.route("/commit-wizard", methods=["POST"])
def commit_wizard():
    table_name = request.form.get("table_name", "vista_routines_clean").strip()
    field_1 = request.form.get("field_1", "routine_name TEXT").strip()
    field_2 = request.form.get("field_2", "node_type TEXT").strip()
    field_3 = request.form.get("field_3", "line_number TEXT").strip()
    field_4 = request.form.get("field_4", "node_value TEXT").strip()
    regex_str = request.form.get("regex_pattern", "").strip()
    exclusion_str = request.form.get("exclusion_filter", "").strip()
    
    file_path = os.path.join(DATA_DIR, "ROUTINE.txt")
    db = get_db(DB_NAME)
    cursor = db.cursor()
    
    table_name = re.sub(r'[^a-zA-Z0-9_]', '', table_name)
    
    cursor.execute(f"DROP TABLE IF EXISTS {table_name};")
    cursor.execute(f"""
        CREATE TABLE {table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            {field_1},
            {field_2},
            {field_3},
            {field_4}
        )
    """)
    db.commit()
    
    lines = []
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            
    parser_pattern = re.compile(regex_str) if regex_str else None
    exclusion_pattern = re.compile(exclusion_str) if exclusion_str else None
    
    all_parsed = parse_lines_resilient(lines, parser_pattern, exclusion_pattern, max_results=None)
    
    batch = []
    inserted_count = 0
    filtered_count = 0
    
    f1_name = field_1.split()[0]
    f2_name = field_2.split()[0]
    f3_name = field_3.split()[0]
    f4_name = field_4.split()[0]
    
    for row in all_parsed:
        if row['status'] == 'FILTERED' or row['status'] == 'UNPARSED':
            filtered_count += 1
            continue
            
        batch.append((row['v1'], row['v2'], row['v3'], row['v4']))
        inserted_count += 1
        
        if len(batch) >= 2000:
            cursor.executemany(f"INSERT INTO {table_name} ({f1_name}, {f2_name}, {f3_name}, {f4_name}) VALUES (?, ?, ?, ?)", batch)
            db.commit()
            batch.clear()
            
    if batch:
        cursor.executemany(f"INSERT INTO {table_name} ({f1_name}, {f2_name}, {f3_name}, {f4_name}) VALUES (?, ?, ?, ?)", batch)
        db.commit()
        
    db.close()
    success_msg = f"Successfully staged! Created {inserted_count:,} records in '{table_name}'."
    return redirect(url_for('viewer', table=table_name, msg=success_msg))

@app.route("/viewer")
def viewer():
    search_query = request.args.get('q', '').strip()
    message = request.args.get('msg', '').strip()
    target_table = request.args.get('table', '').strip()
    
    db = get_db(DB_NAME)
    cursor = db.cursor()
    
    try:
        if not target_table:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence' ORDER BY rowid DESC;")
            tables = cursor.fetchall()
            target_table = tables[0][0] if tables else 'vista_routines_clean'
            
        cursor.execute(f"PRAGMA table_info({target_table});")
        cols = [col['name'] for col in cursor.fetchall()]
        f1_col = cols[1] if len(cols) > 1 else 'routine_name'
        f4_col = cols[4] if len(cols) > 4 else 'node_value'
        
        if search_query:
            cursor.execute(f"SELECT id, routine_name, node_type, line_number, node_value FROM {target_table} WHERE {f1_col} LIKE ? OR {f4_col} LIKE ? LIMIT 50", (f'%{search_query}%', f'%{search_query}%'))
        else:
            cursor.execute(f"SELECT id, routine_name, node_type, line_number, node_value FROM {target_table} LIMIT 10")
        rows = cursor.fetchall()
    except sqlite3.OperationalError:
        rows = []
        target_table = 'vista_routines_clean'
        
    db.close()
    return render_template_string(DASHBOARD_TEMPLATE, active='viewer', rows=rows, search_query=search_query, message=message, target_table=target_table)

if __name__ == '__main__':
    print("Starting Resilient SQL Staging Dashboard...")
    print("Open your browser and navigate to: http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)