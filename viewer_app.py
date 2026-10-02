import sqlite3
import os
import re
import zipfile
from datetime import datetime
from flask import Flask, g, render_template_string, request, session, abort, jsonify
from impact_analyzer import ImpactAnalyzer

# Define database paths
DB_DIR = os.path.join(os.path.dirname(__file__), 'data')
DB_PATH = os.path.join(DB_DIR, 'dynamic_dataset.db')
ZIP_PATH = os.path.join(DB_DIR, 'dynamic_dataset.db.zip')

# Auto-extract the lean production database from the zip archive on startup if needed
if not os.path.exists(DB_PATH) and os.path.exists(ZIP_PATH):
    print("Extracting production database from zip archive...")
    with zipfile.ZipFile(ZIP_PATH, 'r') as zip_ref:
        zip_ref.extractall(DB_DIR)

app = Flask(__name__)
app.secret_key = 'data_analyzer_secret_key'

def init_database():
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS architectural_xrf (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            routine_name TEXT,
            line_number TEXT,
            analysis_code TEXT,
            file_number TEXT,
            field_number TEXT,
            op_intent TEXT,
            invocation_type TEXT,
            target_entity TEXT,
            op_context TEXT
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS preprocessor_anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_ns TEXT,
            routine_name TEXT,
            error_message TEXT,
            node_snippet TEXT
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS build_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version_tag TEXT,
            build_timestamp TEXT,
            total_records INTEGER,
            intent_summary TEXT,
            invocation_summary TEXT,
            ad_hoc_col_1 TEXT,
            ad_hoc_col_2 TEXT
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vista_routines_clean (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            routine_name TEXT,
            line_number TEXT,
            node_value TEXT
        );
    """)
    
    cursor.execute("PRAGMA table_info(build_history);")
    columns = [col[1] for col in cursor.fetchall()]
    if 'version_tag' not in columns:
        try:
            cursor.execute("ALTER TABLE build_history ADD COLUMN version_tag TEXT;")
            conn.commit()
        except Exception as mig_err:
            print(f"Migration note: {mig_err}")

    conn.commit()
    conn.close()

init_database()

def log_build_version(total_records, intent_summary_str, inv_summary_str, ad_hoc_1="", ad_hoc_2=""):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM build_history;")
        count = cursor.fetchone()[0]
        version_tag = f"v1.{count}"
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO build_history (version_tag, build_timestamp, total_records, intent_summary, invocation_summary, ad_hoc_col_1, ad_hoc_col_2)
            VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (version_tag, timestamp, total_records, intent_summary_str, inv_summary_str, ad_hoc_1 or 'None', ad_hoc_2 or 'None'))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ Error logging build version: {e}")

def get_package_registry():
    registry = {}
    if os.path.exists(DB_PATH):
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vista_packages';")
            if cursor.fetchone():
                cursor.execute("SELECT namespace, description FROM vista_packages;")
                rows = cursor.fetchall()
                for r in rows:
                    ns = (r[0] or '').upper().strip()
                    desc = (r[1] or '').strip()
                    if ns:
                        registry[ns] = desc or f"Package {ns}"
            conn.close()
        except Exception as e:
            print(f"⚠️ Error loading vista_packages registry: {e}")

    if not registry:
        registry = {
            'AG': 'Indian Health Service Registration',
            'BPS': 'Billing Payer Suite', 'BT': 'Blood Bank Transfusion',
            'CL': 'Clinic Scheduling', 'CP': 'Clinical Procedures', 'CS': 'CST / Surgery',
            'DG': 'Registration / MPI', 'DI': 'Data Dictionary Utilities', 'DIC': 'FileMan Lookup',
            'DIE': 'FileMan Data Entry', 'DIK': 'FileMan Indexing', 'DIR': 'FileMan Reader',
            'DT': 'Date / Time Utilities', 'DU': 'Utilities Core',
            'EC': 'Event Capture', 'ED': 'Emergency Department', 'EN': 'Engineering & Maintenance',
            'FB': 'Fee Basis', 'FH': 'Dietetics', 'FM': 'FileMan Core',
            'GMR': 'General Medical Record', 'GMRV': 'Vital Signs', 'HMP': 'Health Management Platform',
            'IB': 'Integrated Billing', 'IVM': 'Income Verification Match', 'LR': 'Laboratory', 'MC': 'Medicine',
            'OR': 'Order Entry / OERR', 'PS': 'Pharmacy', 'PX': 'PCE Patient Care Encounter',
            'RA': 'Radiology / Nuclear Med', 'TIU': 'Text Integration Utility', 'XU': 'Kernel',
            'MPIF': 'Master Patient Index', 'EAS': 'Enrollment Application System', 'GMTS': 'Health Summary',
            'SD': 'Scheduling'
        }
    return registry

def get_file_description(file_num):
    known_files = {
        '2': 'Patient',
        '200': 'New Person (Staff)',
        '4': 'Institution',
        '9.4': 'Package',
        '50': 'Medication - Drug',
        '52': 'Prescription',
        '3': 'Domain',
        '8989.3': 'Kernel Parameters',
        '409.81': 'Appointment'
    }
    if file_num in known_files:
        return known_files[file_num]
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM vista_dic WHERE file_number = ? LIMIT 1;", (file_num,))
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            parts = row[0].split('^')
            if len(parts) > 0 and not parts[0].isdigit():
                return parts[0]
    except Exception:
        pass
    return f"FileMan Schema Entity {file_num}"

def get_package_namespace(routine_name, registry):
    rname = routine_name.upper().strip()
    if rname.startswith('%'):
        return '%'
    for ns in sorted(registry.keys(), key=len, reverse=True):
        if rname.startswith(ns):
            return ns
    return rname[:2]

def get_available_packages():
    registry = get_package_registry()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT routine_name FROM architectural_xrf WHERE routine_name IS NOT NULL;")
    rows = cursor.fetchall()
    conn.close()

    db_routines = [r[0].upper() for r in rows if r[0]]
    valid_packages = []
    for pkg_prefix in registry.keys():
        matches = any(r.startswith(pkg_prefix) for r in db_routines)
        if matches:
            valid_packages.append(pkg_prefix)
    return sorted(valid_packages)

def get_available_invocations():
    invocations = {'MUMPS', 'FILEMAN', 'PACKAGE_CALL'}
    if os.path.exists(DB_PATH):
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT invocation_type FROM architectural_xrf WHERE invocation_type IS NOT NULL;")
            rows = cursor.fetchall()
            for r in rows:
                if r[0]:
                    invocations.add(r[0].upper().strip())
            conn.close()
        except Exception:
            pass
    return sorted(list(invocations))

def evaluate_mumps_context(code_upper, token, routine_name=""):
    try:
        cleaned_token = token.lstrip('^').strip()
        
        if cleaned_token.isdigit() or cleaned_token.upper() == routine_name.upper() or cleaned_token.startswith('%') or cleaned_token in {
            'ADDIOL', 'XLFDT', 'XGF', 'VALM1', 'XLFSTR', 'ORUTL', 'DDIOL', 'ADIE', 'DIR', 'DIC', 'DIK', 'DIQ', 'B'
        }:
            return {'invocation_type': 'MUMPS', 'op_intent': 'READ', 'is_valid_data_op': False, 'target_pkg': None}

        registry = get_package_registry()
        focal_ns = get_package_namespace(routine_name, registry)

        call_match = re.search(r'\b(D|DO|G|GOTO|J|JOB)\s+([A-Z0-9]+\^)?([A-Z0-9%]+)', code_upper)
        if call_match:
            called_routine = call_match.group(3)
            if called_routine.startswith('%'):
                return {'invocation_type': 'MUMPS', 'op_intent': 'CALL', 'is_valid_data_op': False, 'target_pkg': '%'}
                
            target_pkg = get_package_namespace(called_routine, registry)
            
            if target_pkg and target_pkg != focal_ns:
                return {'invocation_type': 'PACKAGE_CALL', 'op_intent': 'CALL', 'is_valid_data_op': True, 'target_pkg': target_pkg}
            else:
                return {'invocation_type': 'PACKAGE_CALL', 'op_intent': 'CALL', 'is_valid_data_op': False, 'target_pkg': target_pkg}

        if re.search(r'\b(DIC|DIE|DIK|DIQ|DIR|GET1\^DIQ)\b', code_upper):
            if re.search(r'\b(SET\s+\^|KILL\s+\^|MERGE\s+\^|UPDATE\^|FILE\^)', code_upper):
                op_intent = 'WRITE'
            elif re.search(r'\b(DIC|FIND\^|LIST\^)', code_upper):
                op_intent = 'QUERY'
            else:
                op_intent = 'READ'
            return {'invocation_type': 'FILEMAN', 'op_intent': op_intent, 'is_valid_data_op': True, 'target_pkg': None}
        
        if re.search(r'\b(SET|S|KILL|K|MERGE|M)\s+\^' + re.escape(token.lstrip('^')), code_upper):
            if re.search(r'\b(KILL|K)\b', code_upper):
                op_intent = 'WRITE'
            elif re.search(r'\b(SET|S|MERGE|M)\b', code_upper):
                op_intent = 'WRITE'
            else:
                op_intent = 'READ'
            return {'invocation_type': 'MUMPS', 'op_intent': op_intent, 'is_valid_data_op': True, 'target_pkg': None}
        
        if re.search(r'\$(\$GET|\$G|\$DATA|\$D|\$ORDER|\$O)\s*\(\s*\^' + re.escape(token.lstrip('^')), code_upper):
            return {'invocation_type': 'MUMPS', 'op_intent': 'QUERY', 'is_valid_data_op': True, 'target_pkg': None}

        if token.startswith('^') and '(' in token:
            return {'invocation_type': 'MUMPS', 'op_intent': 'READ', 'is_valid_data_op': True, 'target_pkg': None}
    except Exception:
        pass

    return {'invocation_type': 'MUMPS', 'op_intent': 'CALL', 'is_valid_data_op': False, 'target_pkg': None}

def is_strict_peer_reference(target_entity, op_context, focal_pkg, peer_pkg):
    target = (target_entity or '').upper().strip()
    context = (op_context or '').upper().strip()
    peer = peer_pkg.upper()
    focal = focal_pkg.upper()

    if peer == focal:
        return False

    global_pattern = f"^\\^{peer}"
    if re.search(global_pattern, target) or re.search(global_pattern, context):
        return True
    elif re.search(f"\\^\\s*{peer}[A-Z0-9]+", context):
        return True
    elif target.startswith(f"^{peer}") or f"({peer}" in target:
        return True

    return False

SORTABLE_TABLE_SCRIPT = """
<script>
function sortTable(tableId, colIdx, isNumeric = false) {
    var table = document.getElementById(tableId);
    var tbody = table.tBodies[0];
    var rows = Array.from(tbody.querySelectorAll('tr'));
    var dir = table.dataset.sortDir === 'asc' ? 'desc' : 'asc';
    table.dataset.sortDir = dir;

    rows.sort(function(a, b) {
        var cellA = a.cells[colIdx].innerText.trim();
        var cellB = b.cells[colIdx].innerText.trim();
        
        if (isNumeric) {
            return dir === 'asc' ? parseFloat(cellA) - parseFloat(cellB) : parseFloat(cellB) - parseFloat(cellA);
        }
        return dir === 'asc' ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA);
    });

    rows.forEach(row => tbody.appendChild(row));
}

function toggleSelectAll(source) {
    checkboxes = document.getElementsByName('selected_row');
    for(var i=0, n=checkboxes.length; i<n; i++) {
        checkboxes[i].checked = source.checked;
    }
}

function printSelectedRows() {
    var checkboxes = document.getElementsByName('selected_row');
    var selectedIds = [];
    for (var i = 0; i < checkboxes.length; i++) {
        if (checkboxes[i].checked) {
            selectedIds.push(checkboxes[i].value);
        }
    }

    if (selectedIds.length === 0) {
        alert('Please select at least one row using the checkboxes to print/export.');
        return;
    }

    var rows = document.querySelectorAll('#remediationTable tbody tr');
    var printContent = `
        <!doctype html>
        <html>
        <head>
            <title>VistA Selected Architecture & Research Report</title>
            <style>
                body { font-family: sans-serif; padding: 20px; color: #1e293b; }
                h2 { border-bottom: 2px solid #0f172a; padding-bottom: 8px; }
                table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 12px; }
                th, td { padding: 8px 10px; border: 1px solid #cbd5e1; text-align: left; }
                th { background: #f1f5f9; }
            </style>
        </head>
        <body>
            <h2>📋 VistA Selected Remediation & Research Report</h2>
            <p>Generated items: <strong>${selectedIds.length}</strong></p>
            <table>
                <thead>
                    <tr>
                        <th>Routine</th>
                        <th>Line</th>
                        <th>File / Field</th>
                        <th>Intent</th>
                        <th>Invocation</th>
                        <th>Operation Context</th>
                    </tr>
                </thead>
                <tbody>
    `;

    rows.forEach(row => {
        var checkbox = row.querySelector('input[name="selected_row"]');
        if (checkbox && checkbox.checked) {
            var cells = row.cells;
            printContent += `
                <tr>
                    <td>${cells[1].innerText}</td>
                    <td>${cells[2].innerText}</td>
                    <td>${cells[3].innerText}</td>
                    <td>${cells[4].innerText}</td>
                    <td>${cells[5].innerText}</td>
                    <td><code>${cells[6].innerText}</code></td>
                </tr>
            `;
        }
    });

    printContent += `
                </tbody>
            </table>
        </body>
        </html>
    `;

    var printWindow = window.open('', '_blank');
    printWindow.document.write(printContent);
    printWindow.document.close();
    printWindow.focus();
    setTimeout(() => { printWindow.print(); }, 250);
}
</script>
<style>
    th.sortable { cursor: pointer; user-select: none; position: relative; }
    th.sortable:hover { background: #e2e8f0; color: #0f172a; }
    th.sortable::after { content: ' ↕'; font-size: 11px; color: #94a3b8; }
</style>
"""

# ==========================================
# HOME ROUTE
# ==========================================
@app.route('/', methods=['GET', 'POST'])
def index():
    available_pkgs = get_available_packages()
    registry = get_package_registry()
    
    selected_pkg = request.form.get('package', 'ALL').upper().strip()
    files_input = request.form.get('files_input', '').strip()
    fields_input = request.form.get('fields_input', '').strip()
    target_routine = request.form.get('target_routine', '').strip().upper()
    global_ref_filter = request.form.get('global_ref', '').strip().upper()
    selected_intent = request.form.get('intent', 'ALL').upper().strip()

    scope_results = []
    scope_summary = {'total': 0, 'reads': 0, 'writes': 0, 'queries': 0}

    if request.method == 'POST':
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = """
            SELECT id, routine_name, line_number, file_number, field_number, op_intent, invocation_type, target_entity, op_context 
            FROM architectural_xrf 
            WHERE 1=1
        """
        params = []

        if selected_pkg and selected_pkg != 'ALL':
            query += " AND UPPER(routine_name) LIKE ?"
            params.append(f"{selected_pkg}%")

        if selected_intent and selected_intent != 'ALL':
            query += " AND UPPER(op_intent) = ?"
            params.append(selected_intent)

        if global_ref_filter:
            query += " AND (UPPER(target_entity) LIKE ? OR UPPER(op_context) LIKE ?)"
            params.extend([f"%{global_ref_filter}%", f"%{global_ref_filter}%"])

        if files_input:
            file_list = [f.strip() for f in files_input.split(',') if f.strip()]
            if file_list:
                placeholders = ','.join(['?' for _ in file_list])
                query += f" AND file_number IN ({placeholders})"
                params.extend(file_list)

        if fields_input:
            field_list = [f.strip() for f in fields_input.split(',') if f.strip()]
            if field_list:
                f_conds = []
                for fno in field_list:
                    f_conds.append("field_number = ?")
                    params.append(fno)
                query += f" AND ({' OR '.join(f_conds)})"

        if target_routine:
            query += " AND UPPER(routine_name) LIKE ?"
            params.append(f"%{target_routine}%")

        query += " ORDER BY routine_name ASC, line_number ASC LIMIT 300;"
        cursor.execute(query, params)
        scope_results = cursor.fetchall()

        for r in scope_results:
            scope_summary['total'] += 1
            intent = (r['op_intent'] or 'READ').upper()
            if intent == 'WRITE': scope_summary['writes'] += 1
            elif intent == 'QUERY': scope_summary['queries'] += 1
            else: scope_summary['reads'] += 1

        conn.close()

    return render_template_string("""
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>VistA Enterprise Analyzer - Advanced Architect Workbench</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 30px; }
            .container { max-width: 1350px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
            
            .header-bar { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; padding-bottom: 15px; margin-bottom: 25px; flex-wrap: wrap; gap: 15px; }
            h1 { margin: 0; color: #0f172a; font-size: 22px; }
            .nav-group { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
            .btn { display: inline-block; padding: 6px 12px; background: #2563eb; color: white; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 12px; transition: background 0.2s; }
            .btn:hover { background: #1d4ed8; }
            .btn-secondary { background: #059669; }
            .btn-secondary:hover { background: #047857; }
            .btn-accent { background: #7c3aed; }
            .btn-accent:hover { background: #6d28d9; }
            .btn-warning { background: #d97706; color: white; }
            .btn-warning:hover { background: #b45309; }

            .scope-form-box { background: #f8fafc; border: 1px solid #cbd5e1; padding: 20px; border-radius: 8px; margin-bottom: 25px; }
            .scope-form-box h3 { margin-top: 0; color: #0f172a; font-size: 15px; margin-bottom: 12px; }
            .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; align-items: flex-end; margin-top: 10px; }
            .form-field { display: flex; flex-direction: column; gap: 5px; font-size: 13px; font-weight: 600; color: #475569; }
            .form-field select, .form-field input { padding: 7px 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 13px; background: #fff; }
            .submit-btn { background: #16a34a; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; font-size: 13px; cursor: pointer; height: 35px; width: 100%; }
            .submit-btn:hover { background: #15803d; }

            .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 15px; margin-bottom: 25px; }
            .metric-card { background: #f0fdf4; border: 1px solid #bbf7d0; padding: 15px; border-radius: 8px; }
            .metric-card h3 { margin: 0 0 5px 0; font-size: 12px; color: #166534; text-transform: uppercase; }
            .metric-card p { margin: 0; font-size: 20px; font-weight: bold; color: #14532d; }

            h2 { font-size: 16px; color: #0f172a; margin-top: 25px; margin-bottom: 10px; border-bottom: 2px solid #f1f5f9; padding-bottom: 6px; display: flex; justify-content: space-between; align-items: center; }

            table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; table-layout: fixed; }
            th, td { padding: 9px 10px; text-align: left; border-bottom: 1px solid #e2e8f0; word-wrap: break-word; overflow: hidden; text-overflow: ellipsis; }
            th { background: #f8fafc; font-weight: 600; color: #475569; }
            .badge { padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; font-family: monospace; }
            .badge-intent { background: #fef3c7; color: #b45309; }
            .badge-invocation { background: #dcfce7; color: #16a34a; }

            .footer-build { margin-top: 40px; background: #f8fafc; border: 1px solid #e2e8f0; padding: 15px 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; font-size: 13px; color: #334155; }
            .btn-build { background: #475569; color: white; padding: 6px 14px; font-size: 12px; border-radius: 6px; border: none; font-weight: 600; text-decoration: none; cursor: pointer; }
            .btn-build:hover { background: #334155; }
        </style>
        {{ sortable_script|safe }}
    </head>
    <body>
        <div class="container">
            <div class="header-bar">
                <h1>VistA Enterprise Analyzer</h1>
                <div class="nav-group">
                    <a href="/impact" class="btn">Data Dictionary</a>
                    <a href="/xrf-view?filter=DG" class="btn btn-secondary">XRF Matrix</a>
                    <a href="/consistency-report" class="btn-warning btn">Consistency Report</a>
                    <a href="/network-overview?package=DG&view=package" class="btn btn-accent">Architecture</a>
                </div>
            </div>

            <!-- Clean Project Scope Request Form -->
            <div class="scope-form-box">
                <h3>📋 Architect Scope & Research Filter</h3>
                <form method="POST" action="/" id="scopeForm">
                    <div class="form-grid">
                        <div class="form-field">
                            <label for="package">Package Namespace:</label>
                            <select name="package" id="package">
                                <option value="ALL" {% if selected_pkg == 'ALL' %}selected{% endif %}>-- ALL PACKAGES --</option>
                                {% for p in available_pkgs %}
                                <option value="{{ p }}" {% if selected_pkg == p %}selected{% endif %}>{{ p }} - {{ registry.get(p, p) }}</option>
                                {% endfor %}
                            </select>
                        </div>
                        
                        <div class="form-field">
                            <label for="files_input">File Number(s) (e.g. <code>2, 200</code>):</label>
                            <input type="text" name="files_input" id="files_input" value="{{ files_input }}" placeholder="e.g. 2, 200">
                        </div>

                        <div class="form-field">
                            <label for="fields_input">Field Number(s) (e.g. <code>.01, .09</code>):</label>
                            <input type="text" name="fields_input" id="fields_input" value="{{ fields_input }}" placeholder="e.g. .01, .09, .131">
                        </div>

                        <div class="form-field">
                            <label for="global_ref">Global Reference / Root:</label>
                            <input type="text" name="global_ref" id="global_ref" value="{{ global_ref_filter }}" placeholder="e.g. ^DPT, ^VA(200)">
                        </div>

                        <div class="form-field">
                            <label for="target_routine">Report / Routine / Screen Name:</label>
                            <input type="text" name="target_routine" id="target_routine" value="{{ target_routine }}" placeholder="e.g. DGPF, VADPT">
                        </div>

                        <div class="form-field">
                            <label for="intent">Operation Intent:</label>
                            <select name="intent" id="intent">
                                <option value="ALL" {% if selected_intent == 'ALL' %}selected{% endif %}>ALL (Read, Write, Query)</option>
                                <option value="READ" {% if selected_intent == 'READ' %}selected{% endif %}>READ Only</option>
                                <option value="WRITE" {% if selected_intent == 'WRITE' %}selected{% endif %}>WRITE / Update Only</option>
                                <option value="QUERY" {% if selected_intent == 'QUERY' %}selected{% endif %}>QUERY Only</option>
                            </select>
                        </div>

                        <div class="form-field">
                            <button type="submit" class="submit-btn">🔍 Run Scope Evaluation</button>
                        </div>
                    </div>
                </form>
            </div>

            <h2>📊 Executive Scope Summary</h2>
            <div class="summary-grid">
                <div class="metric-card">
                    <h3>Total Affected Touchpoints</h3>
                    <p>{{ "{:,}".format(scope_summary.total) }}</p>
                </div>
                <div class="metric-card">
                    <h3>Read Operations</h3>
                    <p>{{ "{:,}".format(scope_summary.reads) }}</p>
                </div>
                <div class="metric-card">
                    <h3>Write / Update Operations</h3>
                    <p>{{ "{:,}".format(scope_summary.writes) }}</p>
                </div>
                <div class="metric-card">
                    <h3>Query Operations</h3>
                    <p>{{ "{:,}".format(scope_summary.queries) }}</p>
                </div>
            </div>

            <h2>
                <span>📋 Actionable Remediation & Research Register</span>
                <span>
                    <button type="button" class="btn" style="font-size: 11px; padding: 4px 8px;" onclick="printSelectedRows()">🖨️️ Print Selected Rows</button>
                </span>
            </h2>
            <table id="remediationTable">
                <thead>
                    <tr>
                        <th style="width: 4%; text-align: center;"><input type="checkbox" id="selectAll" onclick="toggleSelectAll(this)"></th>
                        <th class="sortable" onclick="sortTable('remediationTable', 1)" style="width: 15%;">Routine</th>
                        <th class="sortable" onclick="sortTable('remediationTable', 2, true)" style="width: 7%;">Line</th>
                        <th class="sortable" onclick="sortTable('remediationTable', 3)" style="width: 12%;">File / Field</th>
                        <th class="sortable" onclick="sortTable('remediationTable', 4)" style="width: 10%;">Intent</th>
                        <th class="sortable" onclick="sortTable('remediationTable', 5)" style="width: 10%;">Invocation</th>
                        <th class="sortable" onclick="sortTable('remediationTable', 6)" style="width: 42%;">Operation Context</th>
                    </tr>
                </thead>
                <tbody>
                    {% for r in scope_results %}
                    <tr>
                        <td style="text-align: center;"><input type="checkbox" name="selected_row" value="{{ r.id }}"></td>
                        <td><a href="/routine-inspect/{{ r.routine_name }}?highlight={{ r.line_number }}&mode=summary" style="font-family:monospace; color:#2563eb; font-weight:bold; text-decoration:none;">{{ r.routine_name }}</a></td>
                        <td style="font-family: monospace;">{{ r.line_number }}</td>
                        <td style="font-family: monospace; color: #16a34a;">{{ r.file_number or 'N/A' }} {% if r.field_number %}({{ r.field_number }}){% endif %}</td>
                        <td><span class="badge badge-intent">{{ r.op_intent or 'READ' }}</span></td>
                        <td><span class="badge badge-invocation">{{ r.invocation_type or 'MUMPS' }}</span></td>
                        <td style="font-family: monospace; font-size: 12px; color: #334155; word-break: break-all;">{{ r.op_context }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>

            <div class="footer-build">
                <span>📦 <code>dynamic_dataset.db</code> active database container</span>
                <a href="/build-control-hub" class="btn-build">⚙️ Build & Ad-Hoc Explorer</a>
            </div>
        </div>
    </body>
    </html>
    """, available_pkgs=available_pkgs, registry=registry, selected_pkg=selected_pkg, files_input=files_input, fields_input=fields_input, target_routine=target_routine, global_ref_filter=global_ref_filter, selected_intent=selected_intent, scope_results=scope_results, scope_summary=scope_summary, sortable_script=SORTABLE_TABLE_SCRIPT)

# ==========================================
# STREAMING BUILD ROUTE
# ==========================================
@app.route('/build-database', methods=['POST'])
def build_database():
    inc_reads = 'inc_reads' in request.form
    inc_writes = 'inc_writes' in request.form
    inc_queries = 'inc_queries' in request.form
    inc_pkg_calls = 'inc_pkg_calls' in request.form
    inc_installs = 'inc_installs' in request.form

    custom_label_1 = request.form.get('custom_label_1', '').strip()
    custom_query_1 = request.form.get('custom_query_1', '').strip()
    custom_label_2 = request.form.get('custom_label_2', '').strip()
    custom_query_2 = request.form.get('custom_query_2', '').strip()

    def generate():
        yield """
        <!doctype html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Building Master Index</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }
                .card { max-width: 900px; margin: 0 auto; background: #1e293b; padding: 30px; border-radius: 10px; border: 1px solid #334155; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.3); }
                h2 { margin-top: 0; color: #38bdf8; font-size: 20px; border-bottom: 1px solid #334155; padding-bottom: 12px; }
                .console { background: #090d16; padding: 15px; border-radius: 6px; border: 1px solid #1e293b; height: 320px; overflow-y: auto; font-family: monospace; font-size: 13px; line-height: 1.6; color: #cbd5e1; }
                .pkg-line { margin: 4px 0; display: flex; justify-content: space-between; border-bottom: 1px dashed #1e293b; padding-bottom: 2px; }
                .pkg-name { color: #38bdf8; font-weight: bold; }
                .pkg-count { color: #10b981; font-weight: bold; }
                .pkg-err { color: #ef4444; font-weight: bold; }
                .btn { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #2563eb; color: #fff; text-decoration: none; border-radius: 6px; font-weight: 600; text-align: center; }
                .btn:hover { background: #1d4ed8; }
                .anomaly-box { margin-top: 20px; background: #090d16; border: 1px solid #ef4444; padding: 15px; border-radius: 6px; max-height: 200px; overflow-y: auto; font-family: monospace; font-size: 12px; color: #fca5a5; }
            </style>
        </head>
        <body>
            <div class="card">
                <h2>⚙️ Parametric Build & Master Index Generation</h2>
                <p style="color: #94a3b8; font-size: 13px;">Executing build with dynamic invocation classifications...</p>
                <div class="console" id="console">
        """
        
        conn = sqlite3.connect(DB_PATH, timeout=60.0)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vista_routines_clean (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                routine_name TEXT,
                line_number TEXT,
                node_value TEXT
            );
        """)
        conn.commit()

        cursor.execute("SELECT COUNT(*) FROM vista_routines_clean;")
        routine_count = cursor.fetchone()[0]

        if routine_count > 0:
            yield f"<p style='color: #10b981;'>📦 Verified active <code>vista_routines_clean</code> corpus ({routine_count:,} records ready).</p>"
        elif os.path.exists('ROUTINE.txt'):
            yield "<p style='color: #38bdf8;'>📥 Ingesting raw routines from <code>ROUTINE.txt</code> into <code>vista_routines_clean</code>...</p>"
            routine_global_regex = re.compile(r'\^ROUTINE\("([^"]+)",0,([0-9]+)\)')
            inserted_lines = 0
            batch_lines = []

            with open('ROUTINE.txt', 'r', encoding='utf-8', errors='ignore') as f:
                current_routine = None
                current_line_no = None
                
                for line in f:
                    line_str = line.rstrip('\n').rstrip('\r')
                    match = routine_global_regex.match(line_str)
                    if match:
                        current_routine = match.group(1).upper()
                        current_line_no = match.group(2)
                    elif current_routine and current_line_no is not None:
                        clean_content = line_str.strip('"')
                        batch_lines.append((current_routine, current_line_no, clean_content))
                        inserted_lines += 1
                        
                        if len(batch_lines) >= 5000:
                            cursor.executemany("""
                                INSERT INTO vista_routines_clean (routine_name, line_number, node_value)
                                VALUES (?, ?, ?);
                            """, batch_lines)
                            conn.commit()
                            batch_lines = []
                        
                        current_routine = None
                        current_line_no = None

            if batch_lines:
                cursor.executemany("""
                    INSERT INTO vista_routines_clean (routine_name, line_number, node_value)
                    VALUES (?, ?, ?);
                """, batch_lines)
                conn.commit()

            yield f"<p style='color: #10b981;'>✅ Successfully ingested {inserted_lines:,} lines into <code>vista_routines_clean</code>.</p>"
        else:
            yield "<p style='color: #ef4444;'>❌ Error: No populated vista_routines_clean table and ROUTINE.txt not found!</p>"

        registry = get_package_registry()
        cursor.execute("DROP TABLE IF EXISTS architectural_xrf;")
        cursor.execute("DROP TABLE IF EXISTS preprocessor_anomalies;")
        cursor.execute("""
            CREATE TABLE architectural_xrf (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                routine_name TEXT,
                line_number TEXT,
                analysis_code TEXT,
                file_number TEXT,
                field_number TEXT,
                op_intent TEXT,
                invocation_type TEXT,
                target_entity TEXT,
                op_context TEXT
            );
        """)
        cursor.execute("""
            CREATE TABLE preprocessor_anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_ns TEXT,
                routine_name TEXT,
                error_message TEXT,
                node_snippet TEXT
            );
        """)
        conn.commit()

        total_committed = 0
        global_regex = re.compile(r'(\^[a-zA-Z0-9%]+(?:\([^\)]+\))?)')
        file_regex = re.compile(r'\b(?:DIC|DIK|DIE|DIQ|GET1\^DIQ|dic|dik|die|diq)\s*\(\s*([0-9]+(?:\.[0-9]+)?)', re.IGNORECASE)
        field_regex = re.compile(r'"[^"]*?([0-9]+(?:\.[0-9]+)?(?:[;:][0-9]+(?:\.[0-9]+)?)*)[^"]*?"')

        adhoc_terms_1 = [t.strip().upper() for t in custom_query_1.split(',') if t.strip()]
        adhoc_terms_2 = [t.strip().upper() for t in custom_query_2.split(',') if t.strip()]

        for ns, desc in registry.items():
            try:
                cursor.execute("""
                    SELECT routine_name, line_number, node_value 
                    FROM vista_routines_clean 
                    WHERE routine_name LIKE ?;
                """, (f"{ns}%",))
                
                routine_rows = cursor.fetchall()
                if not routine_rows:
                    continue
                    
                batch_records = []
                ns_matches = 0
                seen_line_interactions = set()
                
                for r in routine_rows:
                    rname = 'UNKNOWN'
                    lineno = '1'
                    code = ''
                    try:
                        rname = (r[0] or '').upper().strip()
                        if rname.startswith('%') or rname.startswith('^%'):
                            continue

                        is_patch_routine = bool(re.match(r'^[A-Z]{2,4}[0-9]', rname))
                        if not inc_installs and is_patch_routine:
                            continue
                            
                        lineno = str(r[1] or '1')
                        raw_code = r[2] or ''
                        code = raw_code.split(';')[0].strip()
                        if not code:
                            continue

                        code_upper = code.upper()

                        if adhoc_terms_1 and any(term in code_upper for term in adhoc_terms_1):
                            batch_records.append((rname, lineno, 'AD-HOC', None, None, 'CUSTOM', custom_label_1 or 'Ad-Hoc 1', custom_label_1 or 'Custom Match', code))
                            ns_matches += 1
                            continue

                        if adhoc_terms_2 and any(term in code_upper for term in adhoc_terms_2):
                            batch_records.append((rname, lineno, 'AD-HOC', None, None, 'CUSTOM', custom_label_2 or 'Ad-Hoc 2', custom_label_2 or 'Custom Match 2', code))
                            ns_matches += 1
                            continue

                        global_matches = global_regex.findall(code)
                        targets = global_matches if global_matches else [rname]

                        for target in targets:
                            clean_target_root = target.lstrip('^').split('(')[0].upper()
                            
                            if clean_target_root.startswith('%') or clean_target_root in {'TMP', 'XTMP', 'UT', 'UTILITY', 'XUTL', 'ADIE', 'ADDIOL', 'DIR', 'DIC', 'DIK', 'DIQ', 'B', rname.upper()}:
                                continue

                            if 'DIR(0)' in code_upper and re.search(r'[S|SO]\^[A-Z]', code_upper):
                                continue

                            if '"' in code:
                                unquoted_code = re.sub(r'"[^"]*"', '""', code_upper)
                                if target.upper() not in unquoted_code:
                                    continue

                            ctx = evaluate_mumps_context(code_upper, target, rname)
                            if not ctx['is_valid_data_op']:
                                continue

                            op_intent = ctx['op_intent']
                            invocation_type = ctx['invocation_type']

                            if invocation_type == 'PACKAGE_CALL' and not inc_pkg_calls:
                                continue
                            if op_intent == 'READ' and not inc_reads:
                                continue
                            if op_intent == 'WRITE' and not inc_writes:
                                continue
                            if op_intent == 'QUERY' and not inc_queries:
                                continue

                            analysis_code = op_intent
                            file_match = file_regex.search(code)
                            file_number = file_match.group(1) if file_match else None

                            if not file_number:
                                if '^DPT' in code_upper or '^DPT(' in target: file_number = '2'
                                elif '^VA(200)' in code_upper or '^VA\\(200' in target: file_number = '200'
                                elif '^DIC(4)' in code_upper: file_number = '4'
                                elif '^EAS' in code_upper: file_number = '712'

                            field_matches = field_regex.findall(code)
                            extracted_fields = set()
                            for fm in field_matches:
                                for part in re.split(r'[;:]', fm):
                                    if part and ('.' in part or len(part) <= 4):
                                        extracted_fields.add(part)

                            interaction_key = (rname, lineno, file_number or '', target)
                            if interaction_key in seen_line_interactions:
                                continue
                            seen_line_interactions.add(interaction_key)

                            if extracted_fields:
                                for fno in extracted_fields:
                                    batch_records.append((rname, lineno, analysis_code, file_number, fno, op_intent, invocation_type, target, code))
                                    ns_matches += 1
                            else:
                                batch_records.append((rname, lineno, analysis_code, file_number, None, op_intent, invocation_type, target, code))
                                ns_matches += 1
                    except Exception as line_err:
                        cursor.execute("""
                            INSERT INTO preprocessor_anomalies (package_ns, routine_name, error_message, node_snippet)
                            VALUES (?, ?, ?, ?);
                        """, (ns, rname, str(line_err), code[:200]))
                        conn.commit()

                if batch_records:
                    cursor.executemany("""
                        INSERT INTO architectural_xrf (routine_name, line_number, analysis_code, file_number, field_number, op_intent, invocation_type, target_entity, op_context)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, batch_records)
                    conn.commit()
                    total_committed += len(batch_records)

                if ns_matches > 0:
                    yield f"<div class='pkg-line'><span>📦 Namespace <span class='pkg-name'>[{ns}]</span> {desc}</span><span class='pkg-count'>{ns_matches:,} touchpoints (Running Total: {total_committed:,})</span></div>"
            except Exception as pkg_err:
                yield f"<div class='pkg-line'><span>📦 Namespace <span class='pkg-name'>[{ns}]</span> {desc}</span><span class='pkg-err'>Failed: {pkg_err}</span></div>"
                cursor.execute("""
                    INSERT INTO preprocessor_anomalies (package_ns, routine_name, error_message, node_snippet)
                    VALUES (?, ?, ?, ?);
                """, (ns, 'PACKAGE_LEVEL', str(pkg_err), 'Package iteration halted'))
                conn.commit()
                continue

        cursor.execute("SELECT COUNT(*) FROM architectural_xrf;")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT analysis_code, COUNT(*) FROM architectural_xrf GROUP BY analysis_code;")
        intent_summary_dict = dict(cursor.fetchall())
        intent_str = f"Read: {intent_summary_dict.get('READ', 0)}, Write: {intent_summary_dict.get('WRITE', 0)}, Query: {intent_summary_dict.get('QUERY', 0)}, Custom: {intent_summary_dict.get('CUSTOM', 0)}"

        cursor.execute("SELECT invocation_type, COUNT(*) FROM architectural_xrf GROUP BY invocation_type;")
        inv_summary_dict = dict(cursor.fetchall())
        inv_str = f"MUMPS: {inv_summary_dict.get('MUMPS', 0)}, FileMan: {inv_summary_dict.get('FILEMAN', 0)}, PkgCall: {inv_summary_dict.get('PACKAGE_CALL', 0)}, AdHoc: {inv_summary_dict.get('AD-HOC', 0)}"

        cursor.execute("SELECT package_ns, routine_name, error_message, node_snippet FROM preprocessor_anomalies;")
        anomalies = cursor.fetchall()
        conn.close()

        log_build_version(total, intent_str, inv_str, custom_label_1 or (custom_query_1 if custom_query_1 else "Standard Baseline"), custom_label_2 or custom_query_2)

        yield f"""
                </div>
                <div style="margin-top: 20px; display: flex; justify-content: space-between; align-items: center;">
                    <span style="color: #10b981; font-weight: bold;">✨ Build Complete! Total Indexed Records: {total:,} | Anomalies: {len(anomalies)}</span>
                    <a href="/" class="btn">Return to Home</a>
                </div>
        """

        if anomalies:
            yield """
                <div style="margin-top: 15px;">
                    <strong style="color: #fca5a5; font-size: 13px;">⚠️ Consistency Anomaly Report:</strong>
                    <div class="anomaly-box"><pre>"""
            for anom in anomalies:
                yield f"[{anom[0]}] Routine: {anom[1]} | Error: {anom[2]}\n   Snippet: {anom[3]}\n\n"
            yield """</pre></div>
                </div>
            """

        yield """
            </div>
            <script>
                var c = document.getElementById('console');
                c.scrollTop = c.scrollHeight;
            </script>
        </body>
        </html>
        """
    return app.response_class(generate(), mimetype='text/html')

# ==========================================
# DATA DICTIONARY BROWSER
# ==========================================
@app.route('/impact', methods=['GET', 'POST'])
def impact_analysis():
    search_file = request.args.get('file', '').strip()
    inspect_field = request.args.get('field', '').strip()
    inspect_fno = request.args.get('fno', '').strip()
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    file_desc = get_file_description(search_file) if search_file else ""
    available_files = []

    if search_file and (inspect_field or inspect_fno):
        cursor.execute("""
            SELECT id, routine_name, line_number, analysis_code, file_number, field_number, op_intent, invocation_type, target_entity, op_context 
            FROM architectural_xrf 
            WHERE file_number = ? 
              AND (field_number = ? OR UPPER(target_entity) LIKE UPPER(?) OR UPPER(op_context) LIKE UPPER(?) OR UPPER(op_context) LIKE UPPER(?))
            ORDER BY routine_name ASC, line_number ASC 
            LIMIT 500;
        """, (search_file, inspect_fno, f"%{inspect_field}%", f"%{inspect_field}%", f"%{inspect_fno}%"))
        field_rows = cursor.fetchall()
        conn.close()

        html_field_template = """
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>DD Field References: File {{ search_file }} - Field {{ inspect_field or inspect_fno }}</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 30px; }
                .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
                .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
                h1 { margin: 0; color: #0f172a; font-size: 22px; }
                .nav-btn { display: inline-block; padding: 6px 14px; background: #e2e8f0; color: #334155; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 13px; }
                .nav-btn:hover { background: #cbd5e1; }
                table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; table-layout: fixed; }
                th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; word-wrap: break-word; overflow: hidden; text-overflow: ellipsis; }
                th { background: #f8fafc; font-weight: 600; color: #475569; }
                .badge { padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; font-family: monospace; background: #e0f2fe; color: #0369a1; }
                .badge-intent { background: #fef3c7; color: #b45309; }
                .badge-invocation { background: #dcfce7; color: #16a34a; }
                .routine-link { color: #2563eb; text-decoration: none; font-weight: bold; font-family: monospace; }
            </style>
            {{ sortable_script|safe }}
        </head>
        <body>
            <div class="container">
                <div class="header-bar">
                    <div style="display: flex; gap: 15px; align-items: center;">
                        <a href="/impact?file={{ search_file }}" class="nav-btn">← Back to File Fields</a>
                        <h1>File {{ search_file }} ({{ file_desc }}) ➔ Field: <span style="color:#2563eb;">{{ inspect_field or inspect_fno }}</span></h1>
                    </div>
                    <span style="font-size: 13px; color: #64748b;">Found <strong>{{ field_rows|length }}</strong> routine references</span>
                </div>
                <p style="color: #475569; font-size: 13px;">Showing context-evaluated routine references for File <strong>{{ search_file }}</strong> field <strong>{{ inspect_field or inspect_fno }}</strong>. <em>Click headers to sort.</em></p>
                <table id="fieldRefTable">
                    <thead>
                        <tr>
                            <th class="sortable" onclick="sortTable('fieldRefTable', 0)" style="width: 15%;">Routine</th>
                            <th class="sortable" onclick="sortTable('fieldRefTable', 1, true)" style="width: 7%;">Line</th>
                            <th class="sortable" onclick="sortTable('fieldRefTable', 2)" style="width: 12%;">Type</th>
                            <th class="sortable" onclick="sortTable('fieldRefTable', 3)" style="width: 12%;">Invocation</th>
                            <th class="sortable" onclick="sortTable('fieldRefTable', 4)" style="width: 18%;">Target Entity</th>
                            <th class="sortable" onclick="sortTable('fieldRefTable', 5)" style="width: 36%;">Operation Context</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for r in field_rows %}
                        <tr>
                            <td><a href="/routine-inspect/{{ r.routine_name }}?highlight={{ r.line_number }}&mode=summary" class="routine-link">{{ r.routine_name }}</a></td>
                            <td style="font-family: monospace;">{{ r.line_number }}</td>
                            <td><span class="badge badge-intent">{{ r.op_intent or 'READ' }}</span></td>
                            <td><span class="badge badge-invocation">{{ r.invocation_type or 'MUMPS' }}</span></td>
                            <td style="font-family: monospace; color: #0284c7;">{{ r.target_entity }}</td>
                            <td style="font-family: monospace; font-size: 12px; color: #334155; word-break: break-all;">{{ r.op_context }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        return render_template_string(html_field_template, search_file=search_file, file_desc=file_desc, inspect_field=inspect_field, inspect_fno=inspect_fno, field_rows=field_rows, sortable_script=SORTABLE_TABLE_SCRIPT)

    fields_list = []
    if search_file:
        base_global_map = {'2': '^DPT', '200': '^VA(200)', '4': '^DIC(4)', '50': '^PSDRUG', '52': '^PSRX'}
        default_global = base_global_map.get(search_file, f"^DIC({search_file})")

        cursor.execute("""
            SELECT field_number, value FROM vista_dd 
            WHERE file_number = ? AND field_number != '0'
            ORDER BY CAST(field_number AS REAL) ASC;
        """, (search_file,))
        dd_rows = cursor.fetchall()
        
        seen_fields = set()
        for fno, val in dd_rows:
            if not fno:
                continue
            
            try:
                num_val = float(fno)
                if num_val <= 0:
                    continue
            except ValueError:
                continue

            if fno in seen_fields:
                continue
            seen_fields.add(fno)
            
            raw_val = (val or '').strip()
            parts = raw_val.split('^')
            
            fname = parts[0].strip() if len(parts) > 0 else f"FIELD_{fno}"
            if fname.startswith(str(fno)):
                fname = fname[len(str(fno)):].strip()
            
            if not fname or fname.startswith('$') or len(fname) > 40:
                fname = f"FIELD_{fno}"

            ftype = "STANDARD"
            type_code = parts[1].strip() if len(parts) > 1 else ""
            if 'P' in type_code or any('P' in p for p in parts[:3]): ftype = 'POINTER'
            elif 'S' in type_code or any('S' in p for p in parts[:3]): ftype = 'SET'
            elif 'D' in type_code or any('D' in p for p in parts[:3]): ftype = 'DATE/TIME'
            elif 'F' in type_code or any('F' in p for p in parts[:3]): ftype = 'FREE TEXT'
            elif 'N' in type_code or any('N' in p for p in parts[:3]): ftype = 'NUMERIC'

            node_val = '0'
            piece_val = '1'
            np_match = re.search(r'\b([A-Z0-9\.]+;[0-9]+)\b', raw_val, re.IGNORECASE)
            if np_match:
                np_parts = np_match.group(1).split(';')
                node_val = np_parts[0]
                piece_val = np_parts[1]

            global_ref = f"{default_global}(D0,{node_val}) [Piece {piece_val}]"
            fdesc = raw_val if len(raw_val) < 90 else f"File {search_file} Data Dictionary Element {fno}"
            
            fields_list.append({
                'num': str(fno),
                'name': fname.upper(),
                'type': ftype.upper(),
                'global_ref': global_ref,
                'desc': fdesc
            })
            
        if not fields_list:
            fields_list = [
                { 'num': '.01', 'name': 'NAME', 'type': 'FREE TEXT', 'global_ref': f"{default_global}(D0,0) [Piece 1]", 'desc': f'Primary key field for File {search_file}' }
            ]

    conn.close()

    html_file_template = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Data Dictionary Browser</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 30px; }
            .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
            .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 15px; }
            h1 { margin: 0; color: #0f172a; font-size: 22px; }
            .nav-btn { display: inline-block; padding: 6px 14px; background: #e2e8f0; color: #334155; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 13px; }
            .nav-btn:hover { background: #cbd5e1; }
            .filter-form { display: flex; gap: 15px; align-items: center; margin-bottom: 20px; background: #f8fafc; padding: 15px; border-radius: 8px; border: 1px solid #e2e8f0; flex-wrap: wrap; }
            input[type="text"] { padding: 6px 12px; border-radius: 6px; border: 1px solid #cbd5e1; font-size: 13px; background: #fff; width: 200px; }
            .action-btn { padding: 6px 14px; background: #2563eb; color: white; border: none; border-radius: 6px; font-weight: 600; font-size: 13px; cursor: pointer; }
            .action-btn:hover { background: #1d4ed8; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; table-layout: fixed; }
            th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; word-wrap: break-word; overflow: hidden; text-overflow: ellipsis; }
            th { background: #f8fafc; font-weight: 600; color: #475569; }
            .field-link { color: #2563eb; text-decoration: none; font-weight: bold; font-family: monospace; }
            .field-link:hover { text-decoration: underline; }
        </style>
        {{ sortable_script|safe }}
    </head>
    <body>
        <div class="container">
            <div class="header-bar">
                <a href="/" class="nav-btn">← Home</a>
                <h1>Data Dictionary (FileMan Schema)</h1>
            </div>
            
            <form method="GET" action="/impact" class="filter-form">
                <div>
                    <label for="file" style="font-weight: 600; font-size: 13px; display: block; margin-bottom: 4px;">Enter File Number</label>
                    <div style="display: flex; gap: 8px;">
                        <input type="text" name="file" id="file" value="{{ search_file }}" placeholder="e.g. 2, 200, 2.01" autofocus>
                        <button type="submit" class="action-btn">Load File Fields</button>
                    </div>
                </div>
            </form>

            {% if search_file %}
            <div style="margin-bottom: 15px; background: #eff6ff; border: 1px solid #bfdbfe; padding: 12px 16px; border-radius: 6px; display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 15px; font-weight: bold; color: #1e40af;">📂 File {{ search_file }}: {{ file_desc }}</span>
                <span style="font-size: 13px; color: #3b82f6;">Showing <strong>{{ fields_list|length }}</strong> numeric data fields</span>
            </div>
            <table id="fieldsTable">
                <thead>
                    <tr>
                        <th class="sortable" onclick="sortTable('fieldsTable', 0, true)" style="width: 10%;">Field #</th>
                        <th class="sortable" onclick="sortTable('fieldsTable', 1)" style="width: 22%;">Field Name</th>
                        <th class="sortable" onclick="sortTable('fieldsTable', 2)" style="width: 15%;">Data Type</th>
                        <th class="sortable" onclick="sortTable('fieldsTable', 3)" style="width: 28%;">Global Reference</th>
                        <th class="sortable" onclick="sortTable('fieldsTable', 4)" style="width: 25%;">Description</th>
                    </tr>
                </thead>
                <tbody>
                    {% for fd in fields_list %}
                    <tr>
                        <td style="font-family: monospace; font-weight: bold; color: #16a34a;">{{ fd.num }}</td>
                        <td><a href="/impact?file={{ search_file }}&field={{ fd.name }}&fno={{ fd.num }}" class="field-link">{{ fd.name }}</a></td>
                        <td style="font-family: monospace; color: #0284c7;">{{ fd.type }}</td>
                        <td style="font-family: monospace; color: #d97706; font-weight: 600; font-size: 12px;">{{ fd.global_ref }}</td>
                        <td style="color: #334155; font-size: 13px;">{{ fd.desc }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p style="color: #64748b; font-size: 14px; text-align: center; padding: 40px;">Type a FileMan file number (e.g. <code>2</code> or <code>200</code>) above and press Enter or click <strong>Load File Fields</strong>.</p>
            {% endif %}
        </div>
    </body>
    </html>
    """
    return render_template_string(html_file_template, available_files=available_files, search_file=search_file, file_desc=file_desc, fields_list=fields_list, sortable_script=SORTABLE_TABLE_SCRIPT)

# ==========================================
# DUAL-TIER PIVOT ARCHITECTURE WORKSPACE
# ==========================================
@app.route('/network-overview')
def network_overview():
    target_pkg = request.args.get('package', 'DG').upper().strip()
    inv_filter = request.args.get('inv', 'ALL').upper().strip()
    intent_filter = request.args.get('intent', 'ALL').upper().strip()

    available_pkgs = get_available_packages()
    available_invs = get_available_invocations()
    registry = get_package_registry()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT routine_name, target_entity, op_context, invocation_type, op_intent 
        FROM architectural_xrf 
        WHERE UPPER(routine_name) LIKE UPPER(?) 
        LIMIT 5000;
    """, (f"{target_pkg}%",))
    ref_rows = cursor.fetchall()
    conn.close()

    peer_weights = {}
    for p in available_pkgs:
        if p == target_pkg:
            continue
        match_count = 0
        for ref in ref_rows:
            if inv_filter != 'ALL' and (ref['invocation_type'] or 'MUMPS').upper() != inv_filter:
                continue
            if intent_filter != 'ALL' and (ref['op_intent'] or 'READ').upper() != intent_filter:
                continue

            if is_strict_peer_reference(ref['target_entity'], ref['op_context'], target_pkg, p):
                match_count += 1
        if match_count > 0:
            peer_weights[p] = match_count

    pkg_title = registry.get(target_pkg, f"Package Namespace ({target_pkg})")

    html_template = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Architecture - {{ target_pkg }}</title>
        <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 20px; }
            .container { max-width: 98vw; width: 100%; margin: 0 auto; background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); box-sizing: border-box; }
            .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 15px; }
            .header-left { display: flex; align-items: center; gap: 15px; }
            h1 { margin: 0; color: #0f172a; font-size: 22px; }
            .nav-btn { display: inline-block; padding: 6px 14px; background: #e2e8f0; color: #334155; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 13px; }
            .nav-btn:hover { background: #cbd5e1; }
            
            .workspace-layout { display: grid; grid-template-columns: 260px 1fr; gap: 20px; align-items: start; }
            .sidebar-legend { background: #f8fafc; border: 1px solid #e2e8f0; padding: 15px; border-radius: 8px; font-size: 12px; }
            .sidebar-legend h3 { margin-top: 0; font-size: 14px; color: #0f172a; border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; }
            .filter-group-sidebar { margin-bottom: 15px; display: flex; flex-direction: column; gap: 6px; }
            .filter-group-sidebar label { font-weight: 600; color: #475569; }
            .filter-group-sidebar select { padding: 5px 8px; border-radius: 6px; border: 1px solid #cbd5e1; font-size: 12px; background: #fff; cursor: pointer; }
            .legend-item { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; font-weight: 500; color: #334155; }
            .legend-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }

            .btn-sidebar { padding: 5px 10px; background: #2563eb; color: white; border: none; border-radius: 6px; font-weight: 600; font-size: 12px; cursor: pointer; width: 100%; margin-top: 5px; }
            .btn-sidebar:hover { background: #1d4ed8; }

            #network-container { width: 100%; height: 74vh; border: 1px solid #cbd5e1; border-radius: 8px; background: #fafafa; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header-bar">
                <div class="header-left">
                    <a href="/" class="nav-btn">← Home</a>
                    <h1>{{ pkg_title }} ({{ target_pkg }}) – Architecture Workspace</h1>
                </div>
            </div>

            <div class="workspace-layout">
                <div class="sidebar-legend">
                    <h3>🎨 Architectural Controls</h3>
                    <form method="GET" action="/network-overview">
                        <div class="filter-group-sidebar">
                            <label for="pkgSelect">Focus Hub:</label>
                            <select name="package" id="pkgSelect" onchange="this.form.submit()">
                                {% for p in available_pkgs %}
                                <option value="{{ p }}" {% if p == target_pkg %}selected{% endif %}>{{ p }} - {{ pkg_registry.get(p, p) }}</option>
                                {% endfor %}
                            </select>
                        </div>

                        <div class="filter-group-sidebar">
                            <label for="inv">Invocation Type:</label>
                            <select name="inv" id="inv">
                                <option value="ALL" {% if inv_filter == 'ALL' %}selected{% endif %}>ALL (Dynamic Invocations)</option>
                                {% for inv in available_invs %}
                                <option value="{{ inv }}" {% if inv_filter == inv %}selected{% endif %}>{{ inv }}</option>
                                {% endfor %}
                            </select>
                        </div>

                        <div class="filter-group-sidebar">
                            <label for="intent">Operation Intent:</label>
                            <select name="intent" id="intent">
                                <option value="ALL" {% if intent_filter == 'ALL' %}selected{% endif %}>ALL (Read, Write, Query)</option>
                                <option value="READ" {% if intent_filter == 'READ' %}selected{% endif %}>Read Only</option>
                                <option value="WRITE" {% if intent_filter == 'WRITE' %}selected{% endif %}>Write / Update Only</option>
                                <option value="QUERY" {% if intent_filter == 'QUERY' %}selected{% endif %}>Query Only</option>
                            </select>
                        </div>

                        <button type="submit" class="btn-sidebar">Apply Filters</button>
                    </form>

                    <h3 style="margin-top: 20px;">📌 Node Legend</h3>
                    <div class="legend-item"><span class="legend-dot" style="background: #16a34a;"></span> Focal Hub Package</div>
                    <div class="legend-item"><span class="legend-dot" style="background: #cbd5e1;"></span> Interacting Peer Package</div>
                    <div class="legend-item"><span class="legend-dot" style="background: #3b82f6;"></span> Dependency Edge (Blue)</div>
                </div>

                <div id="network-container"></div>
            </div>
        </div>
        <script type="text/javascript">
            var targetPkg = "{{ target_pkg }}";
            var invFilter = "{{ inv_filter }}";
            var intentFilter = "{{ intent_filter }}";
            var pkgRegistry = {{ pkg_registry|tojson }};
            
            var focalDesc = pkgRegistry[targetPkg] || 'Package';
            var focalLabel = targetPkg + '\\n(Focal Hub)';

            var nodesArray = [{ 
                id: targetPkg, 
                label: focalLabel, 
                title: targetPkg + ': ' + focalDesc + ' (Click to view touchpoints)',
                shape: 'box', size: 60, 
                font: { color: '#14532d', face: 'arial', size: 15, bold: true }, 
                color: { background: '#dcfce7', border: '#16a34a' }
            }];
            var edgesArray = [];

            var peerWeights = {{ peer_weights|tojson }};
            for (var peer in peerWeights) {
                var weight = peerWeights[peer];
                var peerDesc = pkgRegistry[peer] || 'Package';
                var peerLabel = peer + '\\n(' + weight + ' refs)';
                nodesArray.push({
                    id: peer, 
                    label: peerLabel, 
                    title: peer + ': ' + peerDesc + ' (Click to view interaction)',
                    shape: 'box',
                    font: { face: 'arial', color: '#1e293b', size: 13, bold: true },
                    color: { background: '#f1f5f9', border: '#cbd5e1' }
                });
                edgesArray.push({
                    id: targetPkg + '->' + peer,
                    from: targetPkg, to: peer, 
                    arrows: 'to',
                    title: 'Click to inspect interaction between ' + targetPkg + ' and ' + peer,
                    color: { color: '#3b82f6', highlight: '#1d4ed8' }
                });
            }

            var nodes = new vis.DataSet(nodesArray);
            var edges = new vis.DataSet(edgesArray);
            var container = document.getElementById('network-container');
            var network = new vis.Network(container, { nodes: nodes, edges: edges }, {
                nodes: { borderWidth: 2, shadow: true },
                edges: { width: 2, smooth: { type: 'cubicBezier', roundness: 0.3 } },
                physics: { 
                    barnesHut: { 
                        gravitationalConstant: -7500, 
                        centralGravity: 0.4,
                        springLength: 160,
                        springConstant: 0.04
                    } 
                }
            });

            network.on("click", function (params) {
                if (params.nodes.length > 0) {
                    var clickedNodeId = params.nodes[0];
                    if (clickedNodeId === targetPkg) {
                        window.location.href = '/package-touchpoints?package=' + targetPkg + '&inv=' + invFilter + '&intent=' + intentFilter;
                    } else {
                        window.location.href = '/package-interaction?source=' + targetPkg + '&target=' + clickedNodeId + '&inv=' + invFilter + '&intent=' + intentFilter;
                    }
                }
            });
        </script>
    </body>
    </html>
    """
    return render_template_string(html_template, target_pkg=target_pkg, available_pkgs=available_pkgs, available_invs=available_invs, peer_weights=peer_weights, pkg_title=pkg_title, pkg_registry=registry, inv_filter=inv_filter, intent_filter=intent_filter)

# ==========================================
# INTER-PACKAGE INTERACTION INSPECTOR
# ==========================================
@app.route('/package-interaction')
def package_interaction():
    source_pkg = request.args.get('source', 'DG').upper().strip()
    target_pkg = request.args.get('target', 'IVM').upper().strip()
    inv_filter = request.args.get('inv', 'ALL').upper().strip()
    intent_filter = request.args.get('intent', 'ALL').upper().strip()
    registry = get_package_registry()

    source_title = registry.get(source_pkg, source_pkg)
    target_title = registry.get(target_pkg, target_pkg)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, routine_name, line_number, analysis_code, file_number, op_intent, invocation_type, target_entity, op_context 
        FROM architectural_xrf 
        WHERE UPPER(routine_name) LIKE UPPER(?) 
        LIMIT 5000;
    """, (f"{source_pkg}%",))
    raw_rows = cursor.fetchall()
    conn.close()

    rows = []
    for r in raw_rows:
        if inv_filter != 'ALL' and (r['invocation_type'] or 'MUMPS').upper() != inv_filter:
            continue
        if intent_filter != 'ALL' and (r['op_intent'] or 'READ').upper() != intent_filter:
            continue
        if is_strict_peer_reference(r['target_entity'], r['op_context'], source_pkg, target_pkg):
            rows.append(r)

    html_template = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Interaction: {{ source_pkg }} → {{ target_pkg }}</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 30px; }
            .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
            .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            h1 { margin: 0; color: #0f172a; font-size: 22px; }
            .nav-btn { display: inline-block; padding: 6px 14px; background: #e2e8f0; color: #334155; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 13px; }
            .nav-btn:hover { background: #cbd5e1; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; table-layout: fixed; }
            th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; word-wrap: break-word; overflow: hidden; text-overflow: ellipsis; }
            th { background: #f8fafc; font-weight: 600; color: #475569; }
            .badge { padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; font-family: monospace; background: #e0f2fe; color: #0369a1; }
            .badge-intent { background: #fef3c7; color: #b45309; }
            .badge-invocation { background: #dcfce7; color: #16a34a; }
            .routine-link { color: #2563eb; text-decoration: none; font-weight: bold; font-family: monospace; }
        </style>
        {{ sortable_script|safe }}
    </head>
    <body>
        <div class="container">
            <div class="header-bar">
                <div style="display: flex; gap: 15px; align-items: center;">
                    <a href="/network-overview?package={{ source_pkg }}&inv={{ inv_filter }}&intent={{ intent_filter }}" class="nav-btn">← Back to Workspace</a>
                    <h1>Inter-Package Interaction: <span style="color:#16a34a;">{{ source_pkg }}</span> ➔ <span style="color:#2563eb;">{{ target_pkg }}</span></h1>
                </div>
                <span style="font-size: 13px; color: #64748b;">Found <strong>{{ rows|length }}</strong> interaction references</span>
            </div>
            <p style="color: #475569; font-size: 13px;">Showing routines in <strong>{{ source_pkg }}</strong> interacting with <strong>{{ target_pkg }}</strong> (Filtered by Invocation: <strong>{{ inv_filter }}</strong>, Intent: <strong>{{ intent_filter }}</strong>).</p>
            <table id="interactionTable">
                <thead>
                    <tr>
                        <th class="sortable" onclick="sortTable('interactionTable', 0)" style="width: 15%;">Routine</th>
                        <th class="sortable" onclick="sortTable('interactionTable', 1, true)" style="width: 7%;">Line</th>
                        <th class="sortable" onclick="sortTable('interactionTable', 2)" style="width: 12%;">Type</th>
                        <th class="sortable" onclick="sortTable('interactionTable', 3)" style="width: 12%;">Invocation</th>
                        <th class="sortable" onclick="sortTable('interactionTable', 4)" style="width: 18%;">Target Entity</th>
                        <th class="sortable" onclick="sortTable('interactionTable', 5)" style="width: 36%;">Operation Context</th>
                    </tr>
                </thead>
                <tbody>
                    {% for r in rows %}
                    <tr>
                        <td><a href="/routine-inspect/{{ r.routine_name }}?highlight={{ r.line_number }}&mode=summary" class="routine-link">{{ r.routine_name }}</a></td>
                        <td style="font-family: monospace;">{{ r.line_number }}</td>
                        <td><span class="badge badge-intent">{{ r.op_intent or 'READ' }}</span></td>
                        <td><span class="badge badge-invocation">{{ r.invocation_type or 'MUMPS' }}</span></td>
                        <td style="font-family: monospace; color: #0284c7;">{{ r.target_entity }}</td>
                        <td style="font-family: monospace; font-size: 12px; color: #334155; word-break: break-all;">{{ r.op_context }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template, source_pkg=source_pkg, target_pkg=target_pkg, source_title=source_title, target_title=target_title, rows=rows, inv_filter=inv_filter, intent_filter=intent_filter, sortable_script=SORTABLE_TABLE_SCRIPT)

# ==========================================
# FOCAL PACKAGE TOUCHPOINTS DRILL-DOWN VIEW
# ==========================================
@app.route('/package-touchpoints')
def package_touchpoints():
    target_pkg = request.args.get('package', 'DG').upper().strip()
    inv_filter = request.args.get('inv', 'ALL').upper().strip()
    intent_filter = request.args.get('intent', 'ALL').upper().strip()
    registry = get_package_registry()
    pkg_title = registry.get(target_pkg, f"Package Namespace ({target_pkg})")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = "SELECT id, routine_name, line_number, analysis_code, file_number, op_intent, invocation_type, target_entity, op_context FROM architectural_xrf WHERE UPPER(routine_name) LIKE UPPER(?)"
    params = [f"{target_pkg}%"]

    if inv_filter != 'ALL':
        query += " AND UPPER(invocation_type) = ?"
        params.append(inv_filter)
    if intent_filter != 'ALL':
        query += " AND UPPER(op_intent) = ?"
        params.append(intent_filter)

    query += " ORDER BY routine_name ASC, line_number ASC LIMIT 500;"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    html_template = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Touchpoints Inventory - {{ target_pkg }}</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 30px; }
            .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
            .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            h1 { margin: 0; color: #0f172a; font-size: 22px; }
            .nav-btn { display: inline-block; padding: 6px 14px; background: #e2e8f0; color: #334155; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 13px; }
            .nav-btn:hover { background: #cbd5e1; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; table-layout: fixed; }
            th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; word-wrap: break-word; overflow: hidden; text-overflow: ellipsis; }
            th { background: #f8fafc; font-weight: 600; color: #475569; }
            .badge { padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; font-family: monospace; background: #e0f2fe; color: #0369a1; }
            .badge-intent { background: #fef3c7; color: #b45309; }
            .badge-invocation { background: #dcfce7; color: #16a34a; }
            .routine-link { color: #2563eb; text-decoration: none; font-weight: bold; font-family: monospace; }
        </style>
        {{ sortable_script|safe }}
    </head>
    <body>
        <div class="container">
            <div class="header-bar">
                <div style="display: flex; gap: 15px; align-items: center;">
                    <a href="/network-overview?package={{ target_pkg }}&inv={{ inv_filter }}&intent={{ intent_filter }}" class="nav-btn">← Back to Workspace</a>
                    <h1>Touchpoints Inventory: {{ pkg_title }} ({{ target_pkg }})</h1>
                </div>
                <span style="font-size: 13px; color: #64748b;">Showing <strong>{{ rows|length }}</strong> recorded touchpoints</span>
            </div>
            <p style="color: #64748b; font-size: 13px;">Filtered by Invocation: <strong>{{ inv_filter }}</strong>, Intent: <strong>{{ intent_filter }}</strong>.</p>
            <table id="touchpointsTable">
                <thead>
                    <tr>
                        <th class="sortable" onclick="sortTable('touchpointsTable', 0)" style="width: 15%;">Routine</th>
                        <th class="sortable" onclick="sortTable('touchpointsTable', 1, true)" style="width: 7%;">Line</th>
                        <th class="sortable" onclick="sortTable('touchpointsTable', 2)" style="width: 12%;">Type</th>
                        <th class="sortable" onclick="sortTable('touchpointsTable', 3)" style="width: 12%;">Invocation</th>
                        <th class="sortable" onclick="sortTable('touchpointsTable', 4)" style="width: 18%;">Target Entity</th>
                        <th class="sortable" onclick="sortTable('touchpointsTable', 5)" style="width: 36%;">Operation Context</th>
                    </tr>
                </thead>
                <tbody>
                    {% for r in rows %}
                    <tr>
                        <td><a href="/routine-inspect/{{ r.routine_name }}?highlight={{ r.line_number }}&mode=summary" class="routine-link">{{ r.routine_name }}</a></td>
                        <td style="font-family: monospace;">{{ r.line_number }}</td>
                        <td><span class="badge badge-intent">{{ r.op_intent or 'READ' }}</span></td>
                        <td><span class="badge badge-invocation">{{ r.invocation_type or 'MUMPS' }}</span></td>
                        <td style="font-family: monospace; color: #0284c7;">{{ r.target_entity }}</td>
                        <td style="font-family: monospace; font-size: 12px; color: #334155; word-break: break-all;">{{ r.op_context }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template, target_pkg=target_pkg, pkg_title=pkg_title, rows=rows, inv_filter=inv_filter, intent_filter=intent_filter, sortable_script=SORTABLE_TABLE_SCRIPT)

# ==========================================
# XRF MATRIX ROUTE
# ==========================================
@app.route('/xrf-view')
def xrf_view():
    filter_pkg = request.args.get('filter', 'DG').strip()
    if filter_pkg.upper() == 'ALL':
        filter_pkg = ''
    available_pkgs = get_available_packages()
    registry = get_package_registry()
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    if filter_pkg:
        cursor.execute("SELECT id, routine_name, line_number, analysis_code, file_number, op_intent, invocation_type, target_entity, op_context FROM architectural_xrf WHERE UPPER(routine_name) LIKE UPPER(?) ORDER BY routine_name ASC, line_number ASC LIMIT 1000;", (f"{filter_pkg}%",))
    else:
        cursor.execute("SELECT id, routine_name, line_number, analysis_code, file_number, op_intent, invocation_type, target_entity, op_context FROM architectural_xrf ORDER BY routine_name ASC, line_number ASC LIMIT 1000;")
    rows = cursor.fetchall()
    conn.close()

    html_template = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Architectural Cross-Reference Matrix</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 30px; }
            .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
            .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 15px; }
            h1 { margin: 0; color: #0f172a; font-size: 22px; }
            .nav-group { display: flex; gap: 10px; align-items: center; }
            .nav-btn { padding: 6px 14px; background: #e2e8f0; color: #334155; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 13px; }
            .filter-form { display: flex; gap: 10px; align-items: center; margin-bottom: 20px; background: #f8fafc; padding: 12px; border-radius: 8px; border: 1px solid #e2e8f0; }
            select { padding: 6px 12px; border-radius: 6px; border: 1px solid #cbd5e1; font-size: 13px; background: #fff; }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; table-layout: fixed; }
            th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; word-wrap: break-word; overflow: hidden; text-overflow: ellipsis; }
            th { background: #f8fafc; font-weight: 600; color: #475569; }
            .badge { padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; font-family: monospace; background: #e0f2fe; color: #0369a1; }
            .badge-intent { background: #fef3c7; color: #b45309; }
            .badge-invocation { background: #dcfce7; color: #16a34a; }
            .routine-link { color: #2563eb; text-decoration: none; font-weight: bold; font-family: monospace; }
        </style>
        {{ sortable_script|safe }}
    </head>
    <body>
        <div class="container">
            <div class="header-bar">
                <h1>Architectural Cross-Reference Matrix</h1>
                <div class="nav-group">
                    <a href="/" class="nav-btn">← Home</a>
                </div>
            </div>
            
            <form method="GET" action="/xrf-view" class="filter-form">
                <label for="filter" style="font-weight: 600; font-size: 13px;">Filter Package Namespace:</label>
                <select name="filter" id="filter" onchange="this.form.submit()">
                    <option value="ALL" {% if not filter_pkg %}selected{% endif %}>-- ALL PACKAGES --</option>
                    {% for p in available_pkgs %}
                    <option value="{{ p }}" {% if filter_pkg|upper == p|upper %}selected{% endif %}>{{ p }} - {{ registry.get(p, 'Package') }}</option>
                    {% endfor %}
                </select>
            </form>

            <table id="xrfTable">
                <thead>
                    <tr>
                        <th class="sortable" onclick="sortTable('xrfTable', 0)" style="width: 15%;">Routine</th>
                        <th class="sortable" onclick="sortTable('xrfTable', 1, true)" style="width: 7%;">Line</th>
                        <th class="sortable" onclick="sortTable('xrfTable', 2)" style="width: 11%;">Type</th>
                        <th class="sortable" onclick="sortTable('xrfTable', 3)" style="width: 11%;">Invocation</th>
                        <th class="sortable" onclick="sortTable('xrfTable', 4)" style="width: 56%;">Operation Context</th>
                    </tr>
                </thead>
                <tbody>
                    {% for r in rows %}
                    <tr>
                        <td><a href="/routine-inspect/{{ r.routine_name }}?highlight={{ r.line_number }}&mode=summary" class="routine-link">{{ r.routine_name }}</a></td>
                        <td style="font-family: monospace;">{{ r.line_number }}</td>
                        <td><span class="badge badge-intent">{{ r.op_intent or r.analysis_code }}</span></td>
                        <td><span class="badge badge-invocation">{{ r.invocation_type or 'MUMPS' }}</span></td>
                        <td style="font-family: monospace; font-size: 12px; color: #334155; word-break: break-all;">{{ r.op_context }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template, rows=rows, filter_pkg=filter_pkg, available_pkgs=available_pkgs, registry=registry, sortable_script=SORTABLE_TABLE_SCRIPT)

# ==========================================
# CONSISTENCY CHECKING REPORT
# ==========================================
@app.route('/consistency-report')
def consistency_report():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM architectural_xrf;")
    total_findings_count = cursor.fetchone()[0]

    cursor.execute("SELECT analysis_code, COUNT(*) as flag_count FROM architectural_xrf GROUP BY analysis_code;")
    summary = cursor.fetchall()
    cursor.execute("SELECT id, routine_name, line_number, analysis_code, file_number, target_entity, op_context FROM architectural_xrf LIMIT 500;")
    findings = cursor.fetchall()
    conn.close()

    html_template = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Consistency Checking & Findings Audit Report</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 30px; }
            .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
            .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            h1 { margin: 0; color: #0f172a; font-size: 24px; }
            .nav-group { display: flex; gap: 10px; align-items: center; }
            .nav-btn { display: inline-block; padding: 6px 14px; background: #e2e8f0; color: #334155; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 13px; }
            .nav-btn:hover { background: #cbd5e1; }
            .btn-print { padding: 6px 14px; background: #2563eb; color: white; border: none; border-radius: 6px; font-weight: 600; font-size: 13px; cursor: pointer; }
            .btn-print:hover { background: #1d4ed8; }
            .telemetry-banner { background: #f0fdf4; border: 1px solid #bbf7d0; padding: 12px 18px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
            .telemetry-banner h3 { margin: 0; font-size: 14px; color: #166534; text-transform: uppercase; }
            .telemetry-banner span { font-size: 20px; font-weight: bold; color: #14532d; font-family: monospace; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; table-layout: fixed; }
            th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #e2e8f0; word-wrap: break-word; overflow: hidden; text-overflow: ellipsis; }
            th { background: #f8fafc; font-weight: 600; color: #475569; }
            .badge { padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; font-family: monospace; background: #fef3c7; color: #b45309; }
            .routine-link { color: #2563eb; text-decoration: none; font-weight: bold; font-family: monospace; }
            
            @media print {
                body { background: white; padding: 0; }
                .container { box-shadow: none; padding: 0; max-width: 100%; }
                .header-bar, .nav-btn, .btn-print { display: none !important; }
            }
        </style>
        {{ sortable_script|safe }}
    </head>
    <body>
        <div class="container">
            <div class="header-bar">
                <a href="/" class="nav-btn">← Home</a>
                <div class="nav-group">
                    <button type="button" class="btn-print" onclick="window.print()">🖨️ Print Full Report</button>
                    <span style="font-size: 13px; color: #64748b; font-weight: 500;">Consistency Audit Suite</span>
                </div>
            </div>
            <h1>Consistency Checking & Findings Audit Report</h1>

            <div class="telemetry-banner">
                <div>
                    <h3>📊 Total Indexed Audit Findings</h3>
                    <p style="margin: 2px 0 0 0; font-size: 12px; color: #475569;">Track this record count down as parser noise and numeric false positives are scrubbed.</p>
                </div>
                <span>{{ "{:,}".format(total_findings_count) }}</span>
            </div>

            <table id="consistencyTable">
                <thead>
                    <tr>
                        <th style="width: 8%; text-align: center;">Item #</th>
                        <th class="sortable" onclick="sortTable('consistencyTable', 1)" style="width: 15%;">Routine</th>
                        <th class="sortable" onclick="sortTable('consistencyTable', 2, true)" style="width: 8%;">Line</th>
                        <th class="sortable" onclick="sortTable('consistencyTable', 3)" style="width: 15%;">Code Type</th>
                        <th class="sortable" onclick="sortTable('consistencyTable', 4)" style="width: 10%;">File Number</th>
                        <th class="sortable" onclick="sortTable('consistencyTable', 5)" style="width: 15%;">Target Entity</th>
                        <th class="sortable" onclick="sortTable('consistencyTable', 6)" style="width: 29%;">Operation Context</th>
                    </tr>
                </thead>
                <tbody>
                    {% for f in findings %}
                    <tr>
                        <td style="text-align: center; font-family: monospace; color: #64748b; font-weight: bold;">{{ loop.index }}</td>
                        <td><a href="/routine-inspect/{{ f.routine_name }}?highlight={{ f.line_number }}&mode=summary" class="routine-link">{{ f.routine_name }}</a></td>
                        <td style="font-family: monospace;">{{ f.line_number }}</td>
                        <td><span class="badge">{{ f.analysis_code }}</span></td>
                        <td style="font-family: monospace; font-weight: bold; color: #16a34a;">{{ f.file_number or 'N/A' }}</td>
                        <td style="font-family: monospace; color: #0284c7;">{{ f.target_entity }}</td>
                        <td style="font-family: monospace; font-size: 12px; color: #334155; word-break: break-all;">{{ f.op_context }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template, summary=summary, findings=findings, total_findings_count=total_findings_count, sortable_script=SORTABLE_TABLE_SCRIPT)

# ==========================================
# BUILD & AD-HOC EXPLORER CONTROL CENTER ROUTE
# ==========================================
@app.route('/build-control-hub', methods=['GET'])
def build_control_hub():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM architectural_xrf;")
    total_records = cursor.fetchone()[0]
    
    cursor.execute("SELECT analysis_code, COUNT(*) as cnt FROM architectural_xrf GROUP BY analysis_code;")
    intent_summary = cursor.fetchall()
    
    cursor.execute("SELECT invocation_type, COUNT(*) as cnt FROM architectural_xrf GROUP BY invocation_type;")
    inv_summary = cursor.fetchall()
    
    conn.close()

    html_template = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Build & Ad-Hoc Explorer Control Center</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 30px; }
            .container { max-width: 1350px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
            .header-bar { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; padding-bottom: 15px; margin-bottom: 25px; flex-wrap: wrap; gap: 15px; }
            h1 { margin: 0; color: #0f172a; font-size: 22px; }
            .nav-group { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
            .nav-btn { padding: 6px 14px; background: #e2e8f0; color: #334155; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 13px; }
            .nav-btn:hover { background: #cbd5e1; }
            .btn-history { background: #7c3aed; color: white; }
            .btn-history:hover { background: #6d28d9; }
            .btn-rebuild { background: #16a34a; color: white; }
            .btn-rebuild:hover { background: #15803d; }
            
            .telemetry-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 15px; margin-bottom: 25px; }
            .metric-card { background: #f8fafc; border: 1px solid #cbd5e1; padding: 15px; border-radius: 8px; }
            .metric-card h3 { margin: 0 0 5px 0; font-size: 12px; color: #475569; text-transform: uppercase; }
            .metric-card p { margin: 0; font-size: 22px; font-weight: bold; color: #0f172a; font-family: monospace; }

            .control-panel { background: #f8fafc; border: 1px solid #cbd5e1; padding: 25px; border-radius: 8px; margin-bottom: 25px; }
            .control-panel h3 { margin-top: 0; color: #0f172a; font-size: 16px; margin-bottom: 15px; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; }
            .checkbox-group { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 20px; font-weight: 600; font-size: 13px; color: #334155; }
            .checkbox-group label { display: flex; align-items: center; gap: 6px; cursor: pointer; }
            
            .adhoc-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
            .adhoc-box { background: #fff; border: 1px solid #cbd5e1; padding: 15px; border-radius: 6px; display: flex; flex-direction: column; gap: 8px; }
            .adhoc-box label { font-size: 12px; font-weight: 600; color: #475569; }
            .adhoc-box input { padding: 7px 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 13px; }

            .action-bar { display: flex; justify-content: space-between; align-items: center; margin-top: 15px; flex-wrap: wrap; gap: 15px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header-bar">
                <h1>Build & Ad-Hoc Explorer Control Center</h1>
                <div class="nav-group">
                    <a href="/build-history" class="nav-btn btn-history">📜 View Build History Log</a>
                    <a href="/" class="nav-btn">← Return to Dashboard</a>
                </div>
            </div>

            <!-- Telemetry Stats Panel -->
            <div class="telemetry-grid">
                <div class="metric-card">
                    <h3>Total Indexed Records (XRF)</h3>
                    <p>{{ "{:,}".format(total_records) }}</p>
                </div>
                <div class="metric-card">
                    <h3>Intent Breakdown</h3>
                    <p style="font-size: 13px; font-weight: normal; margin-top: 5px;">
                        {% for i in intent_summary %}
                            <strong>{{ i.analysis_code }}</strong>: {{ "{:,}".format(i.cnt) }} &nbsp;|&nbsp;
                        {% endfor %}
                    </p>
                </div>
                <div class="metric-card">
                    <h3>Invocation Breakdown</h3>
                    <p style="font-size: 13px; font-weight: normal; margin-top: 5px;">
                        {% for inv in inv_summary %}
                            <strong>{{ inv.invocation_type }}</strong>: {{ "{:,}".format(inv.cnt) }} &nbsp;|&nbsp;
                        {% endfor %}
                    </p>
                </div>
            </div>

            <!-- Unified Control & Build Form -->
            <div class="control-panel">
                <h3>⚙ Master Index Builder & Ad-Hoc Filter Configuration</h3>
                <p style="font-size: 13px; color: #475569; margin-top: 0;">Standard baseline filters are checked by default. Dynamic invocation types are automatically cataloged and made selectable.</p>
                
                <form action="/build-database" method="POST" onsubmit="return confirm('Run parametric streaming master index build?');">
                    <div class="checkbox-group">
                        <label><input type="checkbox" name="inc_reads" checked> Include Reads</label>
                        <label><input type="checkbox" name="inc_writes" checked> Include Writes</label>
                        <label><input type="checkbox" name="inc_queries" checked> Include Queries</label>
                        <label><input type="checkbox" name="inc_pkg_calls" checked> Include Inter-Package Calls</label>
                        <label><input type="checkbox" name="inc_installs"> Include Install / Patch Routines (Optional)</label>
                    </div>

                    <div class="adhoc-grid">
                        <div class="adhoc-box">
                            <label>Custom Ad-Hoc Filter Type 1 (Name):</label>
                            <input type="text" name="custom_label_1" placeholder="e.g. MUMPS Lock">
                            <label style="margin-top: 5px;">Search Keywords (comma-separated):</label>
                            <input type="text" name="custom_query_1" placeholder="e.g. LOCK, L+">
                        </div>
                        <div class="adhoc-box">
                            <label>Custom Ad-Hoc Filter Type 2 (Name):</label>
                            <input type="text" name="custom_label_2" placeholder="e.g. FileMan Lock">
                            <label style="margin-top: 5px;">Search Keywords (comma-separated):</label>
                            <input type="text" name="custom_query_2" placeholder="e.g. LOCK^DIC, FILE^">
                        </div>
                    </div>

                    <div class="action-bar">
                        <span style="font-size: 12px; color: #64748b;">🔄 Triggers live streaming build into active <code>dynamic_dataset.db</code></span>
                        <button type="submit" class="nav-btn btn-rebuild" style="border:none; cursor:pointer; padding: 10px 20px; font-weight: 600; font-size: 14px;">⚡ Run Parametric Live Streaming Build</button>
                    </div>
                </form>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template, total_records=total_records, intent_summary=intent_summary, inv_summary=inv_summary)

# ==========================================
# BUILD HISTORY AUDIT TRAIL ROUTE
# ==========================================
@app.route('/build-history')
def build_history():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, version_tag, build_timestamp, total_records, intent_summary, invocation_summary, ad_hoc_col_1, ad_hoc_col_2 FROM build_history ORDER BY id DESC;")
    history_rows = cursor.fetchall()
    conn.close()

    html_template = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Build Version History Audit Trail</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 30px; }
            .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
            .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            h1 { margin: 0; color: #0f172a; font-size: 24px; }
            .nav-btn { display: inline-block; padding: 6px 14px; background: #e2e8f0; color: #334155; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 13px; }
            .nav-btn:hover { background: #cbd5e1; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; table-layout: fixed; }
            th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; word-wrap: break-word; overflow: hidden; text-overflow: ellipsis; }
            th { background: #f8fafc; font-weight: 600; color: #475569; }
            .badge-version { background: #e0e7ff; color: #3730a3; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-family: monospace; }
        </style>
        {{ sortable_script|safe }}
    </head>
    <body>
        <div class="container">
            <div class="header-bar">
                <h1>Build Version History Audit Trail</h1>
                <a href="/build-control-hub" class="nav-btn">← Back to Control Center</a>
            </div>
            <p style="color: #475569; font-size: 13px;">Chronological audit log tracking index builds. The latest version is displayed at the top.</p>
            
            <table id="historyTable">
                <thead>
                    <tr>
                        <th class="sortable" onclick="sortTable('historyTable', 0)" style="width: 10%;">Version</th>
                        <th class="sortable" onclick="sortTable('historyTable', 1)" style="width: 18%;">Timestamp</th>
                        <th class="sortable" onclick="sortTable('historyTable', 2, true)" style="width: 12%;">Total Indexed</th>
                        <th class="sortable" onclick="sortTable('historyTable', 3)" style="width: 25%;">Intent Breakdown</th>
                        <th class="sortable" onclick="sortTable('historyTable', 4)" style="width: 15%;">Custom Ad-Hoc Filters</th>
                        <th class="sortable" onclick="sortTable('historyTable', 5)" style="width: 20%;">Invocations (MUMPS / FileMan)</th>
                    </tr>
                </thead>
                <tbody>
                    {% for h in history_rows %}
                    <tr>
                        <td><span class="badge-version">{{ h.version_tag }}</span></td>
                        <td style="font-family: monospace; font-weight: 600; color: #0f172a;">{{ h.build_timestamp }}</td>
                        <td style="font-family: monospace; font-weight: bold; color: #16a34a;">{{ "{:,}".format(h.total_records) }}</td>
                        <td style="font-family: monospace; font-size: 12px; color: #b45309;">{{ h.intent_summary }}</td>
                        <td style="font-family: monospace; font-size: 12px; color: #2563eb;">{{ h.ad_hoc_col_1 }}<br><span style="color: #7c3aed;">{{ h.ad_hoc_col_2 }}</span></td>
                        <td style="font-family: monospace; font-size: 12px; color: #334155;">{{ h.invocation_summary }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template, history_rows=history_rows, sortable_script=SORTABLE_TABLE_SCRIPT)

# ==========================================
# ROUTINE INSPECTOR
# ==========================================
@app.route('/routine-inspect/<routine_name>')
def routine_inspect(routine_name):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT line_number, analysis_code, file_number, target_entity, op_context 
        FROM architectural_xrf 
        WHERE UPPER(routine_name) = UPPER(?);
    """, (routine_name,))
    xrf_rows = cursor.fetchall()
    conn.close()

    source_rows = [{'line_number': x['line_number'], 'line_content': x['op_context']} for x in xrf_rows]

    html_template = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Routine Inspector - {{ routine_name }}</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 30px; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
            .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            h1 { margin: 0; color: #0f172a; font-size: 22px; font-family: monospace; }
            .nav-btn { display: inline-block; padding: 6px 14px; background: #e2e8f0; color: #334155; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 13px; }
            .nav-btn:hover { background: #cbd5e1; }
            .source-viewer { background: #1e293b; color: #f8fafc; padding: 20px; border-radius: 8px; font-family: monospace; font-size: 13px; line-height: 1.5; overflow-x: auto; max-height: 700px; overflow-y: auto; }
            .source-line { display: flex; padding: 3px 6px; border-radius: 3px; align-items: flex-start; }
            .line-num { width: 50px; color: #64748b; text-align: right; padding-right: 15px; user-select: none; flex-shrink: 0; }
            .line-content { flex: 1; white-space: pre-wrap; word-break: break-all; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header-bar">
                <a href="javascript:history.back()" class="nav-btn">← Back</a>
                <span style="font-size: 13px; color: #64748b; font-weight: 500;">Routine Inspector Workbench</span>
            </div>
            <h1>Routine: {{ routine_name }}</h1>
            <div class="source-viewer">
                {% for row in source_rows %}
                    <div class="source-line">
                        <div class="line-num">{{ row.line_number }}</div>
                        <div class="line-content">{{ row.line_content }}</div>
                    </div>
                {% endfor %}
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template, routine_name=routine_name, source_rows=source_rows)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)