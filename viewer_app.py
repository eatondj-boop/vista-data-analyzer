import sqlite3
import os
from flask import Flask, g, render_template_string, request, session, abort
from impact_analyzer import ImpactAnalyzer

app = Flask(__name__)
app.secret_key = 'data_analyzer_secret_key'

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'dynamic_dataset.db')

@app.route('/')
def index():
    return """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>VistA Routine & Data Analyzer</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 40px; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
            h1 { margin-top: 0; color: #0f172a; }
            p { color: #475569; line-height: 1.6; }
            .btn { display: inline-block; margin-top: 20px; padding: 12px 24px; background: #2563eb; color: white; text-decoration: none; border-radius: 6px; font-weight: 600; }
            .btn:hover { background: #1d4ed8; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>VistA Enterprise Analyzer</h1>
            <p>Welcome to your local Data Analyzer and Routine inspection suite. Select fields to target changes and analyze enterprise routine impacts.</p>
            <a href="/impact" class="btn">Open Data Dictionary & Impact Inspector →</a>
        </div>
    </body>
    </html>
    """

@app.route('/impact', methods=['GET', 'POST'])
def impact_analysis():
    analyzer = ImpactAnalyzer(DB_PATH)
    
    file_num = request.args.get('file', '').strip()
    file_name = ""
    global_root = ""
    fields = []

    if request.method == 'POST':
        file_num = request.form.get('file_num', '').strip()
        action = request.form.get('action', 'inspect').strip()
        
        if action == 'run_analysis':
            selected_fields = request.form.getlist('selected_fields')
            fields_param = ",".join(selected_fields)
            return f"""
            <script>
                window.location.href = '/impact/report?file={file_num}&fields={fields_param}';
            </script>
            """
        elif file_num:
            return f"""
            <script>
                window.location.href = '/impact?file={file_num}';
            </script>
            """

    if file_num:
        file_name, global_root, fields = analyzer.get_file_fields(file_num)

    html_template = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Data Dictionary & Field Change Inspector</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 30px; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
        h1 { margin-top: 0; font-size: 24px; color: #0f172a; margin-bottom: 20px; }
        .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .nav-btn { display: inline-block; padding: 6px 14px; background: #e2e8f0; color: #334155; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 13px; }
        .nav-btn:hover { background: #cbd5e1; }
        .form-bar { display: flex; gap: 10px; margin-bottom: 25px; background: #f8fafc; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; align-items: center; }
        .form-bar input[type="text"] { padding: 10px 14px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; background: white; flex: 1; }
        .btn-action { padding: 10px 20px; background: #2563eb; color: white; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; }
        .btn-action:hover { background: #1d4ed8; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 14px; table-layout: fixed; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #e2e8f0; word-wrap: break-word; overflow: hidden; text-overflow: ellipsis; }
        th { background: #f8fafc; font-weight: 600; color: #475569; }
        tr:hover { background: #f8fafc; }
        .checkbox-cell { width: 60px; text-align: center; }
        .file-banner { background: #f8fafc; border: 1px solid #cbd5e1; padding: 15px 20px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
        
        #loadingOverlay { display: none; position: fixed; z-index: 9999; top: 0; left: 0; width: 100%; height: 100%; background: rgba(255, 255, 255, 0.85); backdrop-filter: blur(2px); justify-content: center; align-items: center; flex-direction: column; }
        .spinner { width: 50px; height: 50px; border: 5px solid #e2e8f0; border-top: 5px solid #2563eb; border-radius: 50%; animation: spin 0.8s linear infinite; margin-bottom: 15px; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .loading-text { font-weight: 600; color: #0f172a; font-size: 16px; }
    </style>
    <script>
        function toggleAll(source) {
            checkboxes = document.getElementsByName('selected_fields');
            for(var i=0, n=checkboxes.length; i<n; i++) {
                checkboxes[i].checked = source.checked;
            }
        }
        function showLoading() {
            document.getElementById('loadingOverlay').style.display = 'flex';
        }
    </script>
</head>
<body>
    <div id="loadingOverlay">
        <div class="spinner"></div>
        <div class="loading-text">⏳ Processing Request... Please Wait</div>
    </div>

    <div class="container">
        <div class="top-bar">
            <div style="display: flex; gap: 8px; align-items: center;">
                <a href="/" class="nav-btn">← Home</a>
            </div>
            <span style="font-size: 13px; color: #64748b; font-weight: 500;">DataAnalyzer v1.0</span>
        </div>

        <h1>Data Dictionary & Field Change Inspector</h1>

        <form method="POST" class="form-bar" onsubmit="showLoading()">
            <input type="text" name="file_num" value="{{ file_num }}" placeholder="Enter File Number (e.g., 2 or 58.5)" required>
            <input type="hidden" name="action" value="inspect">
            <button type="submit" class="btn-action">Load File Fields</button>
        </form>

        {% if fields %}
            <form method="POST">
                <input type="hidden" name="file_num" value="{{ file_num }}">
                <input type="hidden" name="action" value="run_analysis">
                
                <div class="file-banner">
                    <div>
                        <h3 style="margin: 0 0 4px 0; color: #0f172a; font-size: 17px;">File #{{ file_num }} - {{ file_name }}</h3>
                        <span style="font-family: monospace; font-size: 13px; color: #2563eb; font-weight: bold;">MUMPS Global Root: {{ global_root }}</span>
                    </div>
                    <div>
                        <button type="submit" class="btn-action" onclick="showLoading()">Impact Analysis</button>
                    </div>
                </div>

                <table>
                    <thead>
                        <tr>
                            <th class="checkbox-cell">
                                <input type="checkbox" id="selectAll" onclick="toggleAll(this)" title="Check/Uncheck All">
                            </th>
                            <th style="width: 15%;">Field Number</th>
                            <th style="width: 30%;">Field Name</th>
                            <th style="width: 25%;">Global Location</th>
                            <th style="width: 30%;">Definition / Node Mapping</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for f in fields %}
                        <tr>
                            <td class="checkbox-cell"><input type="checkbox" name="selected_fields" value="{{ f.field_number }}"></td>
                            <td style="font-family: monospace; font-weight: bold; color: #16a34a;">{{ f.field_number }}</td>
                            <td style="font-weight: 600; color: #0f172a;">{{ f.field_name }}</td>
                            <td style="font-family: monospace; font-size: 12px; color: #0284c7; font-weight: bold;">{{ f.global_location }}</td>
                            <td style="font-family: monospace; font-size: 12px; color: #334155;">{{ f.definition }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </form>
        {% elif file_num %}
            <p style="color: #64748b;">No fields found for file number {{ file_num }}.</p>
        {% endif %}
    </div>
</body>
</html>
    """
    return render_template_string(html_template, file_num=file_num, file_name=file_name, global_root=global_root, fields=fields)

# ==========================================
# PAGE 1: Enterprise Overview & Namespace List
# ==========================================
@app.route('/impact/report')
def impact_report():
    file_num = request.args.get('file', '').strip()
    fields_param = request.args.get('fields', '').strip()
    
    if not file_num:
        return "Missing file parameter", 400

    selected_fields = fields_param.split(',') if fields_param else []
    analyzer = ImpactAnalyzer(DB_PATH)
    master_report = analyzer.analyze_selected_fields(file_num, selected_fields)

    cleaned_groups = []
    total_routines = 0
    for ns in master_report.get('namespaces_grouped', []):
        valid_routines = []
        for rot in ns.get('routines', []):
            valid_lines = [l for l in rot.get('matched_lines', []) if '^DD(' not in l.get('code', '')]
            if valid_lines:
                rot_copy = rot.copy()
                rot_copy['matched_lines'] = valid_lines
                rot_copy['total_matches'] = len(valid_lines)
                valid_routines.append(rot_copy)
        if valid_routines:
            ns_copy = ns.copy()
            ns_copy['routines'] = valid_routines
            ns_copy['routine_count'] = len(valid_routines)
            cleaned_groups.append(ns_copy)
            total_routines += len(valid_routines)

    master_report['namespaces_grouped'] = cleaned_groups
    master_report['total_routines_affected'] = total_routines
    master_report['total_namespaces_affected'] = len(cleaned_groups)

    html_template = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Impact Analysis Report: File #{{ report.file_number }} - {{ report.file_description }}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 30px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
        h1 { margin-top: 0; font-size: 24px; color: #0f172a; margin-bottom: 5px; }
        .sub { color: #64748b; margin-bottom: 25px; font-size: 14px; }
        .nav-btn { display: inline-block; margin-bottom: 20px; padding: 6px 14px; background: #e2e8f0; color: #334155; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 13px; }
        .nav-btn:hover { background: #cbd5e1; }
        
        .ns-card { display: flex; justify-content: space-between; align-items: center; border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 12px; background: white; padding: 16px 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); transition: all 0.2s; }
        .ns-card:hover { border-color: #2563eb; background: #f8fafc; }
        .ns-title { font-size: 18px; font-weight: bold; color: #0f172a; text-decoration: none; }
        .ns-title:hover { color: #2563eb; }
        .inspect-btn { background: #2563eb; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; text-decoration: none; font-size: 13px; }
        .inspect-btn:hover { background: #1d4ed8; }

        #loadingOverlay { display: none; position: fixed; z-index: 9999; top: 0; left: 0; width: 100%; height: 100%; background: rgba(255, 255, 255, 0.85); backdrop-filter: blur(2px); justify-content: center; align-items: center; flex-direction: column; }
        .spinner { width: 50px; height: 50px; border: 5px solid #e2e8f0; border-top: 5px solid #2563eb; border-radius: 50%; animation: spin 0.8s linear infinite; margin-bottom: 15px; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .loading-text { font-weight: 600; color: #0f172a; font-size: 16px; }
    </style>
    <script>
        function showLoading() {
            document.getElementById('loadingOverlay').style.display = 'flex';
        }
    </script>
</head>
<body>
    <div id="loadingOverlay">
        <div class="spinner"></div>
        <div class="loading-text">⏳ Loading Namespace Report... Please Wait</div>
    </div>

    <div class="container">
        <a href="/impact?file={{ report.file_number }}" class="nav-btn" onclick="showLoading()">← Back to Field Selection</a>

        <h1>Impact Analysis Report: File #{{ report.file_number }} - {{ report.file_description }}</h1>
        <div style="font-family: monospace; font-size: 14px; color: #2563eb; font-weight: bold; margin-bottom: 15px;">MUMPS Global Root: {{ report.global_root }}</div>
        <div class="sub">Enterprise routine impact summary. Select a namespace below to drill down into routines and AI findings.</div>

        <div style="display: flex; gap: 20px; margin-bottom: 25px;">
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; padding: 15px 20px; border-radius: 6px; flex: 1;">
                <h3 style="margin: 0 0 5px 0; font-size: 13px; color: #64748b; text-transform: uppercase;">Affected Routines</h3>
                <p style="margin: 0; font-size: 20px; font-weight: bold; color: #0f172a;">{{ report.total_routines_affected }} routines</p>
            </div>
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; padding: 15px 20px; border-radius: 6px; flex: 1;">
                <h3 style="margin: 0 0 5px 0; font-size: 13px; color: #64748b; text-transform: uppercase;">Affected Namespaces</h3>
                <p style="margin: 0; font-size: 20px; font-weight: bold; color: #0f172a;">{{ report.total_namespaces_affected }} namespaces</p>
            </div>
        </div>

        <h3 style="font-size: 18px; color: #0f172a; margin-bottom: 15px;">Impact by Namespace (Expandable Drill-Down)</h3>
        
        {% for ns_group in report.namespaces_grouped %}
        <div class="ns-card">
            <div>
                <a href="/impact/package-report?file={{ report.file_number }}&fields={{ report.selected_fields | join(',') }}&ns={{ ns_group.namespace }}" class="ns-title" onclick="showLoading()">
                    {{ ns_group.namespace }}
                </a>
                <span style="background: #e2e8f0; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; color: #334155; margin-left: 10px;">{{ ns_group.routine_count }} routines affected</span>
            </div>
            <a href="/impact/package-report?file={{ report.file_number }}&fields={{ report.selected_fields | join(',') }}&ns={{ ns_group.namespace }}" class="inspect-btn" onclick="showLoading()">
                Drill Down →
            </a>
        </div>
        {% endfor %}
    </div>
</body>
</html>
    """
    return render_template_string(html_template, report=master_report)

# ==========================================
# PAGE 2: Namespace Drill-Down & Routine Highlight View
# ==========================================
@app.route('/impact/package-report')
def package_report():
    file_num = request.args.get('file', '').strip()
    fields_param = request.args.get('fields', '').strip()
    target_ns = request.args.get('ns', '').strip()
    op_filter = request.args.get('op_filter', '').strip()
    access_filter = request.args.get('access_filter', '').strip()
    
    if not file_num or not target_ns:
        return "Missing file or namespace parameter", 400

    selected_fields = fields_param.split(',') if fields_param else []
    analyzer = ImpactAnalyzer(DB_PATH)
    master_report = analyzer.analyze_selected_fields(file_num, selected_fields)

    target_group = None
    g_root = master_report.get('global_root', '').strip('()')

    for ns in master_report.get('namespaces_grouped', []):
        if ns.get('namespace') == target_ns:
            filtered_routines = []
            for rot in ns.get('routines', []):
                filtered_lines = []
                for line in rot.get('matched_lines', []):
                    code_str = line.get('code', '')
                    
                    if '^DD(' in code_str:
                        line['type'] = 'DD_INSTALL'
                    
                    is_direct = g_root and (g_root in code_str or g_root.upper() in code_str.upper())
                    is_fileman = any(token in code_str.upper() for token in ['DIE', 'DIC', 'DIK', 'D ^DIE', 'D ^DIC', 'D ^DIK'])
                    is_dd_install = ('^DD(' in code_str)
                    
                    if access_filter == 'direct' and not is_direct:
                        continue
                    elif access_filter == 'fileman' and not (is_fileman or is_dd_install or not is_direct):
                        continue
                        
                    if op_filter and line.get('type') != op_filter:
                        continue

                    filtered_lines.append(line)
                
                if filtered_lines:
                    rot_copy = rot.copy()
                    rot_copy['matched_lines'] = filtered_lines
                    rot_copy['total_matches'] = len(filtered_lines)
                    filtered_routines.append(rot_copy)
            
            if filtered_routines:
                target_group = ns.copy()
                target_group['routines'] = filtered_routines
                target_group['routine_count'] = len(filtered_routines)
            break

    report = master_report.copy()
    report['namespaces_grouped'] = [target_group] if target_group else []
    report['total_routines_affected'] = target_group['routine_count'] if target_group else 0
    report['total_namespaces_affected'] = 1

    html_template = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Impact Analysis Report: File #{{ report.file_number }} - {{ report.file_description }}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 30px; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
        h1 { margin-top: 0; font-size: 24px; color: #0f172a; margin-bottom: 5px; }
        .sub { color: #64748b; margin-bottom: 25px; font-size: 14px; }
        .nav-btn { display: inline-block; margin-bottom: 20px; padding: 6px 14px; background: #e2e8f0; color: #334155; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 13px; }
        .nav-btn:hover { background: #cbd5e1; }
        
        .pill { display: inline-block; background: #f1f5f9; border: 1px solid #cbd5e1; padding: 6px 12px; border-radius: 6px; font-family: monospace; font-size: 13px; margin-right: 6px; margin-bottom: 6px; color: #0f172a; font-weight: bold; text-decoration: none; transition: all 0.2s; }
        .pill:hover { background: #e2e8f0; border-color: #94a3b8; }
        .pill.active { background: #2563eb; color: white; border-color: #1d4ed8; }
        
        .pill-write { border-color: #fca5a5; }
        .pill-write.active { background: #dc2626; border-color: #b91c1c; color: white; }
        .pill-query { border-color: #bae6fd; }
        .pill-query.active { background: #0284c7; border-color: #0369a1; color: white; }
        .pill-read { border-color: #cbd5e1; }
        .pill-read.active { background: #475569; border-color: #334155; color: white; }
        .pill-dd { border-color: #e9d5ff; }
        .pill-dd.active { background: #7c3aed; border-color: #6d28d9; color: white; }
        
        .ai-btn { background: #7c3aed; color: white; border: none; padding: 6px 14px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 13px; display: inline-block; }
        .ai-btn:hover { background: #6d28d9; }
        .print-btn { background: #059669; color: white; border: none; padding: 6px 14px; border-radius: 6px; font-weight: 600; text-decoration: none; font-size: 13px; display: inline-block; }
        .print-btn:hover { background: #047857; }
        .txt-btn { background: #0284c7; color: white; border: none; padding: 6px 14px; border-radius: 6px; font-weight: 600; text-decoration: none; font-size: 13px; display: inline-block; }
        .txt-btn:hover { background: #0369a1; }
        .help-badge { background: #f8fafc; border: 1px solid #cbd5e1; color: #475569; padding: 4px 10px; border-radius: 50%; font-weight: bold; cursor: pointer; font-size: 13px; display: inline-flex; align-items: center; justify-content: center; width: 26px; height: 26px; transition: all 0.2s; }
        .help-badge:hover { background: #e2e8f0; color: #0f172a; border-color: #94a3b8; }
        .help-content { font-size: 14px; color: #334155; line-height: 1.6; }
        .help-content ul { padding-left: 20px; margin-top: 8px; }
        .help-content li { margin-bottom: 12px; }
        .example-box { background: #f1f5f9; border-left: 3px solid #7c3aed; padding: 8px 12px; margin-top: 4px; font-family: monospace; font-size: 12px; color: #1e293b; border-radius: 0 4px 4px 0; }

        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); overflow-y: auto; }
        .modal-content { background-color: white; margin: 10% auto; padding: 30px; border-radius: 10px; width: 60%; max-width: 700px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
        .close { color: #aaa; float: right; font-size: 26px; font-weight: bold; cursor: pointer; }
        .close:hover { color: #000; }
        .ai-textarea { width: 100%; height: 100px; padding: 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; font-family: inherit; margin-top: 10px; margin-bottom: 15px; resize: vertical; }

        .routine-card { background: white; border: 1px solid #cbd5e1; border-radius: 6px; padding: 14px 18px; margin-bottom: 12px; cursor: pointer; transition: all 0.2s; }
        .routine-card:hover { border-color: #2563eb; background: #f8fafc; }
        .routine-header { font-size: 15px; font-weight: bold; color: #0f172a; margin-bottom: 6px; font-family: monospace; display: flex; justify-content: space-between; align-items: center; }
        
        .code-box { background: #1e293b; color: #ffffff; padding: 8px 12px; border-radius: 4px; font-family: monospace; font-size: 12px; margin-top: 6px; overflow-x: auto; display: flex; justify-content: space-between; align-items: flex-start; border: 2px solid transparent; transition: border-color 0.2s; }
        .code-box.highlighted { border-color: #f59e0b; background: #0f172a; box-shadow: 0 0 10px rgba(245, 158, 11, 0.4); }
        .code-content { flex: 1; word-break: break-all; line-height: 1.4; }
        .match-line { color: #4ade80; font-weight: bold; margin: 2px 0; }
        
        .badge { padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold; text-transform: uppercase; margin-left: 8px; flex-shrink: 0; display: inline-block; vertical-align: middle; }
        .type-WRITE { background: #fee2e2; color: #991b1b; }
        .type-QUERY { background: #e0f2fe; color: #0369a1; }
        .type-READ { background: #f1f5f9; color: #64748b; }
        .type-DD_INSTALL { background: #f3e8ff; color: #7e22ce; }

        #loadingOverlay { display: none; position: fixed; z-index: 9999; top: 0; left: 0; width: 100%; height: 100%; background: rgba(255, 255, 255, 0.85); backdrop-filter: blur(2px); justify-content: center; align-items: center; flex-direction: column; }
        .spinner { width: 50px; height: 50px; border: 5px solid #e2e8f0; border-top: 5px solid #2563eb; border-radius: 50%; animation: spin 0.8s linear infinite; margin-bottom: 15px; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .loading-text { font-weight: 600; color: #0f172a; font-size: 16px; }
    </style>
    <script>
        function highlightCode(boxId) {
            document.querySelectorAll('.code-box').forEach(function(box) {
                box.classList.remove('highlighted');
            });
            var targetBox = document.getElementById(boxId);
            if (targetBox) {
                targetBox.classList.add('highlighted');
                targetBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }
        function openAiModal() { document.getElementById('aiPromptModal').style.display = 'block'; }
        function closeAiModal() { document.getElementById('aiPromptModal').style.display = 'none'; }
        function openHelpModal() { document.getElementById('aiHelpModal').style.display = 'block'; }
        function closeHelpModal() { document.getElementById('aiHelpModal').style.display = 'none'; }
        function showLoading() {
            document.getElementById('loadingOverlay').style.display = 'flex';
        }
    </script>
</head>
<body>
    <div id="loadingOverlay">
        <div class="spinner"></div>
        <div class="loading-text">⏳ Processing Package View... Please Wait</div>
    </div>

    <!-- AI Help Modal -->
    <div id="aiHelpModal" class="modal">
        <div class="modal-content" style="max-width: 750px;">
            <span class="close" onclick="closeHelpModal()">&times;</span>
            <h2 style="color: #0f172a; margin-top: 0; font-size: 20px; display: flex; align-items: center; gap: 8px;">
                <span>💡 AI Synthesis & Capabilities Guide</span>
            </h2>
            <div class="help-content">
                <p>The AI Agent analyzes your scoped VistA work packages and routines to assist with enterprise technical reviews. Here is how you can use its features:</p>
                
                <ul style="list-style-type: none; padding-left: 0;">
                    <li>
                        <strong>1. Architectural Impact Summaries</strong>
                        <div style="color: #64748b; font-size: 13px;">Synthesizes how enterprise routines interact with specific global nodes (e.g., File #2).</div>
                        <div class="example-box"><strong>Example Prompt:</strong> "Summarize how patient phone number updates in DGREG affect external subsystem indexing."</div>
                    </li>
                    
                    <li>
                        <strong>2. Automated Test & Regression Harness Generation</strong>
                        <div style="color: #64748b; font-size: 13px;">Writes structured MUMPS test routine code snippets designed to validate modified global references.</div>
                        <div class="example-box"><strong>Example Checkbox:</strong> Check <em>"Generate Automated MUMPS Test & Regression Harness"</em> to output test routine stubs validating `^DPT` writes.</div>
                    </li>
                    
                    <li>
                        <strong>3. Refining Work Packages & Design Handoffs</strong>
                        <div style="color: #64748b; font-size: 13px;">Scopes findings strictly to your selected namespace (e.g., PS or DG) to strip out noise for project teams.</div>
                        <div class="example-box"><strong>Example Use:</strong> Drill into namespace <code>DG</code>, click AI Synthesis, and export a clean architectural brief for your team handoff.</div>
                    </li>

                    <li>
                        <strong>4. Limitations: Graphs vs. Text Reports</strong>
                        <div style="color: #64748b; font-size: 13px;">The AI agent produces structured narrative text and code blocks, not native visual charts or real-time UI filtering.</div>
                        <div class="example-box"><strong>Note:</strong> Use the built-in Flask Access/Operation filters and Print/Plain Text views for reporting data, and rely on the AI for narrative documentation and code stubs.</div>
                    </li>
                </ul>
            </div>
            <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
                <button type="button" onclick="closeHelpModal()" style="padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 6px; font-weight: 600; cursor: pointer;">Got It</button>
            </div>
        </div>
    </div>

    <!-- AI Prompt Modal -->
    <div id="aiPromptModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeAiModal()">&times;</span>
            <h2 style="color: #0f172a; margin-top: 0; font-size: 20px;">🤖 Configure AI Architectural Analysis</h2>
            <p style="color: #475569; font-size: 14px; line-height: 1.5;">Generating AI synthesis scoped to package: <strong>{{ target_ns }}</strong></p>
            <form action="/impact/ai-brief" method="GET" onsubmit="showLoading()">
                <input type="hidden" name="file" value="{{ report.file_number }}">
                <input type="hidden" name="fields" value="{{ report.selected_fields | join(',') }}">
                <input type="hidden" name="ns" value="{{ target_ns }}">
                <input type="hidden" name="op_filter" value="{{ op_filter }}">
                <input type="hidden" name="access_filter" value="{{ access_filter }}">
                
                <textarea name="change_description" class="ai-textarea" placeholder="E.g., Changing field validation rules, adding a new required cross-reference, or migrating API calls..."></textarea>
                
                <div style="margin-bottom: 20px; display: flex; align-items: center; gap: 10px; background: #f1f5f9; padding: 12px; border-radius: 6px; border: 1px solid #cbd5e1;">
                    <input type="checkbox" id="create_harness" name="create_harness" value="true" style="width: 18px; height: 18px; cursor: pointer;">
                    <label for="create_harness" style="font-size: 14px; font-weight: 600; color: #0f172a; cursor: pointer;">🧪 Generate Automated MUMPS Test & Regression Harness</label>
                </div>

                <div style="display: flex; justify-content: flex-end; gap: 10px;">
                    <button type="button" onclick="closeAiModal()" style="padding: 8px 16px; background: #e2e8f0; border: none; border-radius: 6px; font-weight: 600; cursor: pointer;">Cancel</button>
                    <button type="submit" class="ai-btn" style="padding: 8px 20px;">Generate Analysis 🚀</button>
                </div>
            </form>
        </div>
    </div>

    <div class="container">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
            <a href="/impact/report?file={{ report.file_number }}&fields={{ report.selected_fields | join(',') }}" class="nav-btn" onclick="showLoading()">← Back to Enterprise Overview</a>
            <div style="display: flex; gap: 10px; align-items: center;">
                <a href="/impact/package-plaintext?file={{ report.file_number }}&fields={{ report.selected_fields | join(',') }}&ns={{ target_ns }}{% if op_filter %}&op_filter={{ op_filter }}{% endif %}{% if access_filter %}&access_filter={{ access_filter }}{% endif %}" target="_blank" class="txt-btn">📄 Plain Text Report →</a>
                <a href="/impact/package-print?file={{ report.file_number }}&fields={{ report.selected_fields | join(',') }}&ns={{ target_ns }}{% if op_filter %}&op_filter={{ op_filter }}{% endif %}{% if access_filter %}&access_filter={{ access_filter }}{% endif %}" target="_blank" class="print-btn">🖨️ Print View →</a>
                <button type="button" onclick="openAiModal()" class="ai-btn">🤖 Generate AI Synthesis →</button>
                <button type="button" onclick="openHelpModal()" class="help-badge" title="AI Capabilities Guide">?</button>
            </div>
        </div>

        <h1>Impact Analysis Report: File #{{ report.file_number }} - {{ report.file_description }}</h1>
        <div style="font-family: monospace; font-size: 14px; color: #2563eb; font-weight: bold; margin-bottom: 15px;">MUMPS Global Root: {{ report.global_root }}</div>
        <div class="sub">Namespace Package: <strong>{{ target_ns }}</strong>. Click any routine below to instantly highlight and focus its affected line of code.</div>

        <div style="background: #f8fafc; border: 1px solid #e2e8f0; padding: 20px; border-radius: 8px; margin-bottom: 25px;">
            <div style="margin-bottom: 15px;">
                <h3 style="margin: 0 0 8px 0; color: #0f172a; font-size: 15px;">Access Strategy Filter</h3>
                <a href="/impact/package-report?file={{ report.file_number }}&fields={{ report.selected_fields | join(',') }}&ns={{ target_ns }}{% if op_filter %}&op_filter={{ op_filter }}{% endif %}" class="pill {% if not access_filter %}active{% endif %}" onclick="showLoading()">[All Access Modes]</a>
                <a href="/impact/package-report?file={{ report.file_number }}&fields={{ report.selected_fields | join(',') }}&ns={{ target_ns }}&access_filter=direct{% if op_filter %}&op_filter={{ op_filter }}{% endif %}" class="pill {% if access_filter == 'direct' %}active{% endif %}" onclick="showLoading()">Direct Global Only ({{ report.global_root }})</a>
                <a href="/impact/package-report?file={{ report.file_number }}&fields={{ report.selected_fields | join(',') }}&ns={{ target_ns }}&access_filter=fileman{% if op_filter %}&op_filter={{ op_filter }}{% endif %}" class="pill {% if access_filter == 'fileman' %}active{% endif %}" onclick="showLoading()">FileMan / Cross-References</a>
            </div>

            <hr style="border:0; border-top: 1px solid #e2e8f0; margin: 15px 0;">

            <div style="margin-bottom: 8px;">
                <h3 style="margin: 0 0 8px 0; color: #0f172a; font-size: 15px;">Operation Filter</h3>
            </div>
            <div>
                <a href="/impact/package-report?file={{ report.file_number }}&fields={{ report.selected_fields | join(',') }}&ns={{ target_ns }}{% if access_filter %}&access_filter={{ access_filter }}{% endif %}" class="pill {% if not op_filter %}active{% endif %}" onclick="showLoading()">[All Operations]</a>
                <a href="/impact/package-report?file={{ report.file_number }}&fields={{ report.selected_fields | join(',') }}&ns={{ target_ns }}&op_filter=WRITE{% if access_filter %}&access_filter={{ access_filter }}{% endif %}" class="pill pill-write {% if op_filter == 'WRITE' %}active{% endif %}" onclick="showLoading()">WRITE</a>
                <a href="/impact/package-report?file={{ report.file_number }}&fields={{ report.selected_fields | join(',') }}&ns={{ target_ns }}&op_filter=QUERY{% if access_filter %}&access_filter={{ access_filter }}{% endif %}" class="pill pill-query {% if op_filter == 'QUERY' %}active{% endif %}" onclick="showLoading()">QUERY</a>
                <a href="/impact/package-report?file={{ report.file_number }}&fields={{ report.selected_fields | join(',') }}&ns={{ target_ns }}&op_filter=READ{% if access_filter %}&access_filter={{ access_filter }}{% endif %}" class="pill pill-read {% if op_filter == 'READ' %}active{% endif %}" onclick="showLoading()">READ</a>
                <a href="/impact/package-report?file={{ report.file_number }}&fields={{ report.selected_fields | join(',') }}&ns={{ target_ns }}&op_filter=DD_INSTALL{% if access_filter %}&access_filter={{ access_filter }}{% endif %}" class="pill pill-dd {% if op_filter == 'DD_INSTALL' %}active{% endif %}" onclick="showLoading()">DD / INSTALL</a>
            </div>
        </div>

        <div style="display: flex; gap: 20px; margin-bottom: 25px;">
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; padding: 15px 20px; border-radius: 6px; flex: 1;">
                <h3 style="margin: 0 0 5px 0; font-size: 13px; color: #64748b; text-transform: uppercase;">Affected Routines ({{ target_ns }})</h3>
                <p style="margin: 0; font-size: 20px; font-weight: bold; color: #0f172a;">{{ report.total_routines_affected }} routines</p>
            </div>
        </div>

        <h3 style="font-size: 18px; color: #0f172a;">Affected Routines List</h3>
        
        {% if report.namespaces_grouped %}
            {% for ns_group in report.namespaces_grouped %}
                {% for rot in ns_group.routines %}
                <div class="routine-card" onclick="highlightCode('codebox-{{ loop.index0 }}-{{ rot.routine_name }}')">
                    <div class="routine-header">
                        <span>Routine: <strong>{{ rot.routine_name }}</strong></span>
                        <span style="font-size: 12px; color: #64748b;">Matches: {{ rot.total_matches }}</span>
                    </div>
                    
                    {% for item in rot.matched_lines %}
                    <div id="codebox-{{ loop.index0 }}-{{ rot.routine_name }}" class="code-box">
                        <div class="code-content">
                            <div class="match-line">{{ item.code }}</div>
                        </div>
                        <span class="badge type-{{ item.type }}">{{ item.type }}</span>
                    </div>
                    {% endfor %}
                </div>
                {% endfor %}
            {% endfor %}
        {% else %}
            <div style="background: #f8fafc; border: 1px solid #cbd5e1; padding: 30px; border-radius: 8px; text-align: center; color: #64748b;">
                <p style="margin: 0; font-size: 15px; font-weight: 500;">No routines found for package {{ target_ns }} under the current filters.</p>
            </div>
        {% endif %}
    </div>
</body>
</html>
    """
    return render_template_string(html_template, report=report, target_ns=target_ns, op_filter=op_filter, access_filter=access_filter)

# ==========================================
# PAGE 3: Print / PDF Report View Route
# ==========================================
@app.route('/impact/package-print')
def package_print_view():
    file_num = request.args.get('file', '').strip()
    fields_param = request.args.get('fields', '').strip()
    target_ns = request.args.get('ns', '').strip()
    op_filter = request.args.get('op_filter', '').strip()
    access_filter = request.args.get('access_filter', '').strip()
    
    if not file_num or not target_ns:
        return "Missing file or namespace parameter", 400

    selected_fields = fields_param.split(',') if fields_param else []
    analyzer = ImpactAnalyzer(DB_PATH)
    master_report = analyzer.analyze_selected_fields(file_num, selected_fields)

    target_group = None
    g_root = master_report.get('global_root', '').strip('()')

    for ns in master_report.get('namespaces_grouped', []):
        if ns.get('namespace') == target_ns:
            filtered_routines = []
            for rot in ns.get('routines', []):
                filtered_lines = []
                for line in rot.get('matched_lines', []):
                    code_str = line.get('code', '')
                    
                    if '^DD(' in code_str:
                        line['type'] = 'DD_INSTALL'
                    
                    is_direct = g_root and (g_root in code_str or g_root.upper() in code_str.upper())
                    is_fileman = any(token in code_str.upper() for token in ['DIE', 'DIC', 'DIK', 'D ^DIE', 'D ^DIC', 'D ^DIK'])
                    is_dd_install = ('^DD(' in code_str)
                    
                    if access_filter == 'direct' and not is_direct:
                        continue
                    elif access_filter == 'fileman' and not (is_fileman or is_dd_install or not is_direct):
                        continue
                        
                    if op_filter and line.get('type') != op_filter:
                        continue

                    filtered_lines.append(line)
                
                if filtered_lines:
                    rot_copy = rot.copy()
                    rot_copy['matched_lines'] = filtered_lines
                    rot_copy['total_matches'] = len(filtered_lines)
                    filtered_routines.append(rot_copy)
            
            if filtered_routines:
                target_group = ns.copy()
                target_group['routines'] = filtered_routines
                target_group['routine_count'] = len(filtered_routines)
            break

    report = master_report.copy()
    report['namespaces_grouped'] = [target_group] if target_group else []
    report['total_routines_affected'] = target_group['routine_count'] if target_group else 0
    report['total_namespaces_affected'] = 1

    return render_template_string("""
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Print Report - Package {{ target_ns }} (File #{{ report.file_number }})</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #ffffff; color: #0f172a; margin: 0; padding: 40px; }
        .container { max-width: 1000px; margin: 0 auto; }
        h1 { margin-top: 0; font-size: 22px; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }
        .meta { font-size: 13px; color: #475569; margin-bottom: 25px; line-height: 1.6; background: #f8fafc; padding: 15px; border-radius: 6px; border: 1px solid #e2e8f0; }
        .routine-block { margin-bottom: 20px; border: 1px solid #cbd5e1; border-radius: 6px; padding: 15px; background: #ffffff; page-break-inside: avoid; }
        .routine-title { font-family: monospace; font-size: 14px; font-weight: bold; color: #0f172a; margin-bottom: 8px; display: flex; justify-content: space-between; }
        .code-line { font-family: monospace; font-size: 12px; background: #1e293b; color: #ffffff; padding: 6px 10px; border-radius: 4px; margin-top: 4px; display: flex; justify-content: space-between; align-items: flex-start; }
        .match-line { color: #4ade80; font-weight: bold; }
        .badge { padding: 2px 6px; border-radius: 3px; font-size: 9px; font-weight: bold; text-transform: uppercase; }
        .type-WRITE { background: #fee2e2; color: #991b1b; }
        .type-QUERY { background: #e0f2fe; color: #0369a1; }
        .type-READ { background: #f1f5f9; color: #64748b; }
        .type-DD_INSTALL { background: #f3e8ff; color: #7e22ce; }
        .print-bar { margin-bottom: 25px; display: flex; gap: 10px; }
        .print-btn { background: #2563eb; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; cursor: pointer; }
        .print-btn:hover { background: #1d4ed8; }
        .back-btn { background: #e2e8f0; color: #334155; text-decoration: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; font-size: 13px; display: inline-block; }
        .back-btn:hover { background: #cbd5e1; }
        @media print {
            .print-bar { display: none; }
            body { padding: 0; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="print-bar">
            <button onclick="window.print()" class="print-btn">🖨️ Print / Save as PDF</button>
            <a href="javascript:history.back()" class="back-btn">← Back to Package Report</a>
        </div>

        <h1>Developer Work Package Report: Namespace {{ target_ns }}</h1>
        <div class="meta">
            Target File: <strong>#{{ report.file_number }} - {{ report.file_description }}</strong> (`{{ report.global_root }}`)<br>
            Access Strategy Filter: <strong>{{ access_filter | upper if access_filter else 'ALL ACCESS MODES' }}</strong><br>
            Operation Filter: <strong>{{ op_filter if op_filter else 'ALL OPERATIONS' }}</strong><br>
            Total Impacted Routines: <strong>{{ report.total_routines_affected }}</strong>
        </div>

        {% if report.namespaces_grouped %}
            {% for ns_group in report.namespaces_grouped %}
                {% for rot in ns_group.routines %}
                <div class="routine-block">
                    <div class="routine-title">
                        <span>Routine: {{ rot.routine_name }}</span>
                        <span style="font-size: 12px; color: #64748b;">Matches: {{ rot.total_matches }}</span>
                    </div>
                    {% for item in rot.matched_lines %}
                    <div class="code-line">
                        <div style="flex: 1; word-break: break-all;">
                            <div class="match-line">{{ item.code }}</div>
                        </div>
                        <span class="badge type-{{ item.type }}">{{ item.type }}</span>
                    </div>
                    {% endfor %}
                </div>
                {% endfor %}
            {% endfor %}
        {% else %}
            <p style="color: #64748b; font-style: italic;">No routines matched the selected print filters.</p>
        {% endif %}
    </div>
</body>
</html>
    """, report=report, target_ns=target_ns, op_filter=op_filter, access_filter=access_filter)

# ==========================================
# PAGE 4: Plain Text Report View Route
# ==========================================
@app.route('/impact/package-plaintext')
def package_plaintext_view():
    file_num = request.args.get('file', '').strip()
    fields_param = request.args.get('fields', '').strip()
    target_ns = request.args.get('ns', '').strip()
    op_filter = request.args.get('op_filter', '').strip()
    access_filter = request.args.get('access_filter', '').strip()
    
    if not file_num or not target_ns:
        return "Missing file or namespace parameter", 400

    selected_fields = fields_param.split(',') if fields_param else []
    analyzer = ImpactAnalyzer(DB_PATH)
    master_report = analyzer.analyze_selected_fields(file_num, selected_fields)

    target_group = None
    g_root = master_report.get('global_root', '').strip('()')

    for ns in master_report.get('namespaces_grouped', []):
        if ns.get('namespace') == target_ns:
            filtered_routines = []
            for rot in ns.get('routines', []):
                filtered_lines = []
                for line in rot.get('matched_lines', []):
                    code_str = line.get('code', '')
                    
                    if '^DD(' in code_str:
                        line['type'] = 'DD_INSTALL'
                    
                    is_direct = g_root and (g_root in code_str or g_root.upper() in code_str.upper())
                    is_fileman = any(token in code_str.upper() for token in ['DIE', 'DIC', 'DIK', 'D ^DIE', 'D ^DIC', 'D ^DIK'])
                    is_dd_install = ('^DD(' in code_str)
                    
                    if access_filter == 'direct' and not is_direct:
                        continue
                    elif access_filter == 'fileman' and not (is_fileman or is_dd_install or not is_direct):
                        continue
                        
                    if op_filter and line.get('type') != op_filter:
                        continue

                    filtered_lines.append(line)
                
                if filtered_lines:
                    rot_copy = rot.copy()
                    rot_copy['matched_lines'] = filtered_lines
                    rot_copy['total_matches'] = len(filtered_lines)
                    filtered_routines.append(rot_copy)
            
            if filtered_routines:
                target_group = ns.copy()
                target_group['routines'] = filtered_routines
                target_group['routine_count'] = len(filtered_routines)
            break

    report = master_report.copy()
    report['namespaces_grouped'] = [target_group] if target_group else []
    report['total_routines_affected'] = target_group['routine_count'] if target_group else 0
    report['total_namespaces_affected'] = 1

    txt_lines = []
    txt_lines.append("================================================================")
    txt_lines.append(f"VISTA IMPACT ANALYSIS REPORT - PLAIN TEXT EXPORT")
    txt_lines.append("================================================================")
    txt_lines.append(f"Target File : #{report['file_number']} - {report['file_description']} ({report['global_root']})")
    txt_lines.append(f"Namespace   : {target_ns}")
    txt_lines.append(f"Access Mode : {access_filter.upper() if access_filter else 'ALL'}")
    txt_lines.append(f"Operations  : {op_filter if op_filter else 'ALL'}")
    txt_lines.append(f"Total Routines Affected: {report['total_routines_affected']}")
    txt_lines.append("================================================================")
    txt_lines.append("")

    if report['namespaces_grouped']:
        for ns_group in report['namespaces_grouped']:
            for rot in ns_group['routines']:
                txt_lines.append(f"ROUTINE: {rot['routine_name']} (Matches: {rot['total_matches']})")
                for item in rot['matched_lines']:
                    txt_lines.append(f"  [{item['type']}] {item['code']}")
                txt_lines.append("-" * 64)
    else:
        txt_lines.append("No routines matched the current filters.")

    plain_text_output = "\n".join(txt_lines)

    return render_template_string("""
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Plain Text Report - Package {{ target_ns }}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 40px; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); border: 1px solid #e2e8f0; }
        h1 { margin-top: 0; font-size: 22px; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }
        .nav-bar { margin-bottom: 20px; display: flex; gap: 10px; }
        .nav-btn { background: #e2e8f0; color: #334155; text-decoration: none; padding: 6px 14px; border-radius: 6px; font-weight: 500; font-size: 13px; display: inline-block; }
        .nav-btn:hover { background: #cbd5e1; }
        .ai-btn { background: #7c3aed; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 13px; }
        .ai-btn:hover { background: #6d28d9; }
        pre { background: #1e293b; color: #4ade80; padding: 20px; border-radius: 8px; overflow-x: auto; font-family: monospace; font-size: 13px; line-height: 1.5; margin-top: 15px; }
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); overflow-y: auto; }
        .modal-content { background-color: white; margin: 10% auto; padding: 30px; border-radius: 10px; width: 60%; max-width: 700px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
        .close { color: #aaa; float: right; font-size: 26px; font-weight: bold; cursor: pointer; }
        .close:hover { color: #000; }
        .ai-textarea { width: 100%; height: 100px; padding: 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; font-family: inherit; margin-top: 10px; margin-bottom: 15px; resize: vertical; }

        #loadingOverlay { display: none; position: fixed; z-index: 9999; top: 0; left: 0; width: 100%; height: 100%; background: rgba(255, 255, 255, 0.85); backdrop-filter: blur(2px); justify-content: center; align-items: center; flex-direction: column; }
        .spinner { width: 50px; height: 50px; border: 5px solid #e2e8f0; border-top: 5px solid #2563eb; border-radius: 50%; animation: spin 0.8s linear infinite; margin-bottom: 15px; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .loading-text { font-weight: 600; color: #0f172a; font-size: 16px; }
    </style>
    <script>
        function openAiModal() { document.getElementById('aiPromptModal').style.display = 'block'; }
        function closeAiModal() { document.getElementById('aiPromptModal').style.display = 'none'; }
        function showLoading() {
            document.getElementById('loadingOverlay').style.display = 'flex';
        }
    </script>
</head>
<body>
    <div id="loadingOverlay">
        <div class="spinner"></div>
        <div class="loading-text">⏳ Processing AI Synthesis... Please Wait</div>
    </div>

    <div id="aiPromptModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeAiModal()">&times;</span>
            <h2 style="color: #0f172a; margin-top: 0; font-size: 20px;">🤖 Configure AI Architectural Analysis</h2>
            <p style="color: #475569; font-size: 14px; line-height: 1.5;">Synthesizing plain text work package for namespace: <strong>{{ target_ns }}</strong></p>
            <form action="/impact/ai-brief" method="GET" onsubmit="showLoading()">
                <input type="hidden" name="file" value="{{ report.file_number }}">
                <input type="hidden" name="fields" value="{{ report.selected_fields | join(',') }}">
                <input type="hidden" name="ns" value="{{ target_ns }}">
                <input type="hidden" name="op_filter" value="{{ op_filter }}">
                <input type="hidden" name="access_filter" value="{{ access_filter }}">
                
                <textarea name="change_description" class="ai-textarea" placeholder="E.g., Changing field validation rules, adding a new required cross-reference, or migrating API calls..."></textarea>
                
                <div style="margin-bottom: 20px; display: flex; align-items: center; gap: 10px; background: #f1f5f9; padding: 12px; border-radius: 6px; border: 1px solid #cbd5e1;">
                    <input type="checkbox" id="create_harness" name="create_harness" value="true" style="width: 18px; height: 18px; cursor: pointer;">
                    <label for="create_harness" style="font-size: 14px; font-weight: 600; color: #0f172a; cursor: pointer;">🧪 Generate Automated MUMPS Test & Regression Harness</label>
                </div>

                <div style="display: flex; justify-content: flex-end; gap: 10px;">
                    <button type="button" onclick="closeAiModal()" style="padding: 8px 16px; background: #e2e8f0; border: none; border-radius: 6px; font-weight: 600; cursor: pointer;">Cancel</button>
                    <button type="submit" class="ai-btn" style="padding: 8px 20px;">Generate Analysis 🚀</button>
                </div>
            </form>
        </div>
    </div>

    <div class="container">
        <div class="nav-bar">
            <a href="javascript:history.back()" class="nav-btn">← Back to Package Report</a>
        </div>

        <h1>
            <span>📄 Plain Text Report: Namespace {{ target_ns }}</span>
            <button type="button" onclick="openAiModal()" class="ai-btn">🤖 Generate AI Synthesis →</button>
        </h1>

        <pre>{{ plain_text_output }}</pre>
    </div>
</body>
</html>
    """, report=report, target_ns=target_ns, plain_text_output=plain_text_output, op_filter=op_filter, access_filter=access_filter)

# ==========================================
# AI Synthesis Brief Route
# ==========================================
@app.route('/impact/ai-brief')
def ai_brief_view():
    file_num = request.args.get('file', '').strip()
    fields_param = request.args.get('fields', '').strip()
    target_ns = request.args.get('ns', '').strip()
    change_description = request.args.get('change_description', '').strip()
    create_harness = request.args.get('create_harness') == 'true'
    
    if not file_num or not target_ns:
        return "Missing file or namespace parameter", 400

    selected_fields = fields_param.split(',') if fields_param else []
    analyzer = ImpactAnalyzer(DB_PATH)
    master_report = analyzer.analyze_selected_fields(file_num, selected_fields)

    scoped_groups = [ns for ns in master_report.get('namespaces_grouped', []) if ns.get('namespace') == target_ns]
    report = master_report.copy()
    report['namespaces_grouped'] = scoped_groups
    report['total_routines_affected'] = sum(ns.get('routine_count', len(ns.get('routines', []))) for ns in scoped_groups)
    report['total_namespaces_affected'] = len(scoped_groups)
    
    ai_summary = analyzer.generate_ai_architectural_summary(report, change_description, create_harness)

    return render_template_string("""
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>AI Architectural Synthesis - {{ target_ns }}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 40px; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); border: 1px solid #e2e8f0; }
        h1 { margin-top: 0; font-size: 24px; color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 12px; display: flex; align-items: center; gap: 10px; }
        .badge-ai { background: #dbeafe; color: #1e40af; font-size: 12px; padding: 4px 10px; border-radius: 20px; font-weight: bold; }
        .content-box { background: #f8fafc; border: 1px solid #cbd5e1; padding: 25px; border-radius: 8px; line-height: 1.6; font-size: 15px; margin-top: 20px; white-space: pre-line; }
        .nav-btn { display: inline-block; margin-bottom: 20px; padding: 6px 14px; background: #e2e8f0; color: #334155; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 13px; }
        .nav-btn:hover { background: #cbd5e1; }
        pre { background: #1e293b; color: #4ade80; padding: 15px; border-radius: 6px; overflow-x: auto; font-family: monospace; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <a href="javascript:history.back()" class="nav-btn">← Back</a>
        <h1>🤖 AI Synthesis: Package {{ target_ns }} <span class="badge-ai">Scoped Work Package</span></h1>
        
        <div class="content-box">
            {{ ai_summary }}
        </div>
    </div>
</body>
</html>
    """, report=report, target_ns=target_ns, ai_summary=ai_summary)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)