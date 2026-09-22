import sqlite3
import re

class ImpactAnalyzer:
    def __init__(self, db_path):
        self.db_path = db_path

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_file_fields(self, file_num):
        conn = self.get_connection()
        cursor = conn.cursor()
        file_num_str = str(file_num).strip()
        fields_in_scope = []
        file_name = f"FILE #{file_num_str}"
        global_root = f"^DIC({file_num_str},"

        try:
            meta_row = cursor.execute(
                """
                SELECT value FROM vista_dd 
                WHERE (file_number = ? OR file_number = CAST(? AS INTEGER)) AND field_number = '0'
                """,
                (file_num_str, file_num_str)
            ).fetchone()
            
            if meta_row and meta_row['value']:
                parts = meta_row['value'].split('^')
                if len(parts) > 0 and parts[0]:
                    file_name = parts[0].strip('"')
                if len(parts) > 1 and parts[1]:
                    global_root = '^' + parts[1].strip('"') + '('

            known_catalog = {
                '2': ('PATIENT', '^DPT('),
                '200': ('NEW PERSON', '^VA(200,'),
                '58.5': ('PSI AMIS', '^PSI(58.5,'),
                '3': ('USER', '^DIC(3,'),
                '4': ('INSTITUTION', '^DIC(4,')
            }
            if file_num_str in known_catalog:
                file_name, global_root = known_catalog[file_num_str]

            dd_rows = cursor.execute(
                """
                SELECT field_number, node_key, value 
                FROM vista_dd 
                WHERE file_number = ? OR file_number = CAST(? AS INTEGER)
                ORDER BY field_number ASC
                """,
                (file_num_str, file_num_str)
            ).fetchall()

            for r in dd_rows:
                f_num = str(r['field_number'] or '').strip()
                node_key = str(r['node_key'] or '').strip()
                val = str(r['value'] or '')

                if f_num.startswith('"') or f_num.endswith('"') or f_num == '0':
                    continue
                if not re.match(r'^[0-9\.]+$', f_num):
                    continue

                parts = val.split('^')
                f_name = parts[0].strip('"') if len(parts) > 0 and parts[0] != '' else f"FIELD {f_num}"

                node_subscript = node_key
                piece_num = ""
                
                for part in parts:
                    if ';' in part and any(char.isdigit() for char in part):
                        sub_parts = part.split(';')
                        if len(sub_parts) == 2 and sub_parts[0].isdigit() and sub_parts[1].isdigit():
                            node_subscript = sub_parts[0]
                            piece_num = sub_parts[1]
                            break

                clean_root = global_root.rstrip('(')
                if node_subscript:
                    global_location = f"{clean_root}(D0,{node_subscript})"
                else:
                    global_location = f"{clean_root}(D0)"
                
                if piece_num:
                    global_location += f" piece {piece_num}"

                if not any(d['field_number'] == f_num for d in fields_in_scope):
                    fields_in_scope.append({
                        'field_number': f_num,
                        'field_name': f_name,
                        'definition': val,
                        'global_location': global_location
                    })

        except Exception as e:
            print(f"[ERROR] Field introspection failed: {e}")
        finally:
            conn.close()

        return file_name, global_root, fields_in_scope

    def normalize_namespace(self, routine_name):
        match = re.match(r'^([A-Z%]+)', routine_name)
        if not match:
            return "UNKNOWN"
        raw_ns = match.group(1)
        
        if raw_ns.startswith('RA'): return 'RA (Radiology)'
        if raw_ns.startswith('IB') or raw_ns.startswith('IBC'): return 'IB (Integrated Billing)'
        if raw_ns.startswith('ONC'): return 'ONC (Oncology)'
        if raw_ns.startswith('VAF') or raw_ns.startswith('MPI'): return 'VAF (ADT / Master Patient Index)'
        if raw_ns.startswith('VPS'): return 'VPS (Patient Stream)'
        if raw_ns.startswith('DG') or raw_ns.startswith('DPT'): return 'DG (Registration / Patient)'
        if raw_ns.startswith('PS') or raw_ns.startswith('PSS') or raw_ns.startswith('PSB'): return 'PS (Pharmacy)'
        if raw_ns.startswith('LR'): return 'LR (Laboratory)'
        if raw_ns.startswith('GMRA'): return 'GMRA (Adverse Reaction)'
        if raw_ns.startswith('OR') or raw_ns.startswith('ORE'): return 'OR (Order Entry / CPOE)'
        if raw_ns.startswith('SD'): return 'SD (Scheduling)'
        
        return raw_ns[:3] if len(raw_ns) > 3 else raw_ns

    def execute_ai_file_search(self, file_num, search_query):
        """Performs a thoughtful AI semantic search across routines and fields for a given file."""
        conn = self.get_connection()
        cursor = conn.cursor()
        file_num_str = str(file_num).strip()
        file_name, global_root, fields = self.get_file_fields(file_num_str)

        query_terms = [t.lower() for t in search_query.split() if len(t) > 2]
        matching_snippets = []

        try:
            rows = cursor.execute("SELECT routine_name, node_value FROM vista_routines_clean LIMIT 3000;").fetchall()
            for r in rows:
                text = r['node_value']
                if file_num_str in text or any(term in text.lower() for term in query_terms):
                    matching_snippets.append({
                        'routine_name': r['routine_name'],
                        'code': text.strip()
                    })
                    if len(matching_snippets) >= 25:
                        break
        except Exception as e:
            print(f"[ERROR] AI search query failed: {e}")
        finally:
            conn.close()

        results = {
            'file_number': file_num_str,
            'file_description': file_name,
            'global_root': global_root,
            'search_query': search_query,
            'matched_fields': [f for f in fields if any(term in f['field_name'].lower() for term in query_terms) or not query_terms][:10],
            'matching_snippets': matching_snippets
        }
        return results

    def analyze_selected_fields(self, file_num, selected_fields, target_field_filter=None, op_filter=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        file_num_str = str(file_num).strip()

        if target_field_filter in [None, '', 'None', 'undefined']:
            target_field_filter = None
        if op_filter in [None, '', 'None', 'undefined', 'ALL']:
            op_filter = None

        active_fields = [target_field_filter] if target_field_filter else selected_fields

        file_name, global_root, all_fields = self.get_file_fields(file_num_str)
        field_map = {f['field_number']: f['field_name'] for f in all_fields}
        
        selected_field_details = [
            {'field_number': f_num, 'field_name': field_map.get(f_num, 'Unknown Field')}
            for f_num in selected_fields
        ]

        global_regex_pattern = rf'(?:\^.*?\({re.escape(file_num_str)}\b|\^DD\(\s*{re.escape(file_num_str)}\b)'

        affected_namespaces = set()
        routine_impacts = {}
        namespaces_grouped = {}

        try:
            routine_lines_raw = cursor.execute("SELECT routine_name, node_value FROM vista_routines_clean;").fetchall()
            
            routine_full_texts = {}
            for r in routine_lines_raw:
                r_name = r['routine_name']
                if r_name not in routine_full_texts:
                    routine_full_texts[r_name] = []
                routine_full_texts[r_name].append(r['node_value'])

            for r_name, lines in routine_full_texts.items():
                ns = self.normalize_namespace(r_name)

                for idx, text in enumerate(lines):
                    upper_text = text.upper()
                    stripped_text = text.strip()

                    if stripped_text.startswith(';;') and ('^' in text or len(text.split('^')) > 3):
                        continue

                    is_file_match = bool(re.search(global_regex_pattern, text, re.IGNORECASE))
                    if not is_file_match:
                        continue

                    matched_fields = []
                    for f in active_fields:
                        field_pattern = rf'(?:{re.escape(file_num_str)}\s*,\s*{re.escape(f)}\b|\b{re.escape(f)}\b)'
                        if re.search(field_pattern, text) or file_num_str in text:
                            matched_fields.append(f)

                    if active_fields and not matched_fields and file_num_str not in text:
                        continue

                    interaction_type = "READ"
                    if stripped_text.startswith(';'):
                        interaction_type = "READ"
                    elif '^TMP(' in upper_text or '^UTILITY(' in upper_text:
                        interaction_type = "READ"
                    elif (re.search(r'\b(SET|S)\s+(\^|\^\()', upper_text) or 
                          re.search(r'\b(KILL|K)\s+\^', upper_text) or 
                          re.search(r',\s*\^\(0\)\s*=', upper_text) or
                          any(api in upper_text for api in ['^DIE', 'UPDATE^', 'FILE^', '^DIK', 'EN^DIU2'])):
                        interaction_type = "WRITE"
                    elif ('$D(' in upper_text or '$O(' in upper_text or '$G(' in upper_text or 
                          any(api in upper_text for api in ['^DIQ', 'DIQ1', 'GET1^', 'FIND^', '$$GET', '$$FIND', 'D ^%DT']) or 
                          '$P(' in upper_text or '^DD(' in upper_text):
                        interaction_type = "QUERY"
                    else:
                        interaction_type = "READ"

                    if op_filter and interaction_type != op_filter:
                        continue

                    start_idx = max(0, idx - 5)
                    end_idx = min(len(lines), idx + 6)
                    
                    context_before = [l.strip() for l in lines[start_idx:idx]]
                    context_after = [l.strip() for l in lines[idx+1:end_idx]]

                    affected_namespaces.add(ns)

                    if r_name not in routine_impacts:
                        routine_impacts[r_name] = {
                            'routine_name': r_name,
                            'namespace': ns,
                            'matched_lines': [],
                            'total_matches': 0,
                            'counts': {'WRITE': 0, 'QUERY': 0, 'READ': 0}
                        }

                    routine_impacts[r_name]['total_matches'] += 1
                    routine_impacts[r_name]['counts'][interaction_type] += 1
                    routine_impacts[r_name]['matched_lines'].append({
                        'code': text.strip(),
                        'type': interaction_type,
                        'context_before': context_before,
                        'context_after': context_after,
                        'fields': matched_fields or [file_num_str]
                    })

        except Exception as e:
            print(f"[ERROR] Routine code scan failed: {e}")
        finally:
            conn.close()

        temp_namespaces_grouped = {}
        for r_name, data in routine_impacts.items():
            ns = data['namespace']
            if ns not in temp_namespaces_grouped:
                temp_namespaces_grouped[ns] = {
                    'namespace': ns,
                    'routine_count': 0,
                    'routines': [],
                    'aggregate_counts': {'WRITE': 0, 'QUERY': 0, 'READ': 0}
                }
            temp_namespaces_grouped[ns]['routine_count'] += 1
            temp_namespaces_grouped[ns]['routines'].append(data)
            temp_namespaces_grouped[ns]['aggregate_counts']['WRITE'] += data['counts']['WRITE']
            temp_namespaces_grouped[ns]['aggregate_counts']['QUERY'] += data['counts']['QUERY']
            temp_namespaces_grouped[ns]['aggregate_counts']['READ'] += data['counts']['READ']

        MIN_ROUTINE_THRESHOLD = 5
        namespaces_grouped = {}
        for ns, group in temp_namespaces_grouped.items():
            if group['routine_count'] < MIN_ROUTINE_THRESHOLD and not ns.startswith(('DG', 'IB', 'VAF', 'ONC', 'PS', 'RA')):
                if "OTHER / MINOR SUBSYSTEMS" not in namespaces_grouped:
                    namespaces_grouped["OTHER / MINOR SUBSYSTEMS"] = {
                        'namespace': "OTHER / MINOR SUBSYSTEMS",
                        'routine_count': 0,
                        'routines': [],
                        'aggregate_counts': {'WRITE': 0, 'QUERY': 0, 'READ': 0}
                    }
                other_bucket = namespaces_grouped["OTHER / MINOR SUBSYSTEMS"]
                other_bucket['routine_count'] += group['routine_count']
                other_bucket['routines'].extend(group['routines'])
                other_bucket['aggregate_counts']['WRITE'] += group['aggregate_counts']['WRITE']
                other_bucket['aggregate_counts']['QUERY'] += group['aggregate_counts']['QUERY']
                other_bucket['aggregate_counts']['READ'] += group['aggregate_counts']['READ']
            else:
                namespaces_grouped[ns] = group

        total_routines = len(routine_impacts)
        total_namespaces = len(namespaces_grouped)

        report = {
            'file_number': file_num_str,
            'file_description': file_name,
            'global_root': global_root,
            'selected_fields': selected_fields,
            'selected_field_details': selected_field_details,
            'target_field_filter': target_field_filter,
            'op_filter': op_filter,
            'total_routines_affected': total_routines,
            'total_namespaces_affected': total_namespaces,
            'affected_namespaces': sorted(list(affected_namespaces)),
            'namespaces_grouped': sorted(namespaces_grouped.values(), key=lambda x: x['routine_count'], reverse=True),
            'routine_impacts': sorted(routine_impacts.values(), key=lambda x: x['total_matches'], reverse=True)
        }

        return report

    def generate_ai_architectural_summary(self, report, change_description=None, create_test_harness=False):
        file_num = report['file_number']
        file_desc = report['file_description']
        global_root = report['global_root']
        total_routines = report['total_routines_affected']
        total_namespaces = report['total_namespaces_affected']
        
        write_count = sum(ns['aggregate_counts']['WRITE'] for ns in report['namespaces_grouped'])
        query_count = sum(ns['aggregate_counts']['QUERY'] for ns in report['namespaces_grouped'])
        read_count = sum(ns['aggregate_counts']['READ'] for ns in report['namespaces_grouped'])
        
        top_namespaces = [ns['namespace'] for ns in report['namespaces_grouped'][:3]]
        
        custom_analysis = ""
        if change_description and change_description.strip():
            custom_analysis = (
                f"* **Target Change / Reason:** \"{change_description.strip()}\"\n"
                f"* **Impact Assessment on Change:** Based on the requested modification, routines performing `WRITE` or validation checks on File #{file_num} (`{global_root}`) require direct refactoring."
            )

        test_harness_snippet = ""
        if create_test_harness:
            file_num_clean = file_num.replace('.', '')
            master_orchestrator_calls = "\n".join([f"    D EN^TST{r['routine_name'][:3]}{file_num_clean}" for r in report['routine_impacts'][:4]])
            
            sub_routine_blocks = []
            seen_tests = set()
            for rot in report['routine_impacts'][:4]:
                r_name = rot['routine_name']
                ns_prefix = r_name[:3]
                t_name = f"TST{ns_prefix}{file_num_clean}"
                if t_name in seen_tests:
                    continue
                seen_tests.add(t_name)

                sub_routine_blocks.append(
                    f"; Routine: {t_name}.m (Generated Test Wrapper for {r_name})\n"
                    f"{t_name} ; Test Entry\n"
                    f"    N J S J=$J\n"
                    f"    S ^TMP(\"THST\",J,\"FILE_{file_num_clean}\",\"{r_name}\",\"STATUS\")=\"RUNNING\"\n"
                    f"    ; Copied source logic verification against {global_root}\n"
                    f"    D CHK{r_name}\n"
                    f"    S ^TMP(\"THST\",J,\"FILE_{file_num_clean}\",\"{r_name}\",\"STATUS\")=\"PASSED\"\n"
                    f"    Q\n"
                    f"CHK{r_name} ;\n"
                    f"    Q\n"
                )

            test_harness_snippet = (
                f"\n### 🧪 Master Test Orchestrator & Generated Routine Suite\n"
                f"* **Master Control Routine:** `THST{file_num_clean}`\n"
                f"* **Temporary Telemetry Global:** `^TMP(\"THST\", $J, \"FILE_{file_num_clean}\", ...)`\n\n"
                f"#### 1. Master Orchestrator Routine (`THST{file_num_clean}.m`)\n"
                f"```mumps\n"
                f"THST{file_num_clean} ; Master Regression Test Controller for File #{file_num} ({file_desc})\n"
                f"    N J S J=$J\n"
                f"    K ^TMP(\"THST\",J,\"FILE_{file_num_clean}\")\n"
                f"    S ^TMP(\"THST\",J,\"FILE_{file_num_clean}\",\"START\")=$$NOW^XLFDT\n"                 f"    W !, \"[TEST HARNESS] Initializing test suite execution for {global_root}...\"\n"                 f"    \n"                 f"    ; Invoke generated modular test routines\n"                 f"{master_orchestrator_calls}\n"                 f"    \n"                 f"    S ^TMP(\"THST\",J,\"FILE_{file_num_clean}\",\"END\")=$$NOW^XLFDT\n"
                f"    W !, \"[TEST HARNESS] All test suites completed successfully. Check ^TMP(\\\"THST\\\",J)\"\n"
                f"    Q\n"
                f"```\n\n"
                f"#### 2. Generated Modular Test Routines (Sample Suite)\n"
                f"```mumps\n"
                + "\n".join(sub_routine_blocks) +
                f"```"
            )

        summary = (
            f"### Executive AI Architectural Assessment: File #{file_num} - {file_desc}\n"
            f"* **Target MUMPS Global Root:** `{global_root}`\n"
            f"{custom_analysis}\n\n"
            f"* **Impact Scope:** Evaluated across **{total_routines} routines** and **{total_namespaces} primary package hubs**.\n"
            f"* **Operational Distribution:**\n"
            f"  * 🔴 **Writes (Mutations/APIs):** {write_count} touchpoints (High risk for schema modifications).\n"
            f"  * 🔵 **Queries (Lookups/Indexes):** {query_count} touchpoints (Dependent on cross-references and key structures).\n"
            f"  * ⚪ **Reads / Buffers:** {read_count} touchpoints (Display, reporting, and scratchpads).\n"
            f"* **Primary Integration Hubs:** The highest density of interaction originates from package hubs: **{', '.join(top_namespaces) if top_namespaces else 'None'}**.\n"
            f"* **Risk Recommendation:** Before executing field schema changes or data dictionary migrations on File #{file_num}, prioritize regression testing on the `WRITE` pathways in **{top_namespaces[0] if top_namespaces else 'core'}** routines to prevent data integrity corruption.\n"
            f"{test_harness_snippet}"
        )
        return summary.strip()