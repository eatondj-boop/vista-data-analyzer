import re
from core.database import get_db_connection, get_active_table_name

def extract_routine_dependencies(routine_name):
    conn = get_db_connection()
    cursor = conn.cursor()
    table = get_active_table_name()
    cursor.execute(f"SELECT node_value FROM {table} WHERE routine_name = ?", (routine_name,))
    rows = cursor.fetchall()
    conn.close()
    called_routines = set()
    call_pattern = re.compile(r'(?:DO|D|JOB|J|\$\$)\s+([A-Za-z0-9_%]+)(?:\^([A-Za-z0-9_%]+))?', re.IGNORECASE)
    for row in rows:
        code = row['node_value']
        matches = call_pattern.findall(code)
        for match in matches:
            target = match[1] if match[1] else match[0]
            if target and target.upper() != routine_name.upper():
                called_routines.add(target.upper())
    return list(called_routines)
