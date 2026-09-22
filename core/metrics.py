from core.database import get_db_connection, get_active_table_name

def calculate_routine_metrics(routine_name):
    conn = get_db_connection()
    cursor = conn.cursor()
    table = get_active_table_name()
    
    # Clean and normalize the routine name
    clean_name = routine_name.strip()
    if clean_name.startswith("^"):
        clean_name = clean_name[1:]
    
    # Try exact match first, then case-insensitive match
    cursor.execute(f"""
        SELECT line_number, node_type, node_value 
        FROM {table} 
        WHERE routine_name = ? OR UPPER(routine_name) = UPPER(?) 
        ORDER BY CAST(line_number AS INTEGER)
    """, (clean_name, clean_name))
    
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        return None
        
    total_lines = len(rows)
    commands_count = 0
    branching_statements = 0
    control_keywords = ('I ', 'IF ', 'F ', 'FOR ', 'D ', 'DO ', 'Q ', 'QUIT ')
    
    formatted_rows = []
    for row in rows:
        code = row['node_value']
        if any(code.strip().startswith(kw) for kw in control_keywords):
            branching_statements += 1
        commands_count += len(code.split())
        formatted_rows.append({
            "line_number": row['line_number'],
            "node_type": row['node_type'],
            "node_value": code
        })

    return {
        "routine_name": clean_name,
        "total_lines": total_lines,
        "estimated_commands": commands_count,
        "branching_nodes": branching_statements,
        "complexity_score": round((branching_statements * 1.5) + (total_lines * 0.1), 2),
        "rows": formatted_rows
    }