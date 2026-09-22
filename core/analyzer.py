import sqlite3

class RoutineAnalyzer:
    def __init__(self, db_path="data/vista_routines.db"):
        self.db_path = db_path

    def run_quality_control_audit(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        print("\n" + "="*50)
        print("      VISTA ROUTINE DATASET - AI HEALTH AUDIT")
        print("="*50)

        cursor.execute("SELECT COUNT(DISTINCT routine_name) FROM raw_routines;")
        total_routines = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM raw_routines;")
        total_nodes = cursor.fetchone()[0]
        print(f"• Total Routines Tracked : {total_routines:,}")
        print(f"• Total Database Nodes   : {total_nodes:,}")

        print("\n--- TOP NAMESPACES BY ROUTINE COUNT ---")
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN routine_name LIKE 'DI%' THEN 'DI (FileMan)'
                    WHEN routine_name LIKE 'X%' THEN 'X (Kernel)'
                    WHEN routine_name LIKE 'OR%' THEN 'OR (CPRS)'
                    WHEN routine_name LIKE 'LR%' THEN 'LR (Lab)'
                    WHEN routine_name LIKE 'PS%' THEN 'PS (Pharmacy)'
                    WHEN routine_name LIKE 'RA%' THEN 'RA (Radiology)'
                    ELSE 'OTHER'
                END as namespace_group,
                COUNT(DISTINCT routine_name) as r_count
            FROM raw_routines
            GROUP BY namespace_group
            ORDER BY r_count DESC;
        """)
        ns_results = cursor.fetchall()
        for row in ns_results:
            print(f"  {row[0]:<20} : {row[1]:,} routines")

        print("\n--- DATA INTEGRITY RISK CHECK (Direct Global Writes) ---")
        cursor.execute("""
            SELECT DISTINCT routine_name, node_value 
            FROM raw_routines 
            WHERE subscript LIKE '0,%' 
              AND (node_value LIKE '%^DPT(%' OR node_value LIKE '%^DIC(%' OR node_value LIKE '%^PS(%')
              AND (node_value LIKE '%S ^%' OR node_value LIKE '%SET ^%')
            LIMIT 5;
        """)
        risks = cursor.fetchall()
        if risks:
            print("  [!] Flagged routines executing direct global writes (bypassing FileMan APIs):")
            for r in risks:
                print(f"      • Routine [{r[0]}]: {r[1].strip()}")
        else:
            print("  [✓] No immediate direct global write infractions caught in sample sweep.")

        print("\n--- COMPLEXITY CHECK (Largest Monolithic Routines) ---")
        cursor.execute("""
            SELECT routine_name, MAX(CAST(subscript AS INTEGER)) as max_line
            FROM raw_routines
            WHERE subscript LIKE '0,%'
            GROUP BY routine_name
            ORDER BY max_line DESC
            LIMIT 5;
        """)
        monoliths = cursor.fetchall()
        for m in monoliths:
            print(f"  • {m[0]} : ~{m[1]} lines of code")

        print("="*50)
        conn.close()
