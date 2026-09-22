import os
from core.extract_routines import RoutineExtractor
from core.analyzer import RoutineAnalyzer

if __name__ == "__main__":
    routine_file_path = "data/ROUTINE.txt"
    db_path = "data/vista_routines.db"
    
    extractor = RoutineExtractor(db_path=db_path)
    analyzer = RoutineAnalyzer(db_path=db_path)
    
    # Step 1: Ingest the file into SQLite
    if os.path.exists(routine_file_path):
        print("--- STEP 1: DATABASE EXTRACTION ---")
        success = extractor.extract_to_db(routine_file_path)
        
        if success:
            # Step 2: Run the AI Quality Control Health Audit
            print("\n--- STEP 2: RUNNING AI HEALTH & QC AUDIT ---")
            analyzer.run_quality_control_audit()
    else:
        print(f"File not found at '{routine_file_path}'. Please ensure ROUTINE.txt is in the data/ folder.")
