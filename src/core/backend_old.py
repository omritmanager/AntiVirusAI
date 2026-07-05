import os
import hashlib
import sqlite3
import lief
import numpy as np
import lightgbm as lgb
import ember
import time
import threading
import queue
import ctypes
from ctypes import wintypes

# ==========================================
# Windows API Trust Verification (WinVerifyTrust)
# ==========================================
class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_byte * 8)]

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p)]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p)]

def is_trusted_signature(filepath):
    """
    ×©×•××œ ××ª ×ž×¢×¨×›×ª ×”×”×¤×¢×œ×” ×‘××•×¤×Ÿ ×™×©×™×¨ ×”×× ×”×§×•×‘×¥ ×—×ª×•× ×“×™×’×™×˜×œ×™×ª ×•××ž×™×Ÿ.
    """
    try:
        wintrust = ctypes.windll.wintrust
        wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)]
        wintrust.WinVerifyTrust.restype = wintypes.LONG

        action_id = GUID(0x00AAC56B, 0xCD44, 0x11d0, (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = filepath
        file_info.hFile = None
        file_info.pgKnownSubject = None

        wintrust_data = WINTRUST_DATA()
        wintrust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        wintrust_data.dwUIChoice = 2        
        wintrust_data.fdwRevocationChecks = 0 
        wintrust_data.dwUnionChoice = 1     
        wintrust_data.pFile = ctypes.pointer(file_info)
        wintrust_data.dwStateAction = 1     
        wintrust_data.dwProvFlags = 0x00000010 

        result = wintrust.WinVerifyTrust(None, ctypes.pointer(action_id), ctypes.pointer(wintrust_data))

        wintrust_data.dwStateAction = 2     
        wintrust.WinVerifyTrust(None, ctypes.pointer(action_id), ctypes.pointer(wintrust_data))

        return result == 0 
    except Exception:
        return False

# --- Warning Suppression ---
lief.logging.disable()

# --- Monkey Patching (×ª×•×§×Ÿ ×›×“×™ ×œ×ª×ž×•×š ×‘×’×¨×¡××•×ª LIEF ×—×“×©×•×ª) ---
if hasattr(lief, 'PE'):
    if not hasattr(lief.PE, 'SECTION_CHARACTERISTICS') and hasattr(lief.PE, 'Section'):
        lief.PE.SECTION_CHARACTERISTICS = lief.PE.Section.CHARACTERISTICS

for missing_attr in ['bad_format', 'bad_file', 'pe_error', 'parser_error', 'read_out_of_bound', 'not_found']:
    if not hasattr(lief, missing_attr):
        setattr(lief, missing_attr, type(missing_attr, (Exception,), {}))

if not hasattr(np, 'int'): np.int = int
if not hasattr(np, 'bool'): np.bool = bool
if not hasattr(np, 'float'): np.float = float
if not hasattr(np, 'object'): np.object = object

# ==========================================
# Core System Settings
# ==========================================
DB_PATH = r"C:\Users\omri9\Desktop\School\Final Project\data\hashes\malware_hashes.db"
MODEL_PATH = r"C:\Users\omri9\Desktop\School\Final Project\final\AntivirusAI_V6_Balanced.txt"
ENGINE_VERSION = "V6_Balanced"
TARGET_DIR = r"C:\\"

db_write_queue = queue.Queue()
# ==========================================

def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        with open("scan_errors.log", "a", encoding="utf-8") as err_log:
            err_log.write(f"[HASH ERROR] - Path: {filepath} - Error: {str(e)}\n")
        return None

def db_writer_thread():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=60)
        conn.execute("PRAGMA journal_mode=WAL;")
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_cache (
                sha256 TEXT, engine_version TEXT, result TEXT,
                PRIMARY KEY (sha256, engine_version)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ScanEvent (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT, file_hash TEXT, threat_score REAL,
                classification TEXT, detection_source TEXT, ai_diagnosis TEXT,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

        BATCH_SIZE = 1 
        counter = 0

        while True:
            task = db_write_queue.get()
            
            if task is None:
                conn.commit()
                break

            action, data = task

            try:
                if action == "log_event":
                    cursor.execute("""
                        INSERT INTO ScanEvent 
                        (filename, file_hash, threat_score, classification, detection_source, ai_diagnosis) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, data)
                elif action == "update_cache":
                    cursor.execute("""
                        INSERT OR REPLACE INTO scan_cache (sha256, engine_version, result) 
                        VALUES (?, ?, ?)
                    """, data)
                
                counter += 1
                if counter % BATCH_SIZE == 0:
                    conn.commit()
            
            except Exception as e:
                print(f"\n   âŒ [DB Write Error]: {e} | Data: {data}")

            db_write_queue.task_done()

    except Exception as e:
        print(f"\n   âŒ [DB Thread Fatal Error]: {e}")
    finally:
        if 'conn' in locals():
            conn.commit()
            conn.close()

def log_incident_async(filepath, file_hash, threat_score, status, source, diagnosis):
    filename = os.path.basename(filepath)
    db_write_queue.put(("log_event", (filename, file_hash, threat_score, status, source, diagnosis)))

def update_cache_async(file_hash, status):
    db_write_queue.put(("update_cache", (file_hash, ENGINE_VERSION, status)))

def master_scanner():
    print("======================================================")
    print("ðŸ›¡ï¸  AntivirusAI - Enterprise Grade Scanner (Async & WAL)")
    print("======================================================")
    
    # ×”×¤×¢×œ×ª ×ª×”×œ×™×›×•×Ÿ ×ž×¡×“ ×”× ×ª×•× ×™×
    print("ðŸ”„ 1. Booting Async Database Thread...")
    db_thread = threading.Thread(target=db_writer_thread, daemon=True)
    db_thread.start()
    
    print("ðŸ§  2. Booting Local AI Engine...")
    lgbm_model = lgb.Booster(model_file=MODEL_PATH)
    extractor = ember.PEFeatureExtractor()
    
    # ×—×™×‘×•×¨ ×§×¨×™××” (Read-Only Logic)
    print("ðŸ—„ï¸  3. Connecting Read-Cursor to Local Database...")
    read_conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    read_conn.execute("PRAGMA busy_timeout = 5000;") 
    read_cursor = read_conn.cursor()
    
    read_cursor.execute("CREATE TABLE IF NOT EXISTS whitelist_paths (path TEXT PRIMARY KEY, added_date TIMESTAMP, reason TEXT)")
    read_conn.commit()
    read_cursor.execute("SELECT path FROM whitelist_paths")
    EXCLUDED_DIRS = [row[0] for row in read_cursor.fetchall()]
    
    scan_targets = [TARGET_DIR]
    print(f"ðŸ” 4. Initiating Scan on: {scan_targets}")
    print("-" * 54)
    
    stats = {"Scanned": 0, "Cached": 0, "DB_Hits": 0, "AI_Hits": 0, "Errors": 0}

    # ×ž×—×™×§×ª ×§×•×‘×¥ ×”×œ×•×’ ×”×™×©×Ÿ ×œ×¤× ×™ ×ª×—×™×œ×ª ×¡×¨×™×§×” ×—×“×©×”
    if os.path.exists("scan_errors.log"):
        try: os.remove("scan_errors.log")
        except: pass

    try:
        for target in scan_targets:
            for root, dirs, files in os.walk(target):
                if any(root.startswith(ex_dir) for ex_dir in EXCLUDED_DIRS):
                    continue 
                
                for filename in files:
                    if filename.lower() in ['hiberfil.sys', 'pagefile.sys', 'swapfile.sys', 'dumpstack.log', 'dumpstack.log.tmp']:
                        continue

                    if not filename.lower().endswith(('.exe', '.dll', '.sys')):
                        continue
                    
                    filepath = os.path.join(root, filename)

                    # --- ×—×¡×™×ž×ª ×©×’×™××ª Errno 22: ×“×™×œ×•×’ ×¢×œ ×§×‘×¦×™ 0 ×‘×ª×™× ×•×™×¨×˜×•××œ×™×™× ---
                    try:
                        if os.path.getsize(filepath) == 0:
                            continue
                    except Exception:
                        continue

                    display_path = (filepath[:75] + '..') if len(filepath) > 75 else filepath
                    print(f"   ðŸ”Ž Scanning: {display_path:<80}", end="\r")
                    
                    stats["Scanned"] += 1
                    file_hash = calculate_sha256(filepath)
                    if not file_hash:
                        stats["Errors"] += 1
                        continue

                    read_cursor.execute("SELECT result FROM scan_cache WHERE sha256 = ? AND engine_version = ?", (file_hash, ENGINE_VERSION))
                    if read_cursor.fetchone():
                        stats["Cached"] += 1
                        continue

                    read_cursor.execute("SELECT sha256 FROM blacklist WHERE sha256 = ?", (file_hash,))
                    if read_cursor.fetchone():
                        print(f"\n   ðŸ›‘ [LOCAL DB] MALWARE BLOCKED: {filename:<40}")
                        stats["DB_Hits"] += 1
                        log_incident_async(filepath, file_hash, 100.0, "MALWARE", "Local Blacklist", "Identified via static signature database.")
                        update_cache_async(file_hash, "malware")
                        continue

                    # --- Layer 3: AI Inference Engine ---
                    try:
                        is_os_trusted = is_trusted_signature(filepath)
                        
                        with open(filepath, "rb") as f:
                            file_data = f.read()
                        
                        # ×—×™×œ×•×¥ ×”×ž××¤×™×™× ×™× (×¢×›×©×™×• Ember ×œ× ×™×§×¨×•×¡ ×¤×”!)
                        features = np.array(extractor.feature_vector(file_data), dtype=np.float32)
                        raw_prob = lgbm_model.predict([features])[0]
                        final_score = raw_prob * 100
                        
                        # ×œ×•×’×™×§×” ×¢×¡×§×™×ª (Context Aware)
                        if is_os_trusted:
                            final_score -= 60.0  
                            
                        lower_path = filepath.lower()
                        if "c:\\windows\\" in lower_path or "c:\\program files" in lower_path:
                            final_score -= 20.0
                            
                        final_score = max(0.0, final_score)

                        # ×§×‘×œ×ª ×”×—×œ×˜×•×ª
                        if final_score >= 95.0:
                            print(f"\n   ðŸ§  [AI ENGINE] MALWARE IDENTIFIED: {filename:<40} ({final_score:.2f}%)")
                            stats["AI_Hits"] += 1
                            log_incident_async(filepath, file_hash, final_score, "MALWARE", "LightGBM AI", "High probability of Zero-Day threat based on heuristics.")
                            update_cache_async(file_hash, "malware")
                            
                        elif final_score >= 70.0:
                            stats["AI_Hits"] += 1
                            log_incident_async(filepath, file_hash, final_score, "SUSPICIOUS", "LightGBM AI", "File exhibits unusual attributes. Review recommended.")
                            update_cache_async(file_hash, "suspicious")
                        else:
                            update_cache_async(file_hash, "safe")

                    except Exception as e:
                        stats["Errors"] += 1
                        with open("scan_errors.log", "a", encoding="utf-8") as err_log:
                            err_log.write(f"[AI ERROR] - File: {filename} - Path: {filepath} - Error: {str(e)}\n")

    except KeyboardInterrupt:
        print("\n\nðŸ›‘ Scan interrupted by user. Saving all pending data to database...")

    finally:
        read_conn.close()
        
        print("\nâ³ Finalizing database writes (Please wait)...")
        db_write_queue.put(None) 
        db_thread.join()         

        print(f"\n{'='*54}")
        print("ðŸ“‹ ENTERPRISE SCAN SUMMARY:")
        print(f"   ðŸ“‚ Total Processed:      {stats['Scanned']}")
        print(f"   âš¡ Skipped (Cached):     {stats['Cached']}")
        print(f"   ðŸ›‘ Caught (Local DB):    {stats['DB_Hits']}")
        print(f"   ðŸ§  Caught (AI Engine):   {stats['AI_Hits']}")
        print(f"   âŒ Read/Parse Errors:    {stats['Errors']}")
        print("======================================================")

if __name__ == "__main__":
    master_scanner()
