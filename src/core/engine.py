"""
AntivirusAI Scan Engine - מנוע הסריקה הגרעיני (ללא GUI)
"""

import os
import hashlib
import sqlite3
import threading
import queue
import time
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional, List
import argparse
import lief
import numpy as np
import lightgbm as lgb
import ember
# ==========================================
# Default Configuration (used when run standalone)
# ==========================================
DEFAULT_DB_PATH = r"C:\Users\omri9\Desktop\School\Final Project\data\hashes\malware_hashes.db"
DEFAULT_MODEL_PATH = r"C:\Users\omri9\Desktop\School\Final Project\final\AntivirusAI_V6_Balanced.txt"
DEFAULT_ENGINE_VERSION = "V6_Balanced"

# ==========================================
# Warning Suppression & Compatibility Patches
# ==========================================
lief.logging.disable()

if hasattr(lief, 'PE'):
    if not hasattr(lief.PE, 'SECTION_CHARACTERISTICS') and hasattr(lief.PE, 'Section'):
        lief.PE.SECTION_CHARACTERISTICS = lief.PE.Section.CHARACTERISTICS

for missing_attr in ['bad_format', 'bad_file', 'pe_error', 'parser_error',
                     'read_out_of_bound', 'not_found']:
    if not hasattr(lief, missing_attr):
        setattr(lief, missing_attr, type(missing_attr, (Exception,), {}))

if not hasattr(np, 'int'):    np.int = int
if not hasattr(np, 'bool'):   np.bool = bool
if not hasattr(np, 'float'):  np.float = float
if not hasattr(np, 'object'): np.object = object


# ==========================================
# Windows API - WinVerifyTrust
# ==========================================
class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_byte * 8)]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p)]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p)]


def is_trusted_signature(filepath: str) -> bool:
    """בודק חתימה דיגיטלית מול מערכת ההפעלה."""
    try:
        wintrust = ctypes.windll.wintrust
        wintrust.WinVerifyTrust.argtypes = [wintypes.HWND,
                                            ctypes.POINTER(_GUID),
                                            ctypes.POINTER(_WINTRUST_DATA)]
        wintrust.WinVerifyTrust.restype = wintypes.LONG

        action_id = _GUID(0x00AAC56B, 0xCD44, 0x11d0,
                          (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

        file_info = _WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = filepath
        file_info.hFile = None
        file_info.pgKnownSubject = None

        wintrust_data = _WINTRUST_DATA()
        wintrust_data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
        wintrust_data.dwUIChoice = 2
        wintrust_data.fdwRevocationChecks = 0
        wintrust_data.dwUnionChoice = 1
        wintrust_data.pFile = ctypes.pointer(file_info)
        wintrust_data.dwStateAction = 1
        wintrust_data.dwProvFlags = 0x00000010

        result = wintrust.WinVerifyTrust(None, ctypes.pointer(action_id),
                                         ctypes.pointer(wintrust_data))

        wintrust_data.dwStateAction = 2
        wintrust.WinVerifyTrust(None, ctypes.pointer(action_id),
                                ctypes.pointer(wintrust_data))

        return result == 0
    except Exception:
        return False


# ==========================================
# Event Data Classes
# ==========================================
class ScanStatus(Enum):
    IDLE = "idle"
    LOADING = "loading"
    SCANNING = "scanning"
    PAUSED = "paused"
    STOPPING = "stopping"
    FINISHED = "finished"
    ERROR = "error"


@dataclass
class ThreatInfo:
    filepath: str
    filename: str
    file_hash: str
    threat_score: float
    classification: str   # "MALWARE" / "SUSPICIOUS"
    source: str           # "Local Blacklist" / "LightGBM AI"
    diagnosis: str


@dataclass
class ScanProgress:
    current_file: str
    scanned: int
    cached: int
    db_hits: int
    ai_hits: int
    errors: int


@dataclass
class ScanSummary:
    scanned: int
    cached: int
    db_hits: int
    ai_hits: int
    errors: int
    duration_seconds: float


# ==========================================
# Scan Engine
# ==========================================
class ScanEngine:
    SCANNABLE_EXTENSIONS = ('.exe', '.dll', '.sys')
    SKIP_FILENAMES = {'hiberfil.sys', 'pagefile.sys', 'swapfile.sys',
                      'dumpstack.log', 'dumpstack.log.tmp'}

    def __init__(self, db_path: str, model_path: str,
                 engine_version: str = "V6_Balanced"):
        self.db_path = db_path
        self.model_path = model_path
        self.engine_version = engine_version

        # Callbacks - ה-GUI/CLI מגדיר אותם אחרי בנייה
        self.on_progress: Optional[Callable[[ScanProgress], None]] = None
        self.on_threat: Optional[Callable[[ThreatInfo], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None
        self.on_status_change: Optional[Callable[[ScanStatus], None]] = None
        self.on_finished: Optional[Callable[[ScanSummary], None]] = None

        # State
        self._status = ScanStatus.IDLE
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # not paused initially

        self._scan_thread: Optional[threading.Thread] = None
        self._db_thread: Optional[threading.Thread] = None
        self._db_write_queue: queue.Queue = queue.Queue()

        self._lgbm_model = None
        self._extractor = None
        self._read_conn: Optional[sqlite3.Connection] = None
        self._read_cursor: Optional[sqlite3.Cursor] = None
        self._excluded_dirs: List[str] = []
        self._stats = self._fresh_stats()

    @staticmethod
    def _fresh_stats():
        return {"Scanned": 0, "Cached": 0, "DB_Hits": 0, "AI_Hits": 0, "Errors": 0}

    # ----- Public Control API -----
    @property
    def status(self) -> ScanStatus:
        return self._status

    def is_running(self) -> bool:
        return self._status in (ScanStatus.SCANNING, ScanStatus.PAUSED,
                                ScanStatus.LOADING)

    def start(self, target_dir: str) -> bool:
        if self.is_running():
            return False
        self._stop_event.clear()
        self._pause_event.set()
        self._stats = self._fresh_stats()
        self._scan_thread = threading.Thread(
            target=self._scan_worker, args=(target_dir,), daemon=True
        )
        self._scan_thread.start()
        return True

    def stop(self):
        if not self.is_running():
            return
        self._set_status(ScanStatus.STOPPING)
        self._stop_event.set()
        self._pause_event.set()  # unblock pause so loop can exit

    def pause(self):
        if self._status != ScanStatus.SCANNING:
            return
        self._pause_event.clear()
        self._set_status(ScanStatus.PAUSED)

    def resume(self):
        if self._status != ScanStatus.PAUSED:
            return
        self._pause_event.set()
        self._set_status(ScanStatus.SCANNING)

    def wait(self, timeout=None):
        if self._scan_thread:
            self._scan_thread.join(timeout)

    # ----- Event Emitters (safe wrappers) -----
    def _set_status(self, status: ScanStatus):
        self._status = status
        self._safe_call(self.on_status_change, status)

    def _emit_threat(self, threat: ThreatInfo):
        self._safe_call(self.on_threat, threat)

    def _emit_progress(self, current_file: str):
        progress = ScanProgress(
            current_file=current_file,
            scanned=self._stats["Scanned"],
            cached=self._stats["Cached"],
            db_hits=self._stats["DB_Hits"],
            ai_hits=self._stats["AI_Hits"],
            errors=self._stats["Errors"],
        )
        self._safe_call(self.on_progress, progress)

    def _emit_error(self, message: str):
        self._safe_call(self.on_error, message)

    @staticmethod
    def _safe_call(cb, *args):
        if cb is None:
            return
        try:
            cb(*args)
        except Exception:
            pass

    # ----- Helpers -----
    def _calculate_sha256(self, filepath: str) -> Optional[str]:
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for block in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self._log_error_file(f"[HASH ERROR] {filepath} - {e}")
            return None

    def _log_error_file(self, message: str):
        try:
            with open("scan_errors.log", "a", encoding="utf-8") as err_log:
                err_log.write(message + "\n")
        except Exception:
            pass

    # ----- DB Writer Thread -----
    def _db_writer_thread(self):
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=60)
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

            BATCH_SIZE = 50
            counter = 0
            last_commit = time.time()

            while True:
                try:
                    task = self._db_write_queue.get(timeout=1.0)
                except queue.Empty:
                    if counter > 0 and (time.time() - last_commit) > 2.0:
                        conn.commit()
                        counter = 0
                        last_commit = time.time()
                    continue

                if task is None:
                    conn.commit()
                    break

                action, data = task
                try:
                    if action == "log_event":
                        cursor.execute("""
                            INSERT INTO ScanEvent 
                            (filename, file_hash, threat_score, classification,
                             detection_source, ai_diagnosis) 
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, data)
                    elif action == "update_cache":
                        cursor.execute("""
                            INSERT OR REPLACE INTO scan_cache
                            (sha256, engine_version, result) 
                            VALUES (?, ?, ?)
                        """, data)

                    counter += 1
                    if counter >= BATCH_SIZE:
                        conn.commit()
                        counter = 0
                        last_commit = time.time()
                except Exception as e:
                    self._emit_error(f"[DB Write Error]: {e}")
                self._db_write_queue.task_done()

        except Exception as e:
            self._emit_error(f"[DB Thread Fatal Error]: {e}")
        finally:
            if conn is not None:
                try:
                    conn.commit()
                    conn.close()
                except Exception:
                    pass

    def _log_incident_async(self, filepath, file_hash, threat_score,
                            status, source, diagnosis):
        filename = os.path.basename(filepath)
        self._db_write_queue.put(
            ("log_event",
             (filename, file_hash, threat_score, status, source, diagnosis))
        )

    def _update_cache_async(self, file_hash, status):
        self._db_write_queue.put(
            ("update_cache", (file_hash, self.engine_version, status))
        )

    # ----- Main Worker -----
    def _scan_worker(self, target_dir: str):
        start_time = time.time()
        try:
            self._set_status(ScanStatus.LOADING)

            # 1. Boot DB thread
            self._db_thread = threading.Thread(
                target=self._db_writer_thread, daemon=True
            )
            self._db_thread.start()

            # 2. Load AI
            self._lgbm_model = lgb.Booster(model_file=self.model_path)
            self._extractor = ember.PEFeatureExtractor()

            # 3. Read connection + whitelist
            self._read_conn = sqlite3.connect(self.db_path, timeout=30,
                                              isolation_level=None)
            self._read_conn.execute("PRAGMA busy_timeout = 5000;")
            self._read_cursor = self._read_conn.cursor()
            self._read_cursor.execute("""
                CREATE TABLE IF NOT EXISTS whitelist_paths
                (path TEXT PRIMARY KEY, added_date TIMESTAMP, reason TEXT)
            """)
            self._read_cursor.execute("SELECT path FROM whitelist_paths")
            self._excluded_dirs = [row[0] for row in self._read_cursor.fetchall()]

            if os.path.exists("scan_errors.log"):
                try: os.remove("scan_errors.log")
                except Exception: pass

            self._set_status(ScanStatus.SCANNING)

            # 4. Walk
            for root, dirs, files in os.walk(target_dir):
                if self._stop_event.is_set():
                    break
                if any(root.startswith(ex) for ex in self._excluded_dirs):
                    continue
                for filename in files:
                    if self._stop_event.is_set():
                        break
                    self._pause_event.wait()
                    if self._stop_event.is_set():
                        break
                    self._scan_one_file(root, filename)

            # 5. Finalize
            try: self._read_conn.close()
            except Exception: pass

            if self._status != ScanStatus.STOPPING:
                self._set_status(ScanStatus.STOPPING)
            self._db_write_queue.put(None)
            if self._db_thread:
                self._db_thread.join()

            duration = time.time() - start_time
            summary = ScanSummary(
                scanned=self._stats["Scanned"],
                cached=self._stats["Cached"],
                db_hits=self._stats["DB_Hits"],
                ai_hits=self._stats["AI_Hits"],
                errors=self._stats["Errors"],
                duration_seconds=duration,
            )
            self._set_status(ScanStatus.FINISHED)
            self._safe_call(self.on_finished, summary)

        except Exception as e:
            self._emit_error(f"[Engine Fatal Error]: {e}")
            self._set_status(ScanStatus.ERROR)
            try:
                self._db_write_queue.put(None)
                if self._db_thread:
                    self._db_thread.join(timeout=10)
            except Exception:
                pass

    def _scan_one_file(self, root: str, filename: str):
        lower_name = filename.lower()
        if lower_name in self.SKIP_FILENAMES:
            return
        if not lower_name.endswith(self.SCANNABLE_EXTENSIONS):
            return

        filepath = os.path.join(root, filename)

        try:
            if os.path.getsize(filepath) == 0:
                return
        except Exception:
            return

        self._stats["Scanned"] += 1
        self._emit_progress(filepath)

        file_hash = self._calculate_sha256(filepath)
        if not file_hash:
            self._stats["Errors"] += 1
            return

        # Layer 1: cache
        try:
            self._read_cursor.execute(
                "SELECT result FROM scan_cache WHERE sha256 = ? AND engine_version = ?",
                (file_hash, self.engine_version)
            )
            if self._read_cursor.fetchone():
                self._stats["Cached"] += 1
                return

            # Layer 2: blacklist
            self._read_cursor.execute(
                "SELECT sha256 FROM blacklist WHERE sha256 = ?", (file_hash,)
            )
            blacklisted = self._read_cursor.fetchone()
        except Exception as e:
            self._emit_error(f"[DB Read Error]: {e}")
            self._stats["Errors"] += 1
            return

        if blacklisted:
            self._stats["DB_Hits"] += 1
            threat = ThreatInfo(
                filepath=filepath, filename=filename, file_hash=file_hash,
                threat_score=100.0, classification="MALWARE",
                source="Local Blacklist",
                diagnosis="Identified via static signature database.",
            )
            self._emit_threat(threat)
            self._log_incident_async(filepath, file_hash, 100.0, "MALWARE",
                                     "Local Blacklist",
                                     "Identified via static signature database.")
            self._update_cache_async(file_hash, "malware")
            return

        # Layer 3: AI
        try:
            is_os_trusted = is_trusted_signature(filepath)

            with open(filepath, "rb") as f:
                file_data = f.read()

            features = np.array(self._extractor.feature_vector(file_data),
                                dtype=np.float32)
            raw_prob = self._lgbm_model.predict([features])[0]
            final_score = raw_prob * 100

            if is_os_trusted:
                final_score -= 60.0

            lower_path = filepath.lower()
            if "c:\\windows\\" in lower_path or "c:\\program files" in lower_path:
                final_score -= 20.0

            final_score = max(0.0, final_score)

            if final_score >= 95.0:
                self._stats["AI_Hits"] += 1
                threat = ThreatInfo(
                    filepath=filepath, filename=filename, file_hash=file_hash,
                    threat_score=final_score, classification="MALWARE",
                    source="LightGBM AI",
                    diagnosis="High probability of Zero-Day threat based on heuristics.",
                )
                self._emit_threat(threat)
                self._log_incident_async(filepath, file_hash, final_score, "MALWARE",
                                         "LightGBM AI", threat.diagnosis)
                self._update_cache_async(file_hash, "malware")

            elif final_score >= 70.0:
                self._stats["AI_Hits"] += 1
                threat = ThreatInfo(
                    filepath=filepath, filename=filename, file_hash=file_hash,
                    threat_score=final_score, classification="SUSPICIOUS",
                    source="LightGBM AI",
                    diagnosis="File exhibits unusual attributes. Review recommended.",
                )
                self._emit_threat(threat)
                self._log_incident_async(filepath, file_hash, final_score, "SUSPICIOUS",
                                         "LightGBM AI", threat.diagnosis)
                self._update_cache_async(file_hash, "suspicious")
            else:
                self._update_cache_async(file_hash, "safe")

        except Exception as e:
            self._stats["Errors"] += 1
            self._log_error_file(f"[AI ERROR] - {filepath} - {e}")

            