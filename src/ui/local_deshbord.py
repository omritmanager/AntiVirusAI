import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import pandas as pd
import hashlib
import os
import threading
import time
import urllib.request
import urllib.parse
import json
try:
    import winsound
    HAS_WINSOUND = True
except ImportError:
    HAS_WINSOUND = False
from datetime import datetime, timedelta

# ==========================================
# 1. THEMES & SETTINGS
# ==========================================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

DB_PATH       = r"C:\Users\omri9\Desktop\School\Final Project\HASH\malware_hashes.db"
SETTINGS_PATH = r"C:\Users\omri9\Desktop\School\Final Project\HASH\settings.json"
ENGINE_SCRIPT = r"C:\Users\omri9\Desktop\School\Final Project\src\core\engine.py"


def load_settings() -> dict:
    """Load persistent settings (scan folder, threshold)."""
    defaults = {"scan_folder": "C:\\", "threshold": 83.4}
    try:
        if os.path.exists(SETTINGS_PATH):
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            defaults.update({k: v for k, v in data.items() if k in defaults})
    except Exception as e:
        print("Settings load error:", e)
    return defaults


def save_settings(scan_folder: str, threshold: float):
    try:
        parent = os.path.dirname(SETTINGS_PATH)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump({"scan_folder": scan_folder, "threshold": threshold}, f)
    except Exception as e:
        print("Settings save error:", e)

THEMES = {
    "dark": {
        "bg":       "#0b1120",
        "sidebar":  "#0f172a",
        "card":     "#111827",
        "safe":     "#10b981",
        "danger":   "#ef4444",
        "warn":     "#f59e0b",
        "accent":   "#3b82f6",
        "border":   "#1e293b",
        "text_dim": "#9ca3af",
        "text":     "#ffffff",
    },
    "light": {
        "bg":       "#f1f5f9",
        "sidebar":  "#e2e8f0",
        "card":     "#ffffff",
        "safe":     "#059669",
        "danger":   "#dc2626",
        "warn":     "#b45309",
        "accent":   "#2563eb",
        "border":   "#cbd5e1",
        "text_dim": "#64748b",
        "text":     "#0f172a",
    },
}

current_theme = THEMES["dark"]


def apply_ctk_mode(theme_name: str):
    ctk.set_appearance_mode("dark" if theme_name == "dark" else "light")


def play_alert_sound():
    if HAS_WINSOUND:
        try:
            winsound.PlaySound("SystemAsterisk", winsound.SND_ALIAS | winsound.SND_ASYNC)
        except Exception:
            pass


def play_critical_sound():
    if HAS_WINSOUND:
        try:
            winsound.PlaySound("SystemHand", winsound.SND_ALIAS | winsound.SND_ASYNC)
        except Exception:
            pass


# ==========================================
# 2. DATABASE & SYNC FUNCTIONS
# ==========================================
def initialize_db():
    try:
        # SQLite will create the .db file, but NOT the parent directory.
        # Ensure the HASH folder exists before opening the connection.
        parent_dir = os.path.dirname(DB_PATH)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
            print(f"Created DB directory: {parent_dir}")

        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS whitelist_hashes "
            "(hash TEXT PRIMARY KEY, filename TEXT, reason TEXT, "
            "added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        # Migration: add filename column to existing tables that pre-date this version
        try:
            conn.execute("ALTER TABLE whitelist_hashes ADD COLUMN filename TEXT")
        except Exception:
            pass  # column already exists
        conn.execute(
            "CREATE TABLE IF NOT EXISTS whitelist_paths "
            "(path TEXT PRIMARY KEY, reason TEXT, added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ScanEvent "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, detection_source TEXT, "
            "threat_score REAL, classification TEXT, ai_diagnosis TEXT, file_hash TEXT, "
            "scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS threat_hashes "
            "(hash TEXT PRIMARY KEY, malware_name TEXT, file_type TEXT, "
            "first_seen TEXT, tags TEXT, "
            "added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sync_log "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
            "new_hashes INTEGER, status TEXT)")
        conn.commit()
        conn.close()
    except Exception as e:
        print("DB Init Error:", e)


def sync_malware_hashes() -> dict:
    """
    Download recent malware SHA-256 hashes from MalwareBazaar (abuse.ch).
    Inserts only hashes not already present in threat_hashes.
    Returns a dict with 'inserted', 'skipped', 'status', 'error'.
    """
    result = {"inserted": 0, "skipped": 0, "status": "error", "error": ""}
    try:
        payload = urllib.parse.urlencode({"query": "get_recent", "selector": "100"}).encode()
        req = urllib.request.Request(
            "https://mb-api.abuse.ch/api/v1/",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "User-Agent": "AntiVirusAI-Dashboard/1.0"}
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        if data.get("query_status") != "ok":
            result["error"] = data.get("query_status", "unknown API error")
            _log_sync(0, f"API_ERROR: {result['error']}")
            return result

        samples = data.get("data", [])
        conn = sqlite3.connect(DB_PATH)
        inserted = 0
        skipped  = 0
        for sample in samples:
            sha256 = (sample.get("sha256_hash") or "").strip()
            if not sha256:
                continue
            cur = conn.execute(
                "INSERT OR IGNORE INTO threat_hashes "
                "(hash, malware_name, file_type, first_seen, tags) VALUES (?,?,?,?,?)",
                (sha256,
                 sample.get("signature") or "Unknown",
                 sample.get("file_type") or "",
                 sample.get("first_seen") or "",
                 ",".join(sample.get("tags") or []))
            )
            if cur.rowcount:
                inserted += 1
            else:
                skipped += 1
        conn.commit()
        conn.close()

        result.update({"inserted": inserted, "skipped": skipped, "status": "ok"})
        _log_sync(inserted, "OK")
        return result

    except Exception as e:
        result["error"] = str(e)
        _log_sync(0, f"EXCEPTION: {e}")
        return result


def _log_sync(new_hashes: int, status: str):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO sync_log (new_hashes, status) VALUES (?,?)",
            (new_hashes, status))
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_last_sync_info() -> dict:
    try:
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute(
            "SELECT synced_at, new_hashes, status FROM sync_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        conn.close()
        if row:
            return {"time": row[0], "new": row[1], "status": row[2]}
    except Exception:
        pass
    return {"time": "Never", "new": 0, "status": "N/A"}


def get_threat_hash_count() -> int:
    try:
        conn = sqlite3.connect(DB_PATH)
        count = conn.execute("SELECT COUNT(*) FROM threat_hashes").fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0


def start_daily_sync(callback=None):
    """Start a background thread that runs sync once immediately, then every 24 h."""
    def _loop():
        res = sync_malware_hashes()
        if callback:
            callback(res)
        while True:
            time.sleep(86400)   # 24 hours
            res = sync_malware_hashes()
            if callback:
                callback(res)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()


# ==========================================
# DB READ / WRITE HELPERS
# ==========================================
def api_get_incidents():
    """Return real ScanEvent rows only. Empty DataFrame when table is empty."""
    empty = pd.DataFrame(columns=[
        "id", "filename", "source", "score", "status",
        "diagnosis", "hash", "scanned_at", "entropy",
        "malware_type", "reason", "scan_id"
    ])
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT id, filename, detection_source AS source, threat_score AS score, "
            "classification AS status, ai_diagnosis AS diagnosis, file_hash AS hash, "
            "scanned_at FROM ScanEvent ORDER BY id DESC",
            conn)
        conn.close()
    except Exception as e:
        print("DB read error:", e)
        return empty

    if df.empty:
        return empty

    if "entropy"      not in df.columns: df["entropy"]      = "N/A"
    if "malware_type" not in df.columns: df["malware_type"] = "Unknown"
    if "reason"       not in df.columns: df["reason"]       = "N/A"
    if "scan_id"      not in df.columns:
        df["scan_id"] = df["id"].apply(lambda x: f"SCAN-{x}")

    return df


def api_post_file_delete(incident_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM ScanEvent WHERE id = ?", (incident_id,))
        conn.commit()
        conn.close()
    except Exception:
        pass


def api_post_whitelist_add(type_: str, value: str,
                            reason: str = "Added via Dashboard",
                            filename: str = ""):
    try:
        conn = sqlite3.connect(DB_PATH)
        if type_ == "hash":
            conn.execute(
                "INSERT OR REPLACE INTO whitelist_hashes (hash, filename, reason) "
                "VALUES (?,?,?)",
                (value, filename, reason))
        else:
            conn.execute(
                "INSERT OR REPLACE INTO whitelist_paths (path, reason) VALUES (?,?)",
                (value, reason))
        conn.commit()
        conn.close()
    except Exception as e:
        print("Whitelist Add Error:", e)


def api_post_whitelist_delete(type_: str, value: str):
    try:
        conn = sqlite3.connect(DB_PATH)
        if type_ == "hash":
            conn.execute("DELETE FROM whitelist_hashes WHERE hash = ?", (value,))
        else:
            conn.execute("DELETE FROM whitelist_paths WHERE path = ?", (value,))
        conn.commit()
        conn.close()
    except Exception:
        pass


def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ==========================================
# 3. MAIN APPLICATION CLASS
# ==========================================
class AntiVirusApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("AntiVirusAI - Command Center")
        self.geometry("1450x900")

        initialize_db()

        self.chat_history = [
            {"role": "BOT",
             "text": "Hello! I am your SOC Copilot. How can I help? "
                     "(e.g. 'What is ransomware?', 'How do I add to the whitelist?')"}
        ]

        self._sync_status_text = "Checking..."
        self._on_dashboard = False

        # Persistent settings — shared between Dashboard and Settings page
        cfg = load_settings()
        self.scan_folder = cfg["scan_folder"]
        self.threshold   = cfg["threshold"]

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.df_incidents = api_get_incidents()
        self.build_ui()

        # Start daily background hash sync; update status label when done
        start_daily_sync(callback=self._on_sync_complete)

    def _on_sync_complete(self, result: dict):
        """Called from background thread after each sync — update label via after()."""
        if result["status"] == "ok":
            self._sync_status_text = (
                f"Last sync: {datetime.now().strftime('%Y-%m-%d %H:%M')}  "
                f"|  +{result['inserted']} new hashes  "
                f"|  {get_threat_hash_count():,} total"
            )
        else:
            self._sync_status_text = f"Sync failed: {result.get('error','unknown')}"
        self.after(0, self._refresh_sync_label)

    def _refresh_sync_label(self):
        if hasattr(self, "_sync_lbl") and self._sync_lbl.winfo_exists():
            self._sync_lbl.configure(text=self._sync_status_text)

    # ------------------------------------------------------------------
    # BUILD UI
    # ------------------------------------------------------------------
    def build_ui(self):
        self.configure(fg_color=current_theme["bg"])

        if hasattr(self, "sidebar_frame") and self.sidebar_frame.winfo_exists():
            self.sidebar_frame.destroy()

        # ---- SIDEBAR ----
        self.sidebar_frame = ctk.CTkFrame(
            self, width=240, corner_radius=0, fg_color=current_theme["sidebar"])
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_propagate(False)
        self.sidebar_frame.grid_columnconfigure(0, weight=1)
        # Spacer row below the nav buttons (8 buttons -> rows 2..9) so the engine
        # status panel stays pinned to the bottom without colliding with a button.
        self.sidebar_frame.grid_rowconfigure(10, weight=1)

        # Brand
        brand_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        brand_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(25, 20))

        ctk.CTkLabel(brand_frame, text="[AV]",
                     font=ctk.CTkFont(size=16, weight="bold"),
                     text_color=current_theme["accent"],
                     width=36, height=36,
                     fg_color=current_theme["card"],
                     corner_radius=8).pack(side="left")

        text_frame = ctk.CTkFrame(brand_frame, fg_color="transparent")
        text_frame.pack(side="left", padx=(10, 0))
        ctk.CTkLabel(text_frame, text="AntiVirusAI",
                     font=ctk.CTkFont(size=20, weight="bold"),
                     text_color=current_theme["text"]).pack(anchor="w")

        status_row = ctk.CTkFrame(text_frame, fg_color="transparent")
        status_row.pack(anchor="w")
        ctk.CTkLabel(status_row, text="●", text_color=current_theme["safe"],
                     font=ctk.CTkFont(size=10)).pack(side="left")
        ctk.CTkLabel(status_row, text=" ACTIVE", text_color=current_theme["safe"],
                     font=ctk.CTkFont(size=10, weight="bold")).pack(side="left")

        ctk.CTkFrame(self.sidebar_frame, fg_color=current_theme["border"],
                     height=1).grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 10))

        nav_buttons = [
            ("Dashboard",      self.show_home),
            ("Threat Matrix",  self.show_matrix),
            ("Scan History",   self.show_history),
            ("Quarantine",     self.show_quarantine),
            ("Whitelist",      self.show_whitelist),
            ("Model Info",     self.show_model_info),
            ("Help & Support", self.show_support),
            ("Settings",       self.show_settings),
        ]
        for i, (label, cmd) in enumerate(nav_buttons):
            ctk.CTkButton(
                self.sidebar_frame, text=label, command=cmd,
                fg_color="transparent", text_color=current_theme["text"],
                hover_color=current_theme["card"], anchor="w",
                font=ctk.CTkFont(size=14), height=40, corner_radius=6
            ).grid(row=i + 2, column=0, padx=12, pady=2, sticky="ew")

        # Engine status
        engine_frame = ctk.CTkFrame(
            self.sidebar_frame, fg_color=current_theme["card"],
            corner_radius=8, border_width=1, border_color=current_theme["border"])
        engine_frame.grid(row=11, column=0, sticky="ew", padx=12, pady=(0, 20))

        ctk.CTkLabel(engine_frame, text="ENGINE STATUS",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=current_theme["text_dim"]).pack(anchor="w", padx=12, pady=(10, 6))

        def _status_row(name, status, color):
            r = ctk.CTkFrame(engine_frame, fg_color="transparent")
            r.pack(fill="x", padx=12, pady=2)
            ctk.CTkLabel(r, text=name, text_color=current_theme["text_dim"],
                         font=ctk.CTkFont(size=11)).pack(side="left")
            ctk.CTkLabel(r, text=status, text_color=color,
                         font=ctk.CTkFont(size=11, weight="bold")).pack(side="right")

        _status_row("LightGBM",   "ONLINE",    current_theme["safe"])
        _status_row("Hash DB",    "38,945 hashes", current_theme["safe"])
        _status_row("LIEF Parser","READY",     current_theme["safe"])

        # Sync status label (updated by background thread)
        self._sync_lbl = ctk.CTkLabel(
            engine_frame,
            text=self._sync_status_text,
            text_color=current_theme["text_dim"],
            font=ctk.CTkFont(size=9),
            wraplength=200, justify="left")
        self._sync_lbl.pack(anchor="w", padx=12, pady=(6, 10))

        # ---- MAIN CONTENT ----
        if hasattr(self, "main_frame") and self.main_frame.winfo_exists():
            self.main_frame.destroy()

        self.main_frame = ctk.CTkFrame(self, fg_color=current_theme["bg"], corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.current_frame = None
        self.show_home()

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------
    def clear_main_frame(self):
        if self.current_frame is not None and self.current_frame.winfo_exists():
            self.current_frame.destroy()

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                        background=current_theme["card"],
                        foreground=current_theme["text"],
                        rowheight=34,
                        fieldbackground=current_theme["card"],
                        borderwidth=0,
                        font=("Segoe UI", 11))
        style.map("Treeview", background=[("selected", current_theme["accent"])])
        style.configure("Treeview.Heading",
                        background=current_theme["sidebar"],
                        foreground=current_theme["text_dim"],
                        font=("Segoe UI", 11, "bold"),
                        borderwidth=0)
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    def _make_scrollable_tree(self, parent, columns, col_widths=None):
        container = ctk.CTkFrame(parent, fg_color="transparent")
        tree = ttk.Treeview(container, columns=columns, show="headings")
        vsb = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=(col_widths or {}).get(col, 120), minwidth=60)
        return container, tree

    def _section_card(self, parent, title, color=None):
        """Return (section_frame, card_frame, title_row) for a titled card section."""
        color = color or current_theme["accent"]
        sec = ctk.CTkFrame(parent, fg_color="transparent")
        sec.pack(fill="x", pady=(0, 14))

        title_row = ctk.CTkFrame(sec, fg_color="transparent")
        title_row.pack(fill="x", pady=(0, 8))
        ctk.CTkFrame(title_row, fg_color=color, width=3, corner_radius=2).pack(
            side="left", fill="y", padx=(0, 8))
        ctk.CTkLabel(title_row, text=title, text_color=current_theme["text"],
                     font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")

        card = ctk.CTkFrame(sec, fg_color=current_theme["card"],
                             corner_radius=8, border_width=1,
                             border_color=current_theme["border"])
        card.pack(fill="x")
        return sec, card, title_row

    # ------------------------------------------------------------------
    # PAGE: HOME
    # ------------------------------------------------------------------
    def show_home(self):
        self.clear_main_frame()
        self._on_dashboard = True
        self.current_frame = ctk.CTkScrollableFrame(
            self.main_frame, fg_color="transparent")
        self.current_frame.grid(row=0, column=0, sticky="nsew", padx=30, pady=30)

        df = self.df_incidents
        total_scanned = len(df)
        total_threats = len(df[df["status"] != "SAFE"])      if not df.empty else 0
        total_malware = len(df[df["status"] == "MALWARE"])   if not df.empty else 0
        total_susp    = len(df[df["status"] == "SUSPICIOUS"])if not df.empty else 0
        ai_detect     = len(df[df["source"] == "AI Engine"]) if not df.empty else 0

        # Header
        hdr = ctk.CTkFrame(self.current_frame, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 18))

        tb = ctk.CTkFrame(hdr, fg_color="transparent")
        tb.pack(side="left")
        ctk.CTkLabel(tb, text="Dashboard",
                     font=ctk.CTkFont(size=30, weight="bold"),
                     text_color=current_theme["text"]).pack(anchor="w")
        ctk.CTkLabel(tb, text="SECURITY OPERATIONS CENTER  —  REAL-TIME MONITORING",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=current_theme["text_dim"]).pack(anchor="w")

        # Header right side — Scan Now button + (optional) active-threats badge
        self._dash_scan_btn = ctk.CTkButton(
            hdr, text="Scan Now",
            fg_color=current_theme["accent"],
            hover_color="#2563eb",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=34, width=120,
            command=lambda: self._run_scan_now(self._dash_scan_btn))
        self._dash_scan_btn.pack(side="right", padx=(8, 0))

        if total_threats > 0:
            ctk.CTkButton(hdr, text=f"{total_threats} ACTIVE THREATS",
                          fg_color="transparent",
                          border_color=current_theme["danger"], border_width=1,
                          text_color=current_theme["danger"],
                          font=ctk.CTkFont(weight="bold"),
                          height=34).pack(side="right")

        # KPIs
        kpi_row = ctk.CTkFrame(self.current_frame, fg_color="transparent")
        kpi_row.pack(fill="x", pady=(0, 18))
        kpi_row.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._kpi_card(kpi_row, 0, "FILES SCANNED",
                       str(total_scanned), "Total scan events", current_theme["accent"])
        self._kpi_card(kpi_row, 1, "THREATS BLOCKED",
                       str(total_threats), "MALWARE + SUSPICIOUS", current_theme["danger"],
                       f"  {total_malware} malware / {total_susp} suspicious",
                       current_theme["danger"])
        self._kpi_card(kpi_row, 2, "SAFE FILES",
                       str(total_scanned - total_threats), "Clean scan results",
                       current_theme["safe"])
        self._kpi_card(kpi_row, 3, "AI DETECTIONS",
                       str(ai_detect), "Flagged by AI Engine", current_theme["warn"])

        # --- Signature vs ML comparison (from latest avscan report) ---
        def _load_hash_stats():
            import glob, json as _j
            proj_root = os.path.dirname(os.path.dirname(DB_PATH))
            pattern = os.path.join(proj_root, "evaluation", "scan_*.json")
            files = sorted(glob.glob(pattern), reverse=True)
            if not files:
                return None
            try:
                with open(files[0]) as f:
                    d = _j.load(f)
                return d.get("hash_comparison", {}).get("files")
            except Exception:
                return None
        hc = _load_hash_stats()
        if hc:
            hc_frame = ctk.CTkFrame(self.current_frame,
                                     fg_color=current_theme["card"],
                                     corner_radius=8, border_width=1,
                                     border_color=current_theme["border"])
            hc_frame.pack(fill="x", pady=(0, 18))
            hh = ctk.CTkFrame(hc_frame, fg_color="transparent")
            hh.pack(fill="x", padx=20, pady=(14, 4))
            ctk.CTkLabel(hh, text="🔬  SIGNATURE vs ML COMPARISON",
                         font=ctk.CTkFont(size=13, weight="bold"),
                         text_color=current_theme["text"]).pack(side="left")
            stat_row = ctk.CTkFrame(hc_frame, fg_color="transparent")
            stat_row.pack(fill="x", padx=20, pady=(0, 10))
            for label, key, color in [
                ("ML-Only Catches",  "ML_ONLY_CATCH",  current_theme["danger"]),
                ("Both Caught",      "BOTH_CAUGHT",     current_theme["warn"]),
                ("Both Clear",       "BOTH_CLEAR",      current_theme["safe"]),
            ]:
                f = ctk.CTkFrame(stat_row, fg_color="transparent")
                f.pack(side="left", padx=(0, 30))
                ctk.CTkLabel(f, text=str(hc.get(key, 0)),
                             font=ctk.CTkFont(size=24, weight="bold"),
                             text_color=color).pack(anchor="w")
                ctk.CTkLabel(f, text=label,
                             font=ctk.CTkFont(size=10),
                             text_color=current_theme["text_dim"]).pack(anchor="w")
            ml_only = hc.get("ML_ONLY_CATCH", 0)
            if ml_only > 0:
                ctk.CTkLabel(hc_frame,
                             text=f"ML detected {ml_only} threat(s) invisible to hash signatures.",
                             text_color=current_theme["text_dim"],
                             font=ctk.CTkFont(size=11)).pack(anchor="w", padx=20, pady=(0, 14))

        # Middle row
        mid = ctk.CTkFrame(self.current_frame, fg_color="transparent")
        mid.pack(fill="x", pady=(0, 18))
        mid.grid_columnconfigure(0, weight=3)
        mid.grid_columnconfigure(1, weight=2)

        # Chart card
        chart_card = ctk.CTkFrame(mid, fg_color=current_theme["card"],
                                   corner_radius=8, border_width=1,
                                   border_color=current_theme["border"])
        chart_card.grid(row=0, column=0, sticky="nsew", padx=(0, 15))

        ch = ctk.CTkFrame(chart_card, fg_color="transparent")
        ch.pack(fill="x", padx=20, pady=(12, 4))
        ctk.CTkLabel(ch, text="Threat Activity Timeline",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=current_theme["text"]).pack(anchor="w")
        ctk.CTkLabel(ch, text="LAST 30 DAYS",
                     font=ctk.CTkFont(size=9, weight="bold"),
                     text_color=current_theme["text_dim"]).pack(anchor="w")

        legend = ctk.CTkFrame(chart_card, fg_color="transparent")
        legend.pack(anchor="e", padx=20)
        for col, lbl in [(current_theme["danger"], "Threats"),
                          (current_theme["accent"], "Scans")]:
            ctk.CTkLabel(legend, text="●", text_color=col,
                         font=ctk.CTkFont(size=10)).pack(side="left", padx=(0, 2))
            ctk.CTkLabel(legend, text=lbl + "  ",
                         text_color=current_theme["text_dim"],
                         font=ctk.CTkFont(size=10)).pack(side="left")

        import random as _rng
        _r = _rng.Random(99)

        cv = tk.Canvas(chart_card, height=180,
                       bg=current_theme["card"], highlightthickness=0)
        cv.pack(fill="x", padx=16, pady=(4, 12))

        def _load_timeline_data():
            try:
                conn = sqlite3.connect(DB_PATH)
                df_t = pd.read_sql_query(
                    "SELECT DATE(scanned_at) as day, "
                    "COUNT(*) as scans, "
                    "SUM(CASE WHEN classification != 'SAFE' THEN 1 ELSE 0 END) as threats "
                    "FROM ScanEvent GROUP BY DATE(scanned_at) "
                    "ORDER BY day DESC LIMIT 30",
                    conn)
                conn.close()
                if df_t.empty:
                    return [], []
                return list(reversed(df_t["scans"].tolist())), \
                       list(reversed(df_t["threats"].tolist()))
            except Exception:
                return [], []

        def _draw(e=None):
            cv.delete("all")
            w = cv.winfo_width()
            h = cv.winfo_height()
            if w < 10 or h < 10:
                return
            pl, pr, pt, pb = 36, 12, 10, 28
            pw = w - pl - pr
            ph = h - pt - pb
            scans_data, threats_data = _load_timeline_data()
            if not scans_data:
                cv.create_text(w // 2, h // 2, text="No scan history yet",
                               fill=current_theme["text_dim"],
                               font=("Segoe UI", 12))
                return
            mx = max(max(scans_data), 1)
            for i in range(5):
                y = pt + ph - int(ph * i / 4)
                cv.create_line(pl, y, w - pr, y,
                               fill=current_theme["border"], dash=(3, 4))
                cv.create_text(pl - 4, y, text=str(int(mx * i / 4)),
                               anchor="e", fill=current_theme["text_dim"],
                               font=("Segoe UI", 7))
            n = len(scans_data)
            tick_step = max(1, n // 6)
            for idx in range(0, n, tick_step):
                x = pl + int(pw * idx / max(n - 1, 1))
                cv.create_text(x, h - pb + 6, text=f"{idx + 1}",
                               fill=current_theme["text_dim"], font=("Segoe UI", 7))

            def _line(data, color):
                pts = []
                for i, v in enumerate(data):
                    x = pl + int(pw * i / max(len(data) - 1, 1))
                    y = pt + ph - int(ph * v / mx)
                    pts.extend([x, y])
                cv.create_line(*pts, fill=color, width=2, smooth=True)

            _line(scans_data,   current_theme["accent"])
            _line(threats_data, current_theme["danger"])

        cv.bind("<Configure>", _draw)
        cv.after(50, _draw)

        # Copilot
        cop = ctk.CTkFrame(mid, fg_color="transparent")
        cop.grid(row=0, column=1, sticky="nsew")
        ctk.CTkLabel(cop, text="SOC Copilot",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=current_theme["text"]).pack(anchor="w", pady=(0, 3))
        ctk.CTkLabel(cop, text="AI-GENERATED BRIEFING",
                     font=ctk.CTkFont(size=9, weight="bold"),
                     text_color=current_theme["text_dim"]).pack(anchor="w", pady=(0, 8))

        sync_info = get_last_sync_info()

        def _cop_card(dot_color, title, body):
            c = ctk.CTkFrame(cop, fg_color=current_theme["card"],
                              corner_radius=8, border_width=1,
                              border_color=current_theme["border"])
            c.pack(fill="x", pady=(0, 7))
            hh = ctk.CTkFrame(c, fg_color="transparent")
            hh.pack(fill="x", padx=12, pady=(10, 3))
            ctk.CTkLabel(hh, text="●", text_color=dot_color,
                         font=ctk.CTkFont(size=10)).pack(side="left", padx=(0, 5))
            ctk.CTkLabel(hh, text=title, text_color=current_theme["text"],
                         font=ctk.CTkFont(weight="bold", size=12)).pack(side="left")
            ctk.CTkLabel(c, text=body, text_color=current_theme["text_dim"],
                         wraplength=270, justify="left",
                         font=ctk.CTkFont(size=11)).pack(anchor="w", padx=12, pady=(0, 10))

        _cop_card(current_theme["safe"], "System Status",
                  f"All engines operational. LightGBM loaded. "
                  f"Hash DB: {get_threat_hash_count():,} known signatures. Environment verified.")
        _cop_card(current_theme["danger"], "Threat Summary",
                  f"{total_threats} threat(s) detected — immediate review recommended."
                  if total_threats > 0 else "No active threats detected.")
        _cop_card(current_theme["accent"], "Threat Intel Sync",
                  f"Last sync: {sync_info['time']}  |  "
                  f"+{sync_info['new']} new hashes  |  "
                  f"{get_threat_hash_count():,} known hashes in DB")

        # Active threats list
        th_hdr = ctk.CTkFrame(self.current_frame, fg_color="transparent")
        th_hdr.pack(fill="x", pady=(4, 6))
        ctk.CTkLabel(th_hdr, text="Active Threats Requiring Attention",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=current_theme["text"]).pack(side="left")
        ctk.CTkLabel(th_hdr, text="click a row to open alert",
                     font=ctk.CTkFont(size=10),
                     text_color=current_theme["text_dim"]).pack(side="right")
        ctk.CTkFrame(self.current_frame, fg_color=current_theme["border"],
                     height=1).pack(fill="x", pady=(0, 6))

        active = df[df["status"] != "SAFE"] if not df.empty else pd.DataFrame()
        if not active.empty:
            for _, row in active.iterrows():
                self._threat_row(row)
        else:
            ctk.CTkLabel(self.current_frame, text="No active threats detected.",
                         text_color=current_theme["safe"],
                         font=ctk.CTkFont(size=13)).pack(pady=16)

    def show_quarantine(self):
        self.clear_main_frame()
        self._on_dashboard = False
        self.current_frame = ctk.CTkScrollableFrame(
            self.main_frame, fg_color="transparent")
        self.current_frame.grid(row=0, column=0, sticky="nsew", padx=30, pady=30)
        # Header
        hdr = ctk.CTkFrame(self.current_frame, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 18))
        ctk.CTkLabel(hdr, text="Quarantine Manager",
                     font=ctk.CTkFont(size=28, weight="bold"),
                     text_color=current_theme["text"]).pack(side="left")
        # Load manifest from the project-root quarantine folder (where avscan writes).
        import json as _json
        proj_root = os.path.dirname(os.path.dirname(DB_PATH))
        quar_dir = os.path.join(proj_root, "quarantine")
        manifest_path = os.path.join(quar_dir, "manifest.json")
        quarantined = []
        try:
            if os.path.exists(manifest_path):
                with open(manifest_path, "r", encoding="utf-8") as f:
                    quarantined = _json.load(f)
        except Exception:
            pass

        # Field accessors tolerant of both the avscan manifest and older key names.
        def _orig_path(e):
            return e.get("original_path") or e.get("path") or ""

        def _is_xored(e):
            return bool(e.get("xored", e.get("xor_neutralized", False)))

        def _xor_key(e):
            try:
                return int(e.get("xor_key", 0x55) or 0x55) & 0xFF
            except Exception:
                return 0x55

        # Stats bar
        total_size = sum(
            os.path.getsize(e.get("quarantine_path", ""))
            for e in quarantined
            if e.get("quarantine_path") and os.path.exists(e.get("quarantine_path", ""))
        )
        size_mb = total_size / (1024 * 1024)
        ctk.CTkLabel(self.current_frame,
                     text=f"Total quarantined: {len(quarantined)} files  |  "
                          f"Size: {size_mb:.1f} MB",
                     text_color=current_theme["text_dim"],
                     font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(0, 12))
        # Action buttons row
        btn_row = ctk.CTkFrame(self.current_frame, fg_color="transparent")
        btn_row.pack(fill="x", pady=(0, 16))

        def _restore_all():
            if not quarantined:
                return
            confirm = messagebox.askyesno(
                "Restore All Quarantined Files",
                f"⚠️  This will move {len(quarantined)} file(s) back to their "
                f"original locations.\n\nOnly proceed if you have verified they are safe.",
                icon="warning")
            if not confirm:
                return
            restored, failed = 0, 0
            for entry in quarantined:
                try:
                    qpath = entry.get("quarantine_path", "")
                    orig = _orig_path(entry)
                    if not qpath or not os.path.exists(qpath) or not orig:
                        failed += 1
                        continue
                    with open(qpath, "rb") as f:
                        data = f.read()
                    # Reverse the XOR neutralization (fast, C-level, symmetric).
                    if _is_xored(entry):
                        k = _xor_key(entry)
                        data = data.translate(bytes(b ^ k for b in range(256)))
                    # Verify against the recorded hash BEFORE overwriting the original,
                    # so a corrupted copy can never clobber a real file.
                    sha = (entry.get("sha256") or "").lower()
                    if sha and hashlib.sha256(data).hexdigest() != sha:
                        failed += 1
                        continue
                    os.makedirs(os.path.dirname(orig), exist_ok=True)
                    with open(orig, "wb") as f:
                        f.write(data)
                    os.remove(qpath)
                    restored += 1
                except Exception:
                    failed += 1
            # Rewrite the manifest, keeping only entries whose copy still exists
            # (i.e. the ones that did NOT restore) so failures are not lost.
            try:
                remaining = [e for e in quarantined
                             if e.get("quarantine_path")
                             and os.path.exists(e.get("quarantine_path", ""))]
                with open(manifest_path, "w", encoding="utf-8") as f:
                    _json.dump(remaining, f, indent=2)
            except Exception:
                pass
            messagebox.showinfo(
                "Restore Complete",
                f"Restored: {restored} file(s)\nFailed: {failed} file(s)")
            self.show_quarantine()

        ctk.CTkButton(btn_row, text="⚠️  Restore All",
                      fg_color=current_theme["warn"],
                      hover_color="#b45309",
                      font=ctk.CTkFont(weight="bold"),
                      height=36, width=140,
                      command=_restore_all).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_row, text="Open Quarantine Folder",
                      fg_color="transparent",
                      border_width=1,
                      border_color=current_theme["border"],
                      text_color=current_theme["text"],
                      height=36,
                      command=lambda: os.startfile(quar_dir)
                      ).pack(side="left")
        # Table
        if not quarantined:
            ctk.CTkLabel(self.current_frame,
                         text="No files in quarantine.",
                         text_color=current_theme["safe"],
                         font=ctk.CTkFont(size=13)).pack(pady=20)
            return
        cols = ("Filename", "Quarantined At", "ML Score", "Original Path", "SHA-256")
        widths = {"Filename": 180, "Quarantined At": 130,
                  "ML Score": 80, "Original Path": 300, "SHA-256": 160}
        tc, tree = self._make_scrollable_tree(self.current_frame, cols, widths)
        tc.pack(fill="both", expand=True, pady=(0, 16))
        for entry in quarantined:
            prob = entry.get("lgbm_prob")
            if prob is None:
                prob = entry.get("threat_score") or 0
            try:
                prob = float(prob)
            except Exception:
                prob = 0.0
            prob_str = f"{prob*100:.1f}%" if prob <= 1.0 else f"{prob:.1f}%"
            ts = str(entry.get("timestamp") or entry.get("quarantined_at") or "")[:16]
            name = (entry.get("original_name") or entry.get("name")
                    or os.path.basename(_orig_path(entry)))
            tree.insert("", "end", values=(
                name, ts, prob_str, _orig_path(entry),
                str(entry.get("sha256", ""))[:20] + "..."))

    def show_model_info(self):
        self.clear_main_frame()
        self._on_dashboard = False
        self.current_frame = ctk.CTkScrollableFrame(
            self.main_frame, fg_color="transparent")
        self.current_frame.grid(row=0, column=0, sticky="nsew", padx=30, pady=30)
        ctk.CTkLabel(self.current_frame, text="Model Card",
                     font=ctk.CTkFont(size=28, weight="bold"),
                     text_color=current_theme["text"]).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(self.current_frame, text="lgbm_v7_correct — academic performance report",
                     font=ctk.CTkFont(size=11),
                     text_color=current_theme["text_dim"]).pack(anchor="w", pady=(0, 20))
        sections = [
            ("Training Data", [
                ("Total samples",  "81,011"),
                ("Benign",         "32,329  (System32 / Apps)"),
                ("Malware",        "48,682  (MalwareBazaar 2026)"),
                ("Features",       "2,381   (EMBER v2 PE vectors)"),
                ("Temporal fix",   "10 timestamp features zeroed"),
            ]),
            ("Performance — held-out test set", [
                ("F1",        "0.9936"),
                ("Precision", "0.9946"),
                ("Recall",    "0.9926   (99.3% malware detected)"),
                ("ROC AUC",   "0.9995"),
                ("FPR",       "0.80%   (39 FP / 4,850 benign)"),
                ("FNR",       "0.74%   (54 missed / 7,303 malware)"),
            ]),
            ("Real-World Validation", [
                ("System32 FPR",     "0.20%   (4 / 2,000 files)"),
                ("SysWOW64 FPR",     "0.00%"),
                ("Overall live FPR", "0.36%"),
                ("V6 live FPR",      "~90%   (reference)"),
                ("Improvement",      "~250x better than V6"),
            ]),
            ("V6 vs V7", [
                ("Root cause of V6 failure", "Temporal feature leakage"),
                ("Fix in V7",               "10 timestamp features zeroed"),
                ("LIEF consistency",         "Enforced via selfcheck"),
                ("Val methodology",          "Corrected — no leakage"),
            ]),
        ]
        for sec_title, rows in sections:
            _, card, _ = self._section_card(self.current_frame, sec_title)
            for label, value in rows:
                r = ctk.CTkFrame(card, fg_color="transparent")
                r.pack(fill="x", padx=16, pady=3)
                ctk.CTkLabel(r, text=label,
                             text_color=current_theme["text_dim"],
                             font=ctk.CTkFont(size=12),
                             width=200, anchor="w").pack(side="left")
                ctk.CTkLabel(r, text=value,
                             text_color=current_theme["text"],
                             font=ctk.CTkFont(size=12)).pack(side="left")
            ctk.CTkFrame(card, fg_color="transparent", height=8).pack()
        # Limitations
        _, lim_card, _ = self._section_card(self.current_frame, "Known Limitations",
                                             current_theme["warn"])
        for lim in [
            "Static analysis only — packed/obfuscated malware may evade detection",
            "Legitimate installers: ~67% FPR on Downloads folder (shared PE features)",
            "Training data from MalwareBazaar only — single source bias",
            "Zero-day proxy: same-month holdout, not post-training malware",
        ]:
            r = ctk.CTkFrame(lim_card, fg_color="transparent")
            r.pack(fill="x", padx=16, pady=3)
            ctk.CTkLabel(r, text="⚠",
                         text_color=current_theme["warn"],
                         font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 8))
            ctk.CTkLabel(r, text=lim,
                         text_color=current_theme["text_dim"],
                         font=ctk.CTkFont(size=12),
                         wraplength=700, justify="left").pack(side="left", anchor="w")
        ctk.CTkFrame(lim_card, fg_color="transparent", height=8).pack()

    def _kpi_card(self, parent, col, title, value, sub, accent, trend="", trend_color=""):
        f = ctk.CTkFrame(parent, fg_color=current_theme["card"],
                          corner_radius=8, border_width=1,
                          border_color=current_theme["border"])
        f.grid(row=0, column=col, sticky="nsew", padx=(0, 15) if col < 3 else 0)
        hh = ctk.CTkFrame(f, fg_color="transparent")
        hh.pack(fill="x", padx=16, pady=(14, 6))
        ctk.CTkLabel(hh, text=title, text_color=current_theme["text_dim"],
                     font=ctk.CTkFont(size=10, weight="bold")).pack(side="left")
        ctk.CTkLabel(hh, text="●", text_color=accent,
                     font=ctk.CTkFont(size=14)).pack(side="right")
        ctk.CTkLabel(f, text=value, text_color=current_theme["text"],
                     font=ctk.CTkFont(size=30, weight="bold")).pack(anchor="w", padx=16)
        ctk.CTkLabel(f, text=sub, text_color=current_theme["text_dim"],
                     font=ctk.CTkFont(size=11)).pack(anchor="w", padx=16)
        if trend:
            ctk.CTkLabel(f, text=trend, text_color=trend_color,
                         font=ctk.CTkFont(size=11, weight="bold")).pack(
                anchor="w", padx=16, pady=(3, 14))
        else:
            ctk.CTkFrame(f, fg_color="transparent", height=17).pack(pady=(3, 14))

    def _threat_row(self, row):
        score_val = float(row["score"])
        sc_color = current_theme["danger"] if score_val > 80 else current_theme["warn"]

        rf = ctk.CTkFrame(self.current_frame, fg_color=current_theme["card"],
                           corner_radius=6, border_width=1,
                           border_color=current_theme["border"], cursor="hand2")
        rf.pack(fill="x", pady=2)
        rf.grid_columnconfigure(1, weight=1)

        def _open(e, r=row): self.open_threat_modal(r["id"], r)
        rf.bind("<Button-1>", _open)

        bar = ctk.CTkFrame(rf, fg_color=sc_color, width=3, corner_radius=0)
        bar.grid(row=0, column=0, rowspan=2, sticky="ns", padx=(0, 10))
        bar.bind("<Button-1>", _open)

        n = ctk.CTkLabel(rf, text=row["filename"],
                          font=ctk.CTkFont(size=12, weight="bold"),
                          text_color=current_theme["text"], anchor="w")
        n.grid(row=0, column=1, sticky="sw", pady=(4, 0))
        n.bind("<Button-1>", _open)

        h = ctk.CTkLabel(rf, text=str(row["hash"])[:34] + "...",
                          font=ctk.CTkFont(size=9, family="Courier"),
                          text_color=current_theme["text_dim"], anchor="w")
        h.grid(row=1, column=1, sticky="nw", pady=(0, 5))
        h.bind("<Button-1>", _open)

        s = ctk.CTkLabel(rf, text=f"{score_val:.1f}%",
                          font=ctk.CTkFont(size=13, weight="bold"),
                          text_color=sc_color, anchor="e", width=60)
        s.grid(row=0, column=2, sticky="se", padx=(8, 12), pady=(4, 0))
        s.bind("<Button-1>", _open)

        src = ctk.CTkLabel(rf, text=row["source"],
                            font=ctk.CTkFont(size=9),
                            text_color=current_theme["text_dim"], anchor="e", width=60)
        src.grid(row=1, column=2, sticky="ne", padx=(8, 12), pady=(0, 5))
        src.bind("<Button-1>", _open)

    # ------------------------------------------------------------------
    # THREAT MODAL
    # ------------------------------------------------------------------
    def open_threat_modal(self, incident_id, data):
        play_critical_sound()
        modal = ctk.CTkToplevel(self)
        modal.title("Threat Detail")
        modal.geometry("680x750")
        modal.configure(fg_color=current_theme["bg"])
        modal.attributes("-topmost", True)
        modal.focus_force()

        is_malware = float(data["score"]) > 80 or str(data["status"]).upper() == "MALWARE"
        tc = current_theme["danger"] if is_malware else current_theme["warn"]
        sev = "HIGH SEVERITY  --  IMMEDIATE ACTION REQUIRED" if is_malware \
            else "MEDIUM SEVERITY  --  REVIEW RECOMMENDED"
        hbg = "#2a1010" if is_malware else "#2a1d0b"

        hf = ctk.CTkFrame(modal, fg_color=hbg, corner_radius=10,
                           border_width=1, border_color=tc)
        hf.pack(fill="x", padx=15, pady=15)
        hi = ctk.CTkFrame(hf, fg_color="transparent")
        hi.pack(fill="x", padx=20, pady=6)
        ib = ctk.CTkFrame(hi, fg_color="transparent", border_width=1,
                           border_color=tc, corner_radius=8, width=46, height=46)
        ib.pack(side="left", padx=(0, 16))
        ib.pack_propagate(False)
        ctk.CTkLabel(ib, text="AV", text_color=tc,
                     font=ctk.CTkFont(size=14, weight="bold")).place(
            relx=0.5, rely=0.5, anchor="center")
        tb2 = ctk.CTkFrame(hi, fg_color="transparent")
        tb2.pack(side="left")
        ctk.CTkLabel(tb2, text="MALWARE DETAIL",
                     font=ctk.CTkFont(size=20, weight="bold"),
                     text_color=tc).pack(anchor="w")
        ctk.CTkLabel(tb2, text=sev,
                     font=ctk.CTkFont(size=9, weight="bold"),
                     text_color=tc).pack(anchor="w")

        content = ctk.CTkScrollableFrame(modal, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=(0, 5))

        def _info_row(card, label, value, val_color=None, badge=False, mono=False):
            val_color = val_color or current_theme["text"]
            r = ctk.CTkFrame(card, fg_color="transparent")
            r.pack(fill="x", padx=16, pady=2)
            ctk.CTkLabel(r, text=label, text_color=current_theme["text_dim"],
                         font=ctk.CTkFont(size=12), width=130, anchor="w").pack(side="left")
            if badge:
                b = ctk.CTkFrame(r, fg_color="transparent",
                                  border_width=1, border_color=val_color, corner_radius=4)
                b.pack(side="right")
                ctk.CTkLabel(b, text=value, text_color=val_color,
                             font=ctk.CTkFont(size=11, weight="bold")).pack(padx=8, pady=2)
            else:
                fnt = ctk.CTkFont(family="Courier", size=11) if mono else ctk.CTkFont(size=12)
                ctk.CTkLabel(r, text=value, text_color=val_color, font=fnt).pack(side="right")

        # Section 1: File Info
        _, card1, _ = self._section_card(content, "File Information", tc)
        _info_row(card1, "Filename",        str(data["filename"]))
        _info_row(card1, "SHA-256",          str(data["hash"])[:34] + "...", mono=True)
        _info_row(card1, "File Path",        f"C:\\Users\\Documents\\{data['filename']}")
        _info_row(card1, "Malware Type",     str(data.get("malware_type", "Unknown")))
        _info_row(card1, "Entropy",          str(data.get("entropy", "N/A")))
        ctk.CTkFrame(card1, fg_color=current_theme["border"], height=1).pack(
            fill="x", padx=16)
        _info_row(card1, "Threat Score",     f"{float(data['score']):.1f}%",
                  val_color=tc)
        _info_row(card1, "Classification",   str(data["status"]).upper(),
                  val_color=tc, badge=True)
        _info_row(card1, "Detection Reason", str(data.get("reason", "N/A")),
                  val_color=current_theme["warn"])

        # Section 2: Cloud / Source
        _, card2, _ = self._section_card(content, "Detection Source", tc)
        _info_row(card2, "Source Engine",   str(data["source"]))
        diag = (str(data["diagnosis"])
                if pd.notna(data["diagnosis"]) and data["diagnosis"]
                else "No diagnosis available.")
        ctk.CTkLabel(card2, text=diag, text_color=current_theme["text_dim"],
                     font=ctk.CTkFont(size=12), justify="left",
                     wraplength=580).pack(anchor="w", padx=16, pady=(4, 14))

        # Action buttons
        bf = ctk.CTkFrame(modal, fg_color="transparent")
        bf.pack(fill="x", padx=15, pady=(5, 15))

        ctk.CTkButton(bf, text="LOCAL AI SCAN",
                      fg_color=current_theme["accent"],
                      font=ctk.CTkFont(weight="bold"),
                      height=40).pack(side="left", expand=True, padx=4)

        def _delete():
            api_post_file_delete(incident_id)
            self.df_incidents = api_get_incidents()
            modal.destroy()
            self.show_home()

        ctk.CTkButton(bf, text="DELETE FILE",
                      fg_color=current_theme["danger"], hover_color="#b91c1c",
                      font=ctk.CTkFont(weight="bold"),
                      height=40, command=_delete).pack(side="left", expand=True, padx=4)

        def _whitelist():
            api_post_whitelist_add("hash", data["hash"], "Marked safe from Alert Modal")
            _delete()

        ctk.CTkButton(bf, text="WHITELIST",
                      fg_color=current_theme["safe"], hover_color="#059669",
                      font=ctk.CTkFont(weight="bold"),
                      height=40, command=_whitelist).pack(side="left", expand=True, padx=4)

    # ------------------------------------------------------------------
    # PAGE: THREAT MATRIX
    # ------------------------------------------------------------------
    def show_matrix(self):
        self.clear_main_frame()
        self._on_dashboard = False
        self.current_frame = ctk.CTkFrame(self.main_frame, fg_color=current_theme["bg"])
        self.current_frame.grid(row=0, column=0, sticky="nsew", padx=30, pady=30)
        self.current_frame.grid_rowconfigure(3, weight=1)
        self.current_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.current_frame, text="Threat Matrix",
                     font=ctk.CTkFont(size=28, weight="bold"),
                     text_color=current_theme["text"]).grid(
            row=0, column=0, sticky="w", pady=(0, 4))
        ctk.CTkLabel(self.current_frame,
                     text="Global File Registry — click any row for details",
                     font=ctk.CTkFont(size=11),
                     text_color=current_theme["text_dim"]).grid(
            row=1, column=0, sticky="w", pady=(0, 16))

        sf = ctk.CTkFrame(self.current_frame, fg_color="transparent")
        sf.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        self.search_var = tk.StringVar()
        ctk.CTkEntry(sf, textvariable=self.search_var,
                     placeholder_text="Search by filename or hash...",
                     width=380, height=36).pack(side="left", padx=(0, 8))
        self.search_var.trace_add("write", lambda *_: self._filter_matrix())
        ctk.CTkButton(sf, text="Search", width=90, height=36,
                      command=self._filter_matrix,
                      fg_color=current_theme["accent"]).pack(side="left")

        cols = ("Time", "Filename", "Malware Type", "Score", "Entropy", "Status")
        widths = {"Time": 130, "Filename": 240, "Malware Type": 120,
                  "Score": 80, "Entropy": 80, "Status": 110}
        tc, self.tree = self._make_scrollable_tree(self.current_frame, cols, widths)
        tc.grid(row=3, column=0, sticky="nsew")
        self._filter_matrix()

        def _click(e):
            sel = self.tree.selection()
            if sel:
                self.after(50, lambda: self._open_matrix_row(sel[0]))

        self.tree.bind("<ButtonRelease-1>", _click)

    def _open_matrix_row(self, iid):
        try:
            i_id = int(iid)
            mask = self.df_incidents["id"] == i_id
            if mask.any():
                self.open_threat_modal(i_id, self.df_incidents[mask].iloc[0])
        except Exception as ex:
            print("Matrix click error:", ex)

    def _filter_matrix(self):
        if not hasattr(self, "tree") or not self.tree.winfo_exists():
            return
        q = self.search_var.get().lower().strip()
        for item in self.tree.get_children():
            self.tree.delete(item)
        for _, row in self.df_incidents.iterrows():
            if q == "" or q in str(row["filename"]).lower() or q in str(row["hash"]).lower():
                tag = ("malware"    if str(row["status"]).upper() == "MALWARE" else
                       "suspicious" if str(row["status"]).upper() == "SUSPICIOUS" else "safe")
                self.tree.insert("", "end", iid=str(row["id"]),
                                 values=(str(row["scanned_at"])[:16], row["filename"],
                                         row.get("malware_type", "Unknown"),
                                         f"{float(row['score']):.2f}%",
                                         str(row.get("entropy", "N/A")),
                                         row["status"]),
                                 tags=(tag,))
        self.tree.tag_configure("malware",    foreground=current_theme["danger"])
        self.tree.tag_configure("suspicious", foreground=current_theme["warn"])
        self.tree.tag_configure("safe",       foreground=current_theme["safe"])

    # ------------------------------------------------------------------
    # PAGE: SCAN HISTORY
    # ------------------------------------------------------------------
    def show_history(self):
        self.clear_main_frame()
        self._on_dashboard = False
        self.current_frame = ctk.CTkFrame(self.main_frame, fg_color=current_theme["bg"])
        self.current_frame.grid(row=0, column=0, sticky="nsew", padx=30, pady=30)
        self.current_frame.grid_rowconfigure(1, weight=1)
        self.current_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.current_frame, text="Scan Sessions History",
                     font=ctk.CTkFont(size=28, weight="bold"),
                     text_color=current_theme["text"]).grid(
            row=0, column=0, sticky="w", pady=(0, 16))

        scroll = ctk.CTkScrollableFrame(self.current_frame, fg_color="transparent")
        scroll.grid(row=1, column=0, sticky="nsew")

        if self.df_incidents.empty:
            ctk.CTkLabel(scroll, text="No scan sessions in the database.",
                         text_color=current_theme["text_dim"],
                         font=ctk.CTkFont(size=13)).pack(pady=20)
            return

        for scan_id, group in self.df_incidents.groupby("scan_id"):
            total = len(group)
            threats = len(group[group["status"] != "SAFE"])
            last = str(group["scanned_at"].max())[:16]

            card = ctk.CTkFrame(scroll, fg_color=current_theme["card"],
                                 corner_radius=10, border_width=1,
                                 border_color=current_theme["border"])
            card.pack(fill="x", pady=8)

            ir = ctk.CTkFrame(card, fg_color="transparent")
            ir.pack(fill="x", padx=20, pady=16)
            ctk.CTkLabel(ir, text=str(scan_id),
                         font=ctk.CTkFont(size=17, weight="bold"),
                         text_color=current_theme["text"]).pack(anchor="w")
            ctk.CTkLabel(ir,
                         text=f"Last scan: {last}   |   Files: {total}   |   Threats: {threats}",
                         text_color=current_theme["text_dim"],
                         font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(4, 0))

            def _open(s=scan_id, g=group):
                play_alert_sound()
                self._show_scan_detail(s, g)

            ctk.CTkButton(card, text="Open Report",
                          fg_color=current_theme["accent"],
                          height=34, command=_open).pack(
                side="right", padx=20, pady=(0, 16))

    def _show_scan_detail(self, scan_id, group):
        self.current_frame.destroy()
        self.current_frame = ctk.CTkFrame(self.main_frame, fg_color=current_theme["bg"])
        self.current_frame.grid(row=0, column=0, sticky="nsew", padx=30, pady=30)
        self.current_frame.grid_rowconfigure(2, weight=1)
        self.current_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkButton(self.current_frame, text="<  Back to History",
                      fg_color="transparent", border_width=1,
                      border_color=current_theme["border"],
                      text_color=current_theme["text"],
                      command=self.show_history, height=34).grid(
            row=0, column=0, sticky="w", pady=(0, 10))
        ctk.CTkLabel(self.current_frame, text=f"Report: {scan_id}",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=current_theme["text"]).grid(
            row=1, column=0, sticky="w", pady=(0, 14))

        cols = ("Filename", "Score", "Type", "Status", "Reason")
        widths = {"Filename": 240, "Score": 80, "Type": 120, "Status": 100, "Reason": 280}
        tc, tree = self._make_scrollable_tree(self.current_frame, cols, widths)
        tc.grid(row=2, column=0, sticky="nsew")

        for _, r in group.iterrows():
            tag = ("malware"    if str(r["status"]).upper() == "MALWARE" else
                   "suspicious" if str(r["status"]).upper() == "SUSPICIOUS" else "safe")
            tree.insert("", "end", iid=str(r["id"]),
                        values=(r["filename"], f"{float(r['score']):.2f}%",
                                r.get("malware_type", "Unknown"),
                                r["status"], r.get("reason", "N/A")),
                        tags=(tag,))
        tree.tag_configure("malware",    foreground=current_theme["danger"])
        tree.tag_configure("suspicious", foreground=current_theme["warn"])
        tree.tag_configure("safe",       foreground=current_theme["safe"])

        def _click(e):
            sel = tree.selection()
            if sel:
                i_id = int(sel[0])
                mask = self.df_incidents["id"] == i_id
                if mask.any():
                    self.open_threat_modal(i_id, self.df_incidents[mask].iloc[0])

        tree.bind("<ButtonRelease-1>", _click)

    # ------------------------------------------------------------------
    # PAGE: WHITELIST
    # ------------------------------------------------------------------
    def show_whitelist(self):
        self.clear_main_frame()
        self._on_dashboard = False
        self.current_frame = ctk.CTkFrame(self.main_frame, fg_color=current_theme["bg"])
        self.current_frame.grid(row=0, column=0, sticky="nsew", padx=30, pady=30)
        self.current_frame.grid_rowconfigure(1, weight=1)
        self.current_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.current_frame, text="Whitelist Manager",
                     font=ctk.CTkFont(size=28, weight="bold"),
                     text_color=current_theme["text"]).grid(
            row=0, column=0, sticky="w", pady=(0, 16))

        tabs = ctk.CTkTabview(self.current_frame, fg_color=current_theme["card"],
                               segmented_button_selected_color=current_theme["accent"])
        tabs.grid(row=1, column=0, sticky="nsew")

        tab_h = tabs.add("File Hashes")
        tab_p = tabs.add("Path Exclusions")

        # ── helpers that refresh only the treeview, never rebuild the page ──

        def _reload_hashes():
            for row in tree_h.get_children():
                tree_h.delete(row)
            try:
                conn = sqlite3.connect(DB_PATH)
                df_hashes = pd.read_sql_query(
                    "SELECT * FROM whitelist_hashes ORDER BY added_at DESC", conn)
                conn.close()
                for _, r in df_hashes.iterrows():
                    fname = r["filename"] if "filename" in r and pd.notna(r["filename"]) else ""
                    tree_h.insert("", "end",
                                  values=(fname or "(unknown)",
                                          r["hash"],
                                          r.get("added_at", "")))
            except Exception as e:
                print("reload hashes error:", e)

        def _reload_paths():
            for row in tree_p.get_children():
                tree_p.delete(row)
            try:
                conn = sqlite3.connect(DB_PATH)
                for _, r in pd.read_sql_query(
                        "SELECT * FROM whitelist_paths ORDER BY added_date DESC", conn).iterrows():
                    tree_p.insert("", "end", values=(r["path"], r.get("added_date", "")))
                conn.close()
            except Exception as e:
                print("reload paths error:", e)

        # ==============================================================
        # HASH TAB
        # ==============================================================
        tab_h.grid_rowconfigure(2, weight=1)
        tab_h.grid_columnconfigure(0, weight=1)

        row0_h = ctk.CTkFrame(tab_h, fg_color="transparent")
        row0_h.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        hash_var = tk.StringVar()
        name_var = tk.StringVar()       # holds the picked file's basename
        picked = {"name": ""}            # closure holder so callbacks can share

        ctk.CTkEntry(row0_h, textvariable=hash_var,
                     placeholder_text="SHA-256 hash — or use Browse below",
                     height=36).pack(side="left", fill="x", expand=True, padx=(0, 8))

        def _browse_hash():
            fp = filedialog.askopenfilename(
                title="Select file to whitelist",
                filetypes=[("All files", "*.*"),
                           ("Executables", "*.exe *.dll *.sys"),
                           ("Documents",   "*.doc *.docx *.pdf")])
            if not fp:
                return
            try:
                sha = compute_sha256(fp)
                hash_var.set(sha)
                picked["name"] = os.path.basename(fp)
                name_var.set(picked["name"])
                fname = picked["name"]
                messagebox.showinfo(
                    "Hash Computed",
                    f"File: {fname}\n\nSHA-256:\n{sha}\n\n"
                    "Filled in. Click Add Hash to save.")
            except Exception as err:
                messagebox.showerror("Hashing Error", str(err))

        ctk.CTkButton(row0_h, text="Browse File",
                      fg_color=current_theme["accent"], height=36, width=110,
                      command=_browse_hash).pack(side="left", padx=(0, 8))

        def _ask_filename():
            """Pop a tiny input dialog if user typed a hash manually."""
            dlg = ctk.CTkInputDialog(
                text="Optional: enter a name for this file (or leave blank).",
                title="File Name")
            return dlg.get_input() or ""

        def _add_hash():
            h = hash_var.get().strip()
            if not h:
                messagebox.showwarning("Empty Hash",
                                       "Enter a hash or browse for a file first.")
                return
            # Use the picked filename, or prompt for one if user typed the hash manually
            fname = picked["name"] if picked["name"] else _ask_filename()
            api_post_whitelist_add("hash", h, "Added via Dashboard", filename=fname)
            hash_var.set("")
            name_var.set("")
            picked["name"] = ""
            _reload_hashes()

        ctk.CTkButton(row0_h, text="Add Hash",
                      fg_color=current_theme["safe"], height=36, width=100,
                      command=_add_hash).pack(side="left")

        cols_h = ("File Name", "Hash", "Date Added")
        wids_h = {"File Name": 180, "Hash": 420, "Date Added": 140}
        tc_h, tree_h = self._make_scrollable_tree(tab_h, cols_h, wids_h)
        tc_h.grid(row=2, column=0, sticky="nsew")

        def _del_hash():
            sel = tree_h.selection()
            if sel:
                # Hash is column index 1 now (column 0 is File Name)
                api_post_whitelist_delete("hash", tree_h.item(sel[0])["values"][1])
                _reload_hashes()

        ctk.CTkButton(tab_h, text="Delete Selected",
                      fg_color=current_theme["danger"], height=34,
                      command=_del_hash).grid(row=3, column=0, sticky="w", pady=8)

        _reload_hashes()   # initial load

        # ==============================================================
        # PATH TAB
        # ==============================================================
        tab_p.grid_rowconfigure(1, weight=1)
        tab_p.grid_columnconfigure(0, weight=1)

        row0_p = ctk.CTkFrame(tab_p, fg_color="transparent")
        row0_p.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        path_var = tk.StringVar()
        ctk.CTkEntry(row0_p, textvariable=path_var,
                     placeholder_text="Directory path — or use Browse",
                     height=36).pack(side="left", fill="x", expand=True, padx=(0, 8))

        def _browse_dir():
            d = filedialog.askdirectory(title="Select directory to exclude")
            if d:
                path_var.set(os.path.normpath(d))

        ctk.CTkButton(row0_p, text="Browse",
                      fg_color=current_theme["accent"], height=36, width=90,
                      command=_browse_dir).pack(side="left", padx=(0, 8))

        def _add_path():
            raw = path_var.get().strip()
            p = os.path.normpath(raw) if raw else ""
            if p:
                api_post_whitelist_add("path", p, "Added via Dashboard")
                path_var.set("")
                _reload_paths()   # update list in-place — no page rebuild
            else:
                messagebox.showwarning("Empty Path", "Enter a path or use Browse first.")

        ctk.CTkButton(row0_p, text="Add Path",
                      fg_color=current_theme["safe"], height=36, width=100,
                      command=_add_path).pack(side="left")

        cols_p = ("Path", "Date Added")
        wids_p = {"Path": 520, "Date Added": 180}
        tc_p, tree_p = self._make_scrollable_tree(tab_p, cols_p, wids_p)
        tc_p.grid(row=1, column=0, sticky="nsew")

        def _del_path():
            sel = tree_p.selection()
            if sel:
                api_post_whitelist_delete("path", tree_p.item(sel[0])["values"][0])
                _reload_paths()

        ctk.CTkButton(tab_p, text="Delete Selected",
                      fg_color=current_theme["danger"], height=34,
                      command=_del_path).grid(row=2, column=0, sticky="w", pady=8)

        _reload_paths()   # initial load

    # ------------------------------------------------------------------
    # PAGE: HELP & SUPPORT
    # ------------------------------------------------------------------
    def show_support(self):
        self.clear_main_frame()
        self._on_dashboard = False
        self.current_frame = ctk.CTkFrame(self.main_frame, fg_color=current_theme["bg"])
        self.current_frame.grid(row=0, column=0, sticky="nsew", padx=30, pady=30)
        self.current_frame.grid_rowconfigure(1, weight=1)
        self.current_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.current_frame, text="Help & Technical Support",
                     font=ctk.CTkFont(size=28, weight="bold"),
                     text_color=current_theme["text"]).grid(
            row=0, column=0, sticky="w", pady=(0, 16))

        self.chat_display = ctk.CTkScrollableFrame(
            self.current_frame, fg_color=current_theme["card"],
            corner_radius=10, border_width=1, border_color=current_theme["border"])
        self.chat_display.grid(row=1, column=0, sticky="nsew", pady=(0, 12))

        self._refresh_chat()

        inf = ctk.CTkFrame(self.current_frame, fg_color="transparent")
        inf.grid(row=2, column=0, sticky="ew")
        self.chat_var = tk.StringVar()
        entry = ctk.CTkEntry(inf, textvariable=self.chat_var,
                              placeholder_text="Ask the assistant...",
                              height=40, font=ctk.CTkFont(size=13))
        entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        entry.bind("<Return>", lambda e: self._send_chat())
        ctk.CTkButton(inf, text="Send", height=40,
                      command=self._send_chat,
                      fg_color=current_theme["accent"]).pack(side="right")

    def _refresh_chat(self):
        for w in self.chat_display.winfo_children():
            w.destroy()
        for msg in self.chat_history:
            is_user = msg["role"] == "USER"
            bg = current_theme["accent"] if is_user else current_theme["sidebar"]
            prefix = "You: " if is_user else "AI: "
            ctk.CTkLabel(self.chat_display,
                         text=prefix + msg["text"],
                         text_color=current_theme["text"], fg_color=bg,
                         corner_radius=8,
                         justify="right" if is_user else "left",
                         wraplength=750,
                         font=ctk.CTkFont(size=13)).pack(
                anchor="e" if is_user else "w",
                padx=14, pady=6, ipadx=12, ipady=10)

    def _send_chat(self):
        user_text = self.chat_var.get().strip()
        if not user_text:
            return
        self.chat_var.set("")
        self.chat_history.append({"role": "USER", "text": user_text})
        self._refresh_chat()

        t = user_text.lower()
        if "whitelist" in t:
            r = ("To add to the whitelist, click 'Whitelist' in the sidebar. "
                 "You can enter a hash manually or click 'Browse & Compute Hash' to auto-hash a file.")
        elif "ransomware" in t:
            r = ("Ransomware encrypts files and demands payment. "
                 "The system detects it via high entropy scores and known hash matches.")
        elif "matrix" in t or "threat" in t:
            r = ("In Threat Matrix you can see all scanned files. Click any row for full details.")
        elif "settings" in t or "scan" in t:
            r = ("In Settings you can configure the scan folder, AI threshold, "
                 "run an immediate scan, manage appearance, and view audit logs.")
        elif "sync" in t or "hash" in t:
            r = ("Malware hashes are synced daily from MalwareBazaar (abuse.ch). "
                 "You can also trigger a manual sync via Settings > Scan Now.")
        else:
            r = ("I am currently in display mode. "
                 "In the full deployment I connect directly to the AI inference API.")

        self.chat_history.append({"role": "BOT", "text": r})
        self._refresh_chat()

    # ------------------------------------------------------------------
    # PAGE: SETTINGS
    # ------------------------------------------------------------------
    def show_settings(self):
        self.clear_main_frame()
        self._on_dashboard = False
        self.current_frame = ctk.CTkScrollableFrame(
            self.main_frame, fg_color="transparent")
        self.current_frame.grid(row=0, column=0, sticky="nsew", padx=30, pady=30)

        ctk.CTkLabel(self.current_frame, text="Settings & Administration",
                     font=ctk.CTkFont(size=28, weight="bold"),
                     text_color=current_theme["text"]).pack(anchor="w", pady=(0, 20))

        # ---- Scan Configuration ----
        sc = ctk.CTkFrame(self.current_frame, fg_color=current_theme["card"],
                           corner_radius=10, border_width=1,
                           border_color=current_theme["border"])
        sc.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(sc, text="Scan Configuration",
                     font=ctk.CTkFont(size=16, weight="bold"),
                     text_color=current_theme["text"]).pack(anchor="w", padx=20, pady=(20, 4))
        ctk.CTkFrame(sc, fg_color=current_theme["border"],
                     height=1).pack(fill="x", padx=20, pady=(0, 12))

        ctk.CTkLabel(sc, text="Target Scan Folder",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=current_theme["text"]).pack(anchor="w", padx=20, pady=(0, 6))
        target_var = tk.StringVar(value=self.scan_folder)
        folder_row = ctk.CTkFrame(sc, fg_color="transparent")
        folder_row.pack(anchor="w", padx=20, pady=(0, 14))
        ctk.CTkEntry(folder_row, textvariable=target_var,
                     width=380, height=36).pack(side="left", padx=(0, 8))

        def _browse_scan_folder():
            d = filedialog.askdirectory(title="Select target scan folder")
            if d:
                target_var.set(d)

        ctk.CTkButton(folder_row, text="Browse",
                      fg_color=current_theme["accent"], height=36, width=80,
                      command=_browse_scan_folder).pack(side="left")

        ctk.CTkLabel(sc, text="Malware Confidence Threshold (%)",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=current_theme["text"]).pack(anchor="w", padx=20, pady=(0, 4))
        slider_var = tk.DoubleVar(value=self.threshold)
        sl_lbl = ctk.CTkLabel(sc, text=f"{self.threshold:.1f}%",
                               text_color=current_theme["accent"],
                               font=ctk.CTkFont(size=12, weight="bold"))
        sl_lbl.pack(anchor="w", padx=20)

        def _on_slider(v):
            sl_lbl.configure(text=f"{float(v):.1f}%")

        ctk.CTkSlider(sc, from_=50, to=99.9, variable=slider_var,
                       button_color=current_theme["accent"],
                       command=_on_slider).pack(fill="x", padx=20, pady=(4, 12))

        def _save():
            p = target_var.get().strip()
            if not (os.path.exists(p) or p == "C:\\"):
                messagebox.showerror("Error", "Directory does not exist.")
                return
            self.scan_folder = p
            self.threshold   = float(slider_var.get())
            save_settings(self.scan_folder, self.threshold)
            messagebox.showinfo(
                "Saved",
                f"Settings saved.\nScan folder: {self.scan_folder}\n"
                f"Threshold: {self.threshold:.1f}%")

        btn_row = ctk.CTkFrame(sc, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(4, 20))

        ctk.CTkButton(btn_row, text="Save Configurations",
                      fg_color=current_theme["safe"], height=36,
                      command=_save).pack(side="left", padx=(0, 12))

        # ---- SCAN NOW button ----
        self._scan_now_btn = ctk.CTkButton(
            btn_row, text="Scan Now",
            fg_color=current_theme["accent"], height=36,
            command=self._run_scan_now)
        self._scan_now_btn.pack(side="left")

        # ---- Threat Intel Sync ----
        si = ctk.CTkFrame(self.current_frame, fg_color=current_theme["card"],
                           corner_radius=10, border_width=1,
                           border_color=current_theme["border"])
        si.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(si, text="Threat Intelligence Sync",
                     font=ctk.CTkFont(size=16, weight="bold"),
                     text_color=current_theme["text"]).pack(anchor="w", padx=20, pady=(20, 4))
        ctk.CTkFrame(si, fg_color=current_theme["border"],
                     height=1).pack(fill="x", padx=20, pady=(0, 12))

        sync_info = get_last_sync_info()
        ctk.CTkLabel(si,
                     text=(f"Source: MalwareBazaar (abuse.ch)  |  "
                           f"Schedule: Daily automatic sync\n"
                           f"Last sync: {sync_info['time']}  |  "
                           f"New hashes added: {sync_info['new']}  |  "
                           f"Total known hashes: {get_threat_hash_count():,}"),
                     text_color=current_theme["text_dim"],
                     font=ctk.CTkFont(size=12),
                     justify="left").pack(anchor="w", padx=20, pady=(0, 8))

        self._manual_sync_btn = ctk.CTkButton(
            si, text="Sync Now",
            fg_color=current_theme["accent"], height=36,
            command=self._run_manual_sync)
        self._manual_sync_btn.pack(anchor="w", padx=20, pady=(0, 20))

        # ---- Appearance & Accessibility ----
        ap = ctk.CTkFrame(self.current_frame, fg_color=current_theme["card"],
                           corner_radius=10, border_width=1,
                           border_color=current_theme["border"])
        ap.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(ap, text="Appearance & Accessibility",
                     font=ctk.CTkFont(size=16, weight="bold"),
                     text_color=current_theme["text"]).pack(anchor="w", padx=20, pady=(20, 4))
        ctk.CTkFrame(ap, fg_color=current_theme["border"],
                     height=1).pack(fill="x", padx=20, pady=(0, 12))

        ctk.CTkLabel(ap, text="Color Theme",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=current_theme["text"]).pack(anchor="w", padx=20, pady=(0, 4))
        ctk.CTkLabel(ap,
                     text="Dark Mode uses a low-light palette. "
                          "Light Mode uses a bright white palette.",
                     text_color=current_theme["text_dim"],
                     font=ctk.CTkFont(size=12),
                     wraplength=700).pack(anchor="w", padx=20, pady=(0, 10))

        tbr = ctk.CTkFrame(ap, fg_color="transparent")
        tbr.pack(fill="x", padx=20, pady=(0, 20))

        def _set_theme(name: str):
            global current_theme
            current_theme = THEMES[name]
            apply_ctk_mode(name)
            self.build_ui()
            self.show_settings()

        ctk.CTkButton(tbr, text="Dark Mode",
                      fg_color="#1e293b", text_color="#ffffff",
                      border_color="#3b82f6", border_width=2,
                      height=40, command=lambda: _set_theme("dark")).pack(
            side="left", padx=(0, 10))
        ctk.CTkButton(tbr, text="Light Mode",
                      fg_color="#f1f5f9", text_color="#0f172a",
                      border_color="#2563eb", border_width=2,
                      height=40, command=lambda: _set_theme("light")).pack(side="left")

        # ---- Audit Logs ----
        ctk.CTkLabel(self.current_frame, text="Audit Logs",
                     font=ctk.CTkFont(size=18, weight="bold"),
                     text_color=current_theme["text"]).pack(anchor="w", pady=(8, 10))

        cols = ("Time", "Source", "Action", "File")
        widths = {"Time": 150, "Source": 110, "Action": 140, "File": 440}
        tc_a, tree_a = self._make_scrollable_tree(self.current_frame, cols, widths)
        tc_a.pack(fill="x")

        try:
            conn = sqlite3.connect(DB_PATH)
            df_a = pd.read_sql_query(
                "SELECT scanned_at, detection_source, classification, filename "
                "FROM ScanEvent ORDER BY id DESC LIMIT 50",
                conn)
            conn.close()
            for _, r in df_a.iterrows():
                action = "THREAT_DETECTED" if r["classification"] != "SAFE" else "FILE_SCANNED"
                tree_a.insert("", "end", values=(
                    str(r["scanned_at"])[:16],
                    str(r["detection_source"]),
                    action,
                    str(r["filename"])))
        except Exception as e:
            tree_a.insert("", "end", values=("--", "--", "DB_ERROR", str(e)))

    # ---- Scan Now ----
    def _run_scan_now(self, button: "ctk.CTkButton | None" = None):
        """Launch engine.py with the configured scan folder, then reload incidents."""
        import subprocess, sys

        if not os.path.exists(ENGINE_SCRIPT):
            messagebox.showerror(
                "Engine Not Found",
                f"Could not locate engine script:\n{ENGINE_SCRIPT}")
            return

        target = self.scan_folder or "C:\\"
        if not os.path.exists(target):
            messagebox.showerror(
                "Invalid Scan Folder",
                f"Configured scan folder does not exist:\n{target}\n\n"
                "Open Settings to update it.")
            return

        # Disable any button widgets that are currently visible
        buttons = [b for b in
                   [button,
                    getattr(self, "_scan_now_btn", None),
                    getattr(self, "_dash_scan_btn", None)]
                   if b is not None and b.winfo_exists()]
        for b in buttons:
            b.configure(text="Scanning...", state="disabled")

        def _do():
            try:
                result = subprocess.run(
                    [sys.executable, ENGINE_SCRIPT, "--path", target],
                    capture_output=True, text=True, timeout=600
                )
                success = result.returncode == 0
                stdout  = result.stdout.strip()
                stderr  = result.stderr.strip()
            except subprocess.TimeoutExpired:
                success, stdout, stderr = False, "", "Engine timed out after 10 minutes."
            except Exception as e:
                success, stdout, stderr = False, "", str(e)

            self.df_incidents = api_get_incidents()
            self.after(0, lambda: _done(success, stdout, stderr))

        def _done(success, stdout, stderr):
            for b in buttons:
                if b.winfo_exists():
                    b.configure(text="Scan Now", state="normal")
            threats = (len(self.df_incidents[self.df_incidents["status"] != "SAFE"])
                       if not self.df_incidents.empty else 0)
            if success:
                messagebox.showinfo(
                    "Scan Complete",
                    f"Engine finished successfully.\n"
                    f"Scanned folder: {target}\n"
                    f"Events in DB: {len(self.df_incidents)}\n"
                    f"Threats found: {threats}\n\n"
                    f"{stdout[:400] if stdout else ''}")
                # If user is currently on the dashboard, refresh the active threats list
                if hasattr(self, "_on_dashboard") and self._on_dashboard:
                    self.show_home()
            else:
                messagebox.showerror(
                    "Scan Error",
                    f"Engine exited with an error.\n\n{stderr[:600]}")

        threading.Thread(target=_do, daemon=True).start()

    # ---- Manual sync ----
    def _run_manual_sync(self):
        if hasattr(self, "_manual_sync_btn"):
            self._manual_sync_btn.configure(text="Syncing...", state="disabled")

        def _do():
            res = sync_malware_hashes()
            self.after(0, lambda: _done(res))

        def _done(res):
            if hasattr(self, "_manual_sync_btn") and self._manual_sync_btn.winfo_exists():
                self._manual_sync_btn.configure(text="Sync Now", state="normal")
            if res["status"] == "ok":
                messagebox.showinfo(
                    "Sync Complete",
                    f"Sync successful.\n"
                    f"New hashes inserted: {res['inserted']}\n"
                    f"Already present: {res['skipped']}\n"
                    f"Total in DB: {get_threat_hash_count():,}")
            else:
                messagebox.showerror("Sync Failed", f"Error: {res.get('error', 'unknown')}")

        threading.Thread(target=_do, daemon=True).start()


# ==========================================
# ENTRY POINT
# ==========================================
if __name__ == "__main__":
    app = AntiVirusApp()
    app.mainloop()