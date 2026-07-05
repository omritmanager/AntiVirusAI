"""
gui.py — Desktop GUI (spec §11). Toolkit: PySide6 (Qt).

Design goals from the spec:
  * Folder picker + Scan button; live progress (count / current file / %).
  * Results table: file name, ML verdict (color-coded red/amber/green),
    "Signature match (SHA-256)" column, probability, path.
  * Summary card highlighting the ML-ONLY-CATCH count (the headline result).
  * Verdict filter (All / Malware only / ML-only catches).
  * Toggles: zero-day anomaly layer, skip system files, auto-quarantine,
    compare against signature DB.
  * Buttons: Open JSON report, Open quarantine folder, Restore selected.
  * Status bar shows the startup self-check result (green = verified).
  * NEVER freezes during a scan: the scan runs on a QThread; UI updates arrive
    via signals (Qt marshals them to the UI thread).

The exact same orchestrator/engine as the CLI is used — no duplicated inference.
"""
from __future__ import annotations

import os
import sys

from . import config

try:
    from PySide6 import QtCore, QtGui, QtWidgets
    HAVE_QT = True
    _IMPORT_ERR = None
except Exception as e:  # pragma: no cover - exercised only without PySide6
    HAVE_QT = False
    _IMPORT_ERR = e


if HAVE_QT:
    from .engine import MALWARE, POTENTIAL_ZERODAY, SAFE, ERROR, get_engine
    from .hashdb import HashDB, KNOWN_MALWARE
    from .orchestrator import scan_folder, ML_ONLY_CATCH
    from .quarantine import Quarantine
    from .selfcheck import run_selfcheck, status_line
    from . import report as report_mod

    VERDICT_COLORS = {
        MALWARE: QtGui.QColor("#f8d7da"),
        POTENTIAL_ZERODAY: QtGui.QColor("#fff3cd"),
        SAFE: QtGui.QColor("#d4edda"),
        ERROR: QtGui.QColor("#e2e3e5"),
    }

    class SelfCheckWorker(QtCore.QThread):
        done = QtCore.Signal(object)

        def run(self):
            self.done.emit(run_selfcheck(run_regression=True, verbose=False))

    class ScanWorker(QtCore.QThread):
        progress = QtCore.Signal(int, int, str)
        flagged = QtCore.Signal(object)
        finished_scan = QtCore.Signal(object)
        failed = QtCore.Signal(str)

        def __init__(self, folder, *, use_if, whitelist_enabled,
                     hash_compare, auto_quarantine):
            super().__init__()
            self.folder = folder
            self.use_if = use_if
            self.whitelist_enabled = whitelist_enabled
            self.hash_compare = hash_compare
            self.auto_quarantine = auto_quarantine

        def run(self):
            try:
                engine = get_engine(load_if=True)
                hash_db = HashDB(config.BASELINE_SQLITE) if self.hash_compare else None
                q = Quarantine() if self.auto_quarantine else None
                on_malware = q.quarantine_for_result if q else None
                scan = scan_folder(
                    self.folder,
                    engine=engine,
                    use_if=self.use_if,
                    whitelist_enabled=self.whitelist_enabled,
                    hash_db=hash_db,
                    hash_compare=self.hash_compare,
                    progress_cb=lambda i, t, p: self.progress.emit(i, t, str(p)),
                    flagged_cb=lambda fr: self.flagged.emit(fr),
                    on_malware=on_malware,
                )
                if hash_db:
                    hash_db.close()
                self.finished_scan.emit(scan)
            except Exception as e:  # never let the worker die silently
                self.failed.emit(f"{type(e).__name__}: {e}")

    class MainWindow(QtWidgets.QMainWindow):
        COLUMNS = ["File", "ML verdict", "Signature match (SHA-256)", "Probability", "Path"]

        def __init__(self):
            super().__init__()
            self.setWindowTitle("AntivirusAI V7")
            self.resize(1080, 680)
            self._results = []       # list[FileResult]
            self._scan = None
            self._report_path = None
            self._selfcheck_ok = False
            self._worker = None

            self._build_ui()
            self._run_selfcheck()

        # ── UI construction ──────────────────────────────────────────────────
        def _build_ui(self):
            central = QtWidgets.QWidget()
            self.setCentralWidget(central)
            root = QtWidgets.QVBoxLayout(central)

            # Folder picker row
            top = QtWidgets.QHBoxLayout()
            self.path_edit = QtWidgets.QLineEdit()
            self.path_edit.setPlaceholderText("Choose a folder to scan...")
            browse = QtWidgets.QPushButton("Browse...")
            browse.clicked.connect(self._browse)
            self.scan_btn = QtWidgets.QPushButton("Scan")
            self.scan_btn.clicked.connect(self._start_scan)
            self.scan_btn.setEnabled(False)
            top.addWidget(self.path_edit, 1)
            top.addWidget(browse)
            top.addWidget(self.scan_btn)
            root.addLayout(top)

            # Toggles
            tog = QtWidgets.QHBoxLayout()
            self.cb_if = QtWidgets.QCheckBox("Enable zero-day anomaly layer (experimental)")
            self.cb_white = QtWidgets.QCheckBox("Skip system files")
            self.cb_white.setChecked(True)
            self.cb_quar = QtWidgets.QCheckBox("Auto-quarantine malware")
            self.cb_quar.setChecked(True)
            self.cb_hash = QtWidgets.QCheckBox("Compare against signature DB")
            self.cb_hash.setChecked(True)
            for cb in (self.cb_if, self.cb_white, self.cb_quar, self.cb_hash):
                tog.addWidget(cb)
            tog.addStretch(1)
            root.addLayout(tog)

            # Summary card
            self.summary = QtWidgets.QLabel("No scan yet.")
            self.summary.setFrameShape(QtWidgets.QFrame.StyledPanel)
            self.summary.setStyleSheet(
                "QLabel { padding: 10px; background: #f4f6f8; border-radius: 6px; }")
            self.summary.setTextFormat(QtCore.Qt.RichText)
            root.addWidget(self.summary)

            # Filter + action buttons row
            mid = QtWidgets.QHBoxLayout()
            mid.addWidget(QtWidgets.QLabel("Show:"))
            self.filter_box = QtWidgets.QComboBox()
            self.filter_box.addItems(["All", "Malware only", "ML-only catches"])
            self.filter_box.currentIndexChanged.connect(self._refresh_table)
            mid.addWidget(self.filter_box)
            mid.addStretch(1)
            self.btn_report = QtWidgets.QPushButton("Open JSON report")
            self.btn_report.clicked.connect(self._open_report)
            self.btn_quar_dir = QtWidgets.QPushButton("Open quarantine folder")
            self.btn_quar_dir.clicked.connect(self._open_quarantine)
            self.btn_restore = QtWidgets.QPushButton("Restore selected")
            self.btn_restore.clicked.connect(self._restore_selected)
            self.btn_restore_all = QtWidgets.QPushButton("Restore All")
            self.btn_restore_all.clicked.connect(self._restore_all)
            self.btn_restore_all.setStyleSheet(
                "QPushButton { background-color: #f59e0b; color: #1a1a1a;"
                " font-weight: bold; }"
                " QPushButton:hover { background-color: #d97706; }")
            for b in (self.btn_report, self.btn_quar_dir, self.btn_restore,
                      self.btn_restore_all):
                mid.addWidget(b)
            root.addLayout(mid)

            # Results table
            self.table = QtWidgets.QTableWidget(0, len(self.COLUMNS))
            self.table.setHorizontalHeaderLabels(self.COLUMNS)
            self.table.horizontalHeader().setStretchLastSection(True)
            self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
            self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
            self.table.setColumnWidth(0, 220)
            self.table.setColumnWidth(1, 130)
            self.table.setColumnWidth(2, 200)
            self.table.setColumnWidth(3, 90)
            root.addWidget(self.table, 1)

            # Progress
            self.progress = QtWidgets.QProgressBar()
            self.progress.setTextVisible(True)
            self.cur_file = QtWidgets.QLabel("")
            root.addWidget(self.progress)
            root.addWidget(self.cur_file)

            # Status bar (self-check)
            self.status = self.statusBar()
            self.status.showMessage("Running startup self-check...")

        # ── self-check ───────────────────────────────────────────────────────
        def _run_selfcheck(self):
            self._sc_worker = SelfCheckWorker()
            self._sc_worker.done.connect(self._selfcheck_done)
            self._sc_worker.start()

        def _selfcheck_done(self, result):
            self._selfcheck_ok = result.ok
            msg = status_line(result)
            if result.ok:
                self.status.setStyleSheet("color: #137333;")  # green
                self.status.showMessage("✓ " + msg)
                self.scan_btn.setEnabled(True)
            else:
                self.status.setStyleSheet("color: #b00020;")  # red
                self.status.showMessage("✗ " + msg + " - scanning disabled")
                QtWidgets.QMessageBox.critical(
                    self, "Self-check failed",
                    "The environment self-check failed; scanning is blocked.\n\n"
                    + "\n".join(c.name for c in result.checks if not c.passed)
                    + "\n\nRun: python setup_environment.py")

        # ── scan flow ────────────────────────────────────────────────────────
        def _browse(self):
            d = QtWidgets.QFileDialog.getExistingDirectory(self, "Select folder to scan")
            if d:
                self.path_edit.setText(d)

        def _start_scan(self):
            folder = self.path_edit.text().strip()
            if not folder or not os.path.isdir(folder):
                QtWidgets.QMessageBox.warning(self, "No folder", "Choose a valid folder.")
                return
            if not self._selfcheck_ok:
                QtWidgets.QMessageBox.critical(self, "Blocked", "Self-check failed.")
                return
            self.scan_btn.setEnabled(False)
            self.table.setRowCount(0)
            self._results = []
            self.progress.setValue(0)
            self.summary.setText("Scanning...")
            self._worker = ScanWorker(
                folder,
                use_if=self.cb_if.isChecked(),
                whitelist_enabled=self.cb_white.isChecked(),
                hash_compare=self.cb_hash.isChecked(),
                auto_quarantine=self.cb_quar.isChecked(),
            )
            self._worker.progress.connect(self._on_progress)
            self._worker.finished_scan.connect(self._on_finished)
            self._worker.failed.connect(self._on_failed)
            self._worker.start()

        def _on_progress(self, i, total, path):
            self.progress.setMaximum(max(total, 1))
            self.progress.setValue(i)
            self.cur_file.setText(f"{i}/{total}  {os.path.basename(path)}")

        def _on_failed(self, msg):
            self.scan_btn.setEnabled(True)
            QtWidgets.QMessageBox.critical(self, "Scan failed", msg)

        def _on_finished(self, scan):
            self._scan = scan
            self._results = list(scan.results)
            try:
                self._report_path = report_mod.write_report(scan)
            except Exception:
                self._report_path = None
            self._update_summary(scan)
            self._refresh_table()
            self.scan_btn.setEnabled(True)
            self.cur_file.setText("Done.")

        # ── summary + table ──────────────────────────────────────────────────
        def _update_summary(self, scan):
            s = scan.summary
            ml_only = 0
            if scan.hash_comparison:
                ml_only = scan.hash_comparison.get("files", {}).get(ML_ONLY_CATCH, 0)
            self.summary.setText(
                f"<b>Scanned:</b> {s.scanned} &nbsp;|&nbsp; "
                f"<b style='color:#b00020'>MALWARE: {s.malware}</b> &nbsp;|&nbsp; "
                f"<b style='color:#a06a00'>POTENTIAL_ZERODAY: {s.potential_zeroday}</b> &nbsp;|&nbsp; "
                f"<b style='color:#137333'>SAFE: {s.safe}</b> &nbsp;|&nbsp; "
                f"Errors: {s.errors} &nbsp;|&nbsp; Skipped: {s.skipped_system}"
                f"<br><span style='font-size:15px'><b>ML-only catches "
                f"(missed by SHA-256 signatures): {ml_only}</b></span>")

        def _row_passes_filter(self, fr):
            mode = self.filter_box.currentIndex()
            if mode == 1:  # Malware only
                return fr.ml_verdict == MALWARE
            if mode == 2:  # ML-only catches
                return fr.comparison_tag == ML_ONLY_CATCH
            return True

        def _refresh_table(self):
            self.table.setRowCount(0)
            for fr in self._results:
                if not self._row_passes_filter(fr):
                    continue
                row = self.table.rowCount()
                self.table.insertRow(row)
                prob = "" if fr.lgbm_prob is None else f"{fr.lgbm_prob * 100:.1f}%"
                sig = fr.hash_verdict or "-"
                cells = [fr.name, fr.ml_verdict, sig, prob, fr.path]
                for col, text in enumerate(cells):
                    item = QtWidgets.QTableWidgetItem(text)
                    if col == 1 and fr.ml_verdict in VERDICT_COLORS:
                        item.setBackground(VERDICT_COLORS[fr.ml_verdict])
                    if col == 2 and fr.hash_verdict == KNOWN_MALWARE:
                        item.setBackground(QtGui.QColor("#ffe0b2"))
                    item.setData(QtCore.Qt.UserRole, fr)
                    self.table.setItem(row, col, item)

        # ── action buttons ───────────────────────────────────────────────────
        def _open_report(self):
            if self._report_path and os.path.exists(self._report_path):
                self._open_path(str(self._report_path))
            else:
                QtWidgets.QMessageBox.information(self, "No report", "Run a scan first.")

        def _open_quarantine(self):
            config.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
            self._open_path(str(config.QUARANTINE_DIR))

        def _restore_selected(self):
            rows = {i.row() for i in self.table.selectedIndexes()}
            if not rows:
                QtWidgets.QMessageBox.information(self, "Restore", "Select a row first.")
                return
            q = Quarantine()
            restored, errors = [], []
            for r in rows:
                item = self.table.item(r, 0)
                fr = item.data(QtCore.Qt.UserRole) if item else None
                if not fr or not fr.quarantined or not fr.sha256:
                    continue
                try:
                    restored += q.restore(fr.sha256)
                except Exception as e:
                    errors.append(str(e))
            msg = f"Restored {len(restored)} file(s)."
            if errors:
                msg += "\nErrors:\n" + "\n".join(errors)
            QtWidgets.QMessageBox.information(self, "Restore", msg)

        def _restore_all(self):
            q = Quarantine()
            n = len(q.entries())
            if n == 0:
                QtWidgets.QMessageBox.information(
                    self, "Restore All", "Quarantine is empty - nothing to restore.")
                return
            confirm = QtWidgets.QMessageBox.warning(
                self, "Restore All Quarantined Files",
                f"You are about to restore ALL {n} quarantined file(s) to their "
                f"original locations.\n\nOnly proceed if you have verified they "
                f"are safe. Continue?",
                QtWidgets.QMessageBox.StandardButton.Yes
                | QtWidgets.QMessageBox.StandardButton.Cancel,
                QtWidgets.QMessageBox.StandardButton.Cancel)
            if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
                return
            # Quarantine.restore("all") restores every entry; the count that did
            # not come back is the failure count.
            try:
                restored = q.restore("all")
                failed = n - len(restored)
            except Exception:
                restored, failed = [], n
            QtWidgets.QMessageBox.information(
                self, "Restore All",
                f"Restored {len(restored)} file(s).\nFailed: {failed} file(s).")

        @staticmethod
        def _open_path(path):
            try:
                if sys.platform.startswith("win"):
                    os.startfile(path)  # noqa: S606
                elif sys.platform == "darwin":
                    os.system(f'open "{path}"')
                else:
                    os.system(f'xdg-open "{path}"')
            except Exception:
                pass


def main(argv=None) -> int:
    if not HAVE_QT:
        print("The GUI requires PySide6, which is not installed.")
        print("Install it with:  pip install PySide6")
        print(f"(import error: {_IMPORT_ERR})")
        return 1
    app = QtWidgets.QApplication(sys.argv if argv is None else argv)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
