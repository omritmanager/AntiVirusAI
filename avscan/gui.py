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

Presentation is driven entirely by theme.py (palette + QSS + verdict badges),
so colours are defined once and shared with the Tk quick-scan popup.

The exact same orchestrator/engine as the CLI is used — no duplicated inference.
"""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

from . import config, explain, signature, theme

try:
    from PySide6 import QtCore, QtGui, QtWidgets
    HAVE_QT = True
    _IMPORT_ERR = None
except Exception as e:  # pragma: no cover - exercised only without PySide6
    HAVE_QT = False
    _IMPORT_ERR = e


if HAVE_QT:
    from .engine import MALWARE, SAFE, ERROR, get_engine
    from .hashdb import HashDB, KNOWN_MALWARE, NOT_IN_DB
    from .orchestrator import scan_folder, ML_ONLY_CATCH
    from .quarantine import Quarantine
    from .selfcheck import run_selfcheck, status_line
    from . import report as report_mod

    class SelfCheckWorker(QtCore.QThread):
        done = QtCore.Signal(object)

        def run(self):
            self.done.emit(run_selfcheck(run_regression=True, verbose=False))

    class ScanWorker(QtCore.QThread):
        progress = QtCore.Signal(int, int, str)
        result = QtCore.Signal(object)      # fired for every scanned file, live
        flagged = QtCore.Signal(object)
        finished_scan = QtCore.Signal(object)
        failed = QtCore.Signal(str)

        def __init__(self, folder, *, whitelist_enabled,
                     hash_compare, auto_quarantine):
            super().__init__()
            self.folder = folder
            self.whitelist_enabled = whitelist_enabled
            self.hash_compare = hash_compare
            self.auto_quarantine = auto_quarantine

        def run(self):
            try:
                engine = get_engine()
                hash_db = HashDB(config.BASELINE_SQLITE) if self.hash_compare else None
                q = Quarantine() if self.auto_quarantine else None
                on_malware = q.quarantine_for_result if q else None
                scan = scan_folder(
                    self.folder,
                    engine=engine,
                    whitelist_enabled=self.whitelist_enabled,
                    hash_db=hash_db,
                    hash_compare=self.hash_compare,
                    progress_cb=lambda i, t, p: self.progress.emit(i, t, str(p)),
                    result_cb=lambda fr: self.result.emit(fr),
                    flagged_cb=lambda fr: self.flagged.emit(fr),
                    on_malware=on_malware,
                )
                if hash_db:
                    hash_db.close()
                self.finished_scan.emit(scan)
            except Exception as e:  # never let the worker die silently
                self.failed.emit(f"{type(e).__name__}: {e}")

    class ExplainWorker(QtCore.QThread):
        """Calls the Gemini "why" layer for one already-scanned file.

        Re-reads the file from disk (FileResult doesn't keep the bytes around
        after a scan) and reuses the verdict/probability the scan already
        computed — this explains the SAME result the table shows, rather than
        silently re-classifying and risking an explanation of a different
        outcome (e.g. if the file changed on disk since the scan).
        """
        done = QtCore.Signal(dict)
        failed = QtCore.Signal(str)

        def __init__(self, fr):
            super().__init__()
            self.fr = fr

        def run(self):
            try:
                with open(self.fr.path, "rb") as f:
                    data = f.read()
            except Exception as e:
                self.failed.emit(f"Could not read the file: {e}")
                return
            try:
                engine = get_engine()
                ml_result = SimpleNamespace(
                    ml_verdict=self.fr.ml_verdict, lgbm_prob=self.fr.lgbm_prob,
                    error=self.fr.error)
                # Local evidence/vector are free to compute for ANY row (that is
                # what feeds the "all parameters" section and the raw-data
                # toggle below); only the Gemini call itself stays reserved for
                # MALWARE rows. build_prompt() is worded "why was this
                # blocked/flagged" — sending that for a SAFE row would ask
                # Gemini to justify something that never happened. Forcing
                # explain_enabled=False makes explain_bytes() stop right after
                # the local summary, same as if the user had disabled Gemini.
                settings = dict(config.load_settings())
                if self.fr.ml_verdict != MALWARE:
                    settings["explain_enabled"] = False
                result = explain.explain_bytes(
                    engine, data, ml_result, settings=settings,
                    hash_verdict=self.fr.hash_verdict,
                    quarantined=self.fr.quarantined,
                    signature_status=self.fr.signature_status,
                    signature_signer=self.fr.signature_signer,
                )
                self.done.emit(result)
            except Exception as e:  # never let the worker die silently
                self.failed.emit(f"{type(e).__name__}: {e}")

    class ModelSwitchWorker(QtCore.QThread):
        """Loads a newly selected model and re-runs the regression gate on it.

        The gate is the whole point of doing this off the main thread: it scores
        the full held-out test set, which takes seconds, and it is what stops a
        broken candidate from being scanned with. Verifying at SELECTION time
        means the user learns the model is bad immediately, instead of halfway
        through a real scan.
        """
        done = QtCore.Signal(str, float, bool)   # detail, f1, passed
        failed = QtCore.Signal(str)

        def __init__(self, model_path, threshold):
            super().__init__()
            self.model_path = model_path
            self.threshold = threshold

        def run(self):
            try:
                from . import selfcheck
                from .engine import reset_engine

                config.LGBM_PATH = self.model_path
                config.LGBM_THRESHOLD = self.threshold
                reset_engine()          # force the next scan to load this model

                check, f1 = selfcheck.check_regression()
                # Surface the load error itself rather than a bare gate failure.
                get_engine()
                self.done.emit(check.detail, f1 if f1 is not None else float("nan"),
                               bool(check.passed))
            except Exception as e:
                self.failed.emit(f"{type(e).__name__}: {e}")

    class ExplainDialog(QtWidgets.QDialog):
        """Shows the Gemini (or local-fallback) explanation for one file."""

        def __init__(self, parent, file_name: str, result: dict):
            super().__init__(parent)
            self.setWindowTitle(f"Why flagged — {file_name}")
            self.resize(560, 620)
            lay = QtWidgets.QVBoxLayout(self)

            text_box = QtWidgets.QPlainTextEdit()
            text_box.setReadOnly(True)
            text_box.setPlainText(result.get("summary") or "(no explanation available)")
            lay.addWidget(text_box, 1)

            status = result.get("status")
            if status and status != "ok":
                note = QtWidgets.QLabel(explain.status_message(status, "he"))
                note.setObjectName("CurrentFile")
                note.setWordWrap(True)
                lay.addWidget(note)

            # Every measurement collected, not just the 2-4 points the summary
            # above chose to mention — the raw material the AI/local summary
            # was built from.
            all_label = QtWidgets.QLabel("כל הפרמטרים שנאספו מהקובץ:")
            all_label.setObjectName("SectionLabel")
            lay.addWidget(all_label)
            evidence_box = QtWidgets.QPlainTextEdit()
            evidence_box.setReadOnly(True)
            evidence_box.setPlainText(
                explain.format_all_evidence(result.get("evidence") or [],
                                            result.get("top_groups") or [], "he"))
            lay.addWidget(evidence_box, 1)

            # Raw feature vector (2381 numbers, grouped) — hidden by default:
            # it is a wall of numbers with real value only on demand, so it
            # does not compete with the readable sections above for attention.
            raw_label = QtWidgets.QLabel("הווקטור הגולמי (2381 המספרים שהמודל ראה):")
            raw_label.setObjectName("SectionLabel")
            raw_box = QtWidgets.QPlainTextEdit()
            raw_box.setReadOnly(True)
            raw_box.setFont(QtGui.QFont("Consolas", 9))
            raw_box.setPlainText(
                explain.format_raw_vector(result.get("vector"), "he"))
            raw_label.setVisible(False)
            raw_box.setVisible(False)
            lay.addWidget(raw_label)
            lay.addWidget(raw_box, 2)

            btnbar = QtWidgets.QHBoxLayout()
            copy_btn = QtWidgets.QPushButton("Copy")
            copy_btn.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            copy_btn.clicked.connect(
                lambda: QtWidgets.QApplication.clipboard().setText(text_box.toPlainText()))
            raw_btn = QtWidgets.QPushButton("הצג נתונים גולמיים")
            raw_btn.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            has_vector = bool(result.get("vector"))
            raw_btn.setEnabled(has_vector)
            if not has_vector:
                raw_btn.setToolTip("לא חולצו נתונים גולמיים עבור קובץ זה")

            def _toggle_raw():
                showing = not raw_box.isVisible()
                raw_label.setVisible(showing)
                raw_box.setVisible(showing)
                raw_btn.setText("הסתר נתונים גולמיים" if showing else "הצג נתונים גולמיים")
                if showing:
                    self.resize(self.width(), max(self.height(), 780))

            raw_btn.clicked.connect(_toggle_raw)
            close_btn = QtWidgets.QPushButton("Close")
            close_btn.setObjectName("Primary")
            close_btn.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            close_btn.clicked.connect(self.accept)
            btnbar.addWidget(copy_btn)
            btnbar.addWidget(raw_btn)
            btnbar.addStretch(1)
            btnbar.addWidget(close_btn)
            lay.addLayout(btnbar)

    # ── Presentation widgets ────────────────────────────────────────────────
    class BadgeDelegate(QtWidgets.QStyledItemDelegate):
        """Paints the verdict column as a rounded pill.

        The verdict to draw is read from UserRole+1 so the cell's plain text
        stays intact for copy/paste and for tests that read the model.
        """
        ROLE = QtCore.Qt.ItemDataRole.UserRole + 1

        def __init__(self, mode: str, parent=None):
            super().__init__(parent)
            self.mode = mode

        def paint(self, painter, option, index):
            verdict = index.data(self.ROLE)
            if not verdict:
                super().paint(painter, option, index)
                return
            p = theme.palette(self.mode)
            b = theme.badge(verdict, self.mode)
            painter.save()
            painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing, True)
            if option.state & QtWidgets.QStyle.StateFlag.State_Selected:
                painter.fillRect(option.rect, QtGui.QColor(p["selection"]))
            font = QtGui.QFont(option.font)
            font.setBold(True)
            font.setPointSizeF(max(7.5, font.pointSizeF() - 1.5))
            painter.setFont(font)
            fm = QtGui.QFontMetrics(font)
            w = fm.horizontalAdvance(b["label"]) + 22
            h = 21
            rect = QtCore.QRectF(option.rect.left() + 10,
                                 option.rect.center().y() - h / 2 + 1, w, h)
            painter.setPen(QtCore.Qt.PenStyle.NoPen)
            painter.setBrush(QtGui.QColor(b["bg"]))
            painter.drawRoundedRect(rect, h / 2, h / 2)
            painter.setPen(QtGui.QColor(b["fg"]))
            painter.drawText(rect, QtCore.Qt.AlignmentFlag.AlignCenter, b["label"])
            painter.restore()

        def sizeHint(self, option, index):
            s = super().sizeHint(option, index)
            return QtCore.QSize(s.width(), max(s.height(), 34))

    class StatCard(QtWidgets.QFrame):
        """A single headline number, a caption, and an optional small breakdown
        line underneath (e.g. "312 unsigned") — set via `sub` in set_value()."""

        def __init__(self, label: str, accent_key: str = "text", parent=None):
            super().__init__(parent)
            self.setObjectName("Card")
            self.accent_key = accent_key
            lay = QtWidgets.QVBoxLayout(self)
            lay.setContentsMargins(14, 10, 14, 10)
            lay.setSpacing(0)
            self.value = QtWidgets.QLabel("—")
            self.value.setObjectName("StatValue")
            self.caption = QtWidgets.QLabel(label.upper())
            self.caption.setObjectName("StatLabel")
            self.sub = QtWidgets.QLabel("")
            self.sub.setObjectName("StatSub")
            lay.addWidget(self.value)
            lay.addWidget(self.caption)
            lay.addWidget(self.sub)

        def set_value(self, n, mode: str, sub: str | None = None):
            self.value.setText(str(n))
            colour = theme.palette(mode)[self.accent_key]
            self.value.setStyleSheet(f"color: {colour};")
            if sub is not None:
                self.sub.setText(sub)

    class MainWindow(QtWidgets.QMainWindow):
        COLUMNS = ["File", "Verdict", "Confidence",
                   "Signature match (SHA-256)", "Path"]

        def __init__(self, mode: str = theme.DEFAULT_MODE):
            super().__init__()
            self.setWindowTitle("AntivirusAI V7")
            self.resize(1180, 760)
            self._mode = mode
            self._results = []       # list[FileResult]
            self._scan = None
            self._report_path = None
            self._selfcheck_ok = False
            self._worker = None
            self._explain_worker = None
            self._model_worker = None
            self._sort_col = None
            self._sort_reverse = False
            self._pending_live = []          # FileResults not yet flushed to the table
            self._live_counts = dict(scanned=0, malware=0, malware_unsigned=0,
                                     safe=0, safe_verified=0)
            self._live_flush = QtCore.QTimer(self)
            self._live_flush.setInterval(150)
            self._live_flush.timeout.connect(self._flush_live_results)

            self._build_ui()
            self._apply_theme()
            self._run_selfcheck()

        # ── UI construction ──────────────────────────────────────────────────
        def _build_ui(self):
            central = QtWidgets.QWidget()
            self.setCentralWidget(central)
            outer = QtWidgets.QVBoxLayout(central)
            outer.setContentsMargins(0, 0, 0, 0)
            outer.setSpacing(0)

            outer.addWidget(self._build_header())

            body = QtWidgets.QWidget()
            root = QtWidgets.QVBoxLayout(body)
            root.setContentsMargins(18, 16, 18, 14)
            root.setSpacing(14)
            outer.addWidget(body, 1)

            root.addWidget(self._build_scan_card())
            root.addLayout(self._build_stats_row())
            root.addLayout(self._build_toolbar())
            root.addWidget(self._build_table(), 1)
            root.addLayout(self._build_progress())

            self.status = self.statusBar()
            self.status.showMessage("Running startup self-check…")

        def _build_header(self):
            bar = QtWidgets.QFrame()
            bar.setObjectName("HeaderBar")
            lay = QtWidgets.QHBoxLayout(bar)
            lay.setContentsMargins(18, 12, 18, 12)
            lay.setSpacing(12)

            title_box = QtWidgets.QVBoxLayout()
            title_box.setSpacing(1)
            title = QtWidgets.QLabel("🛡  AntivirusAI V7")
            title.setObjectName("AppTitle")
            sub = QtWidgets.QLabel("Machine-learning PE malware detection")
            sub.setObjectName("AppSubtitle")
            title_box.addWidget(title)
            title_box.addWidget(sub)
            lay.addLayout(title_box)
            lay.addStretch(1)

            self.health_pill = QtWidgets.QLabel("checking…")
            self.health_pill.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            lay.addWidget(self.health_pill)

            self.theme_btn = QtWidgets.QPushButton()
            self.theme_btn.setObjectName("IconButton")
            self.theme_btn.setToolTip("Toggle light / dark theme")
            self.theme_btn.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.theme_btn.clicked.connect(self._toggle_theme)
            lay.addWidget(self.theme_btn)
            return bar

        def _build_scan_card(self):
            card = QtWidgets.QFrame()
            card.setObjectName("Card")
            lay = QtWidgets.QVBoxLayout(card)
            lay.setContentsMargins(16, 14, 16, 14)
            lay.setSpacing(11)

            heading = QtWidgets.QLabel("SCAN TARGET")
            heading.setObjectName("SectionLabel")
            lay.addWidget(heading)

            row = QtWidgets.QHBoxLayout()
            row.setSpacing(9)
            self.path_edit = QtWidgets.QLineEdit()
            self.path_edit.setPlaceholderText("Choose a folder to scan…")
            self.path_edit.setClearButtonEnabled(True)
            browse = QtWidgets.QPushButton("Browse")
            browse.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            browse.clicked.connect(self._browse)
            self.scan_btn = QtWidgets.QPushButton("Scan")
            self.scan_btn.setObjectName("Primary")
            self.scan_btn.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.scan_btn.clicked.connect(self._start_scan)
            self.scan_btn.setEnabled(False)
            row.addWidget(self.path_edit, 1)
            row.addWidget(browse)
            row.addWidget(self.scan_btn)
            lay.addLayout(row)

            tog = QtWidgets.QHBoxLayout()
            tog.setSpacing(18)
            self.cb_white = QtWidgets.QCheckBox("Skip system files")
            self.cb_white.setChecked(True)
            self.cb_quar = QtWidgets.QCheckBox("Auto-quarantine malware")
            self.cb_hash = QtWidgets.QCheckBox("Compare against signature DB")
            self.cb_hash.setChecked(True)
            for cb in (self.cb_white, self.cb_quar, self.cb_hash):
                cb.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
                tog.addWidget(cb)
            tog.addStretch(1)
            lay.addLayout(tog)

            lay.addLayout(self._build_model_row())
            return card

        # ── model picker ─────────────────────────────────────────────────────
        @staticmethod
        def _discover_models():
            """(label, path, default_threshold) for every selectable LightGBM model.

            Only lgbm_*.pkl files are offered: lgbm_v7.pkl is the leaky model
            the engine refuses to load (spec §3), so it doesn't belong in a picker.
            """
            out = []
            for p in sorted(config.MODELS_DIR.glob("lgbm_*.pkl")):
                if p.name == "lgbm_v7.pkl":
                    continue
                if p.name == "lgbm_v7_correct.pkl":
                    label, thr = f"{p.name}  (production)", config.DEFAULT_LGBM_THRESHOLD
                elif "candidate" in p.name and "broken" not in p.name:
                    # 0.225 is the recall-matched operating point for the
                    # augmented candidate; at the production 0.40 it looks worse
                    # than it is purely because of where the threshold sits.
                    label, thr = f"{p.name}  (candidate)", 0.225
                else:
                    label, thr = p.name, config.DEFAULT_LGBM_THRESHOLD
                out.append((label, p, thr))
            return out

        def _build_model_row(self):
            row = QtWidgets.QHBoxLayout()
            row.setSpacing(9)
            lbl = QtWidgets.QLabel("MODEL")
            lbl.setObjectName("SectionLabel")
            row.addWidget(lbl)

            self._models = self._discover_models()
            self.model_box = QtWidgets.QComboBox()
            self.model_box.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.model_box.setToolTip(
                "Which trained model to scan with. Switching re-runs the "
                "regression gate on the held-out test set before the model is "
                "used, so a broken model is refused rather than silently trusted.")
            for label, _p, _t in self._models:
                self.model_box.addItem(label)
            # Preselect whatever config actually resolved to (honours AVSCAN_MODEL).
            for i, (_l, p, _t) in enumerate(self._models):
                if p == config.LGBM_PATH:
                    self.model_box.setCurrentIndex(i)
                    break
            row.addWidget(self.model_box, 1)

            thr_lbl = QtWidgets.QLabel("Threshold")
            thr_lbl.setObjectName("CurrentFile")
            row.addWidget(thr_lbl)
            self.thr_spin = QtWidgets.QDoubleSpinBox()
            self.thr_spin.setDecimals(3)
            self.thr_spin.setSingleStep(0.005)
            self.thr_spin.setRange(0.001, 0.999)
            self.thr_spin.setValue(float(config.LGBM_THRESHOLD))
            self.thr_spin.setToolTip(
                "Probability above which a file counts as malware. Comparing two "
                "models at different thresholds is not apples-to-apples — match "
                "the recall first.")
            row.addWidget(self.thr_spin)

            self.model_status = QtWidgets.QLabel("")
            self.model_status.setObjectName("CurrentFile")
            row.addWidget(self.model_status, 1)

            # Connected last so the initial setCurrentIndex/setValue above do not
            # trigger a spurious model switch during construction.
            self.model_box.currentIndexChanged.connect(self._on_model_changed)
            self.thr_spin.valueChanged.connect(self._on_model_changed)
            return row

        def _on_model_changed(self, *_):
            if self._model_worker is not None and self._model_worker.isRunning():
                return
            idx = self.model_box.currentIndex()
            if not (0 <= idx < len(self._models)):
                return
            label, path, default_thr = self._models[idx]

            # Selecting a different model adopts that model's own operating
            # point; editing the spinbox directly keeps whatever was typed.
            if self.sender() is self.model_box:
                self.thr_spin.blockSignals(True)
                self.thr_spin.setValue(default_thr)
                self.thr_spin.blockSignals(False)

            self.model_box.setEnabled(False)
            self.thr_spin.setEnabled(False)
            self.scan_btn.setEnabled(False)
            self.model_status.setText("verifying…")
            self.status.showMessage(f"Loading {path.name} and re-running the regression gate…")

            self._model_worker = ModelSwitchWorker(path, float(self.thr_spin.value()))
            self._model_worker.done.connect(self._on_model_ready)
            self._model_worker.failed.connect(self._on_model_failed)
            self._model_worker.start()

        def _on_model_ready(self, detail, f1, passed):
            self.model_box.setEnabled(True)
            self.thr_spin.setEnabled(True)
            # Matches the app's own rule: the startup self-check owns whether
            # scanning is allowed at all (the path is validated in _start_scan).
            self.scan_btn.setEnabled(self._selfcheck_ok)
            mark = "✓" if passed else "✗"
            self.model_status.setText(f"{mark} F1={f1:.4f}")
            self.model_status.setToolTip(detail)
            self.status.showMessage(f"{config.LGBM_PATH.name}: {detail}", 12000)
            if not passed:
                # Mirrors the startup self-check contract: a model that fails the
                # regression gate must not be quietly scanned with.
                self.scan_btn.setEnabled(False)
                QtWidgets.QMessageBox.critical(
                    self, "Model failed the regression gate",
                    f"{config.LGBM_PATH.name} did not pass:\n\n{detail}\n\n"
                    "Scanning is blocked with this model. Pick another one.")

        def _on_model_failed(self, msg):
            self.model_box.setEnabled(True)
            self.thr_spin.setEnabled(True)
            self.scan_btn.setEnabled(False)   # unknown model state — fail closed
            self.model_status.setText("✗ load failed")
            self.model_status.setToolTip(msg)
            QtWidgets.QMessageBox.critical(self, "Could not load model", msg)

        def _build_stats_row(self):
            row = QtWidgets.QHBoxLayout()
            row.setSpacing(11)
            self.card_scanned = StatCard("Scanned", "text")
            self.card_malware = StatCard("Malware", "danger")
            self.card_safe = StatCard("Safe", "success")
            self._cards = [self.card_scanned, self.card_malware, self.card_safe]
            self.card_malware.setToolTip(
                "Every file the model flagged, including ones shown green in "
                "the table because they carry a trusted signature. The small "
                "number below is how many of these are NOT signed — those are "
                "the ones with no independent counter-signal at all.")
            self.card_safe.setToolTip(
                "Every file the model judged clean. The small number below is "
                "how many of these are also independently corroborated: either "
                "a trusted Authenticode signature, or a SHA-256 that was "
                "checked against the known-malware database and NOT found there.")
            for c in self._cards:
                row.addWidget(c, 1)
            return row

        def _build_toolbar(self):
            mid = QtWidgets.QHBoxLayout()
            mid.setSpacing(9)
            show = QtWidgets.QLabel("SHOW")
            show.setObjectName("SectionLabel")
            mid.addWidget(show)
            self.filter_box = QtWidgets.QComboBox()
            self.filter_box.addItems(["All results", "Malware only", "ML-only catches"])
            self.filter_box.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.filter_box.currentIndexChanged.connect(self._refresh_table)
            mid.addWidget(self.filter_box)
            self.result_count = QtWidgets.QLabel("")
            self.result_count.setObjectName("CurrentFile")
            mid.addWidget(self.result_count)
            mid.addStretch(1)

            self.btn_report = QtWidgets.QPushButton("JSON report")
            self.btn_report.clicked.connect(self._open_report)
            self.btn_quar_dir = QtWidgets.QPushButton("Quarantine folder")
            self.btn_quar_dir.clicked.connect(self._open_quarantine)
            self.btn_explain = QtWidgets.QPushButton("Explain")
            self.btn_explain.setToolTip(
                "Ask Gemini why the selected file got its verdict")
            self.btn_explain.clicked.connect(self._explain_selected)
            self.btn_restore = QtWidgets.QPushButton("Restore selected")
            self.btn_restore.clicked.connect(self._restore_selected)
            self.btn_restore_all = QtWidgets.QPushButton("Restore all")
            self.btn_restore_all.setObjectName("Danger")
            self.btn_restore_all.clicked.connect(self._restore_all)
            for b in (self.btn_report, self.btn_quar_dir, self.btn_explain,
                      self.btn_restore, self.btn_restore_all):
                b.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
                mid.addWidget(b)
            return mid

        def _build_table(self):
            self.table = QtWidgets.QTableWidget(0, len(self.COLUMNS))
            self.table.setHorizontalHeaderLabels(self.COLUMNS)
            self.table.horizontalHeader().setStretchLastSection(True)
            self.table.horizontalHeader().setHighlightSections(False)
            self.table.horizontalHeader().setSectionsClickable(True)
            # Shown only once the user actually clicks a header — Qt defaults to
            # painting an arrow on section 0 the moment this is enabled, which
            # would falsely claim a sort is active before one has been chosen.
            self.table.horizontalHeader().setSortIndicatorShown(False)
            self.table.horizontalHeader().sectionClicked.connect(self._on_header_clicked)
            self.table.setSelectionBehavior(
                QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
            self.table.setEditTriggers(
                QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
            self.table.setShowGrid(False)
            self.table.setAlternatingRowColors(False)
            self.table.verticalHeader().setVisible(False)
            self.table.verticalHeader().setDefaultSectionSize(34)
            self.table.setColumnWidth(0, 230)
            self.table.setColumnWidth(1, 120)
            self.table.setColumnWidth(2, 95)
            self.table.setColumnWidth(3, 330)   # fits "Signed: X · ML: MALWARE"
            self.badge_delegate = BadgeDelegate(self._mode, self.table)
            self.table.setItemDelegateForColumn(1, self.badge_delegate)
            self.table.setContextMenuPolicy(
                QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
            self.table.customContextMenuRequested.connect(self._show_row_context_menu)
            return self.table

        def _build_progress(self):
            box = QtWidgets.QVBoxLayout()
            box.setSpacing(5)
            self.progress = QtWidgets.QProgressBar()
            self.progress.setTextVisible(False)
            self.progress.setVisible(False)
            self.cur_file = QtWidgets.QLabel("Ready.")
            self.cur_file.setObjectName("CurrentFile")
            box.addWidget(self.progress)
            box.addWidget(self.cur_file)
            return box

        # ── theming ──────────────────────────────────────────────────────────
        def _apply_theme(self):
            app = QtWidgets.QApplication.instance()
            if app is not None:
                app.setStyleSheet(theme.stylesheet(self._mode))
            self.theme_btn.setText("☀" if self._mode == "dark" else "☾")
            self.badge_delegate.mode = self._mode
            self._paint_health_pill()
            self._refresh_stat_colours()
            self._refresh_table()

        def _toggle_theme(self):
            self._mode = "light" if self._mode == "dark" else "dark"
            self._apply_theme()

        def _paint_health_pill(self, text: str = None, key: str = None):
            """Self-check state as a coloured pill in the header."""
            if text is not None:
                self._pill_text, self._pill_key = text, key
            text = getattr(self, "_pill_text", "checking…")
            key = getattr(self, "_pill_key", "neutral")
            p = theme.palette(self._mode)
            self.health_pill.setText(text)
            self.health_pill.setStyleSheet(
                f"color: {p[key]}; background: {p[key + '_bg']};"
                f" border-radius: 11px; padding: 4px 12px;"
                f" font-size: 11px; font-weight: 600;")

        def _refresh_stat_colours(self):
            for c in getattr(self, "_cards", []):
                c.set_value(c.value.text(), self._mode)

        # ── self-check ───────────────────────────────────────────────────────
        def _run_selfcheck(self):
            self._sc_worker = SelfCheckWorker()
            self._sc_worker.done.connect(self._selfcheck_done)
            self._sc_worker.start()

        def _selfcheck_done(self, result):
            self._selfcheck_ok = result.ok
            msg = status_line(result)
            if result.ok:
                self._paint_health_pill("✓  Environment verified", "success")
                self.status.showMessage(msg)
                self.scan_btn.setEnabled(True)
            else:
                self._paint_health_pill("✗  Self-check failed", "danger")
                self.status.showMessage(msg + " — scanning disabled")
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
            self.scan_btn.setText("Scanning…")
            self.table.setRowCount(0)
            self._results = []
            self._pending_live = []
            self._live_counts = dict(scanned=0, malware=0, malware_unsigned=0,
                                     safe=0, safe_verified=0)
            for card in self._cards:
                card.set_value(0, self._mode)
            self.progress.setValue(0)
            self.progress.setVisible(True)
            self.cur_file.setText("Starting…")
            self._worker = ScanWorker(
                folder,
                whitelist_enabled=self.cb_white.isChecked(),
                hash_compare=self.cb_hash.isChecked(),
                auto_quarantine=self.cb_quar.isChecked(),
            )
            self._worker.progress.connect(self._on_progress)
            self._worker.result.connect(self._on_result_live)
            self._worker.finished_scan.connect(self._on_finished)
            self._worker.failed.connect(self._on_failed)
            self._worker.start()
            self._live_flush.start()

        def _on_progress(self, i, total, path):
            self.progress.setMaximum(max(total, 1))
            self.progress.setValue(i)
            pct = (i / total * 100) if total else 0
            self.cur_file.setText(f"{i}/{total} · {pct:.0f}%  ·  {os.path.basename(path)}")

        def _reset_scan_button(self):
            self.scan_btn.setEnabled(True)
            self.scan_btn.setText("Scan")
            self.progress.setVisible(False)

        def _on_failed(self, msg):
            self._live_flush.stop()
            self._flush_live_results()
            self._reset_scan_button()
            self.cur_file.setText("Scan failed.")
            QtWidgets.QMessageBox.critical(self, "Scan failed", msg)

        def _on_finished(self, scan):
            self._live_flush.stop()
            self._scan = scan
            self._results = list(scan.results)
            try:
                self._report_path = report_mod.write_report(scan)
            except Exception:
                self._report_path = None
            self._update_summary(scan)
            self._refresh_table()
            self._reset_scan_button()
            self.cur_file.setText(
                f"Done — {scan.summary.scanned} file(s) in "
                f"{scan.duration_seconds:.1f}s.")

        # ── live dashboard updates ──────────────────────────────────────────
        def _on_result_live(self, fr):
            """Runs on the UI thread for every scanned file (Qt queues cross-
            thread signals onto the receiver's thread automatically). Only the
            cheap bookkeeping happens here; the table/cards repaint on a timer
            (_flush_live_results) so a scan of thousands of tiny files cannot
            flood the UI with per-file layout passes.
            """
            self._results.append(fr)
            self._pending_live.append(fr)
            c = self._live_counts
            c["scanned"] += 1
            if fr.ml_flagged:                     # MALWARE or ERROR (fail-closed)
                c["malware"] += 1
                if fr.signature_status != signature.TRUSTED:
                    c["malware_unsigned"] += 1
            elif fr.ml_verdict == SAFE:
                c["safe"] += 1
                if fr.signature_status == signature.TRUSTED or fr.hash_verdict == NOT_IN_DB:
                    c["safe_verified"] += 1

        def _flush_live_results(self):
            if not self._pending_live:
                return
            batch, self._pending_live = self._pending_live, []
            # A sort is active: a mid-scan append would land the new rows out
            # of order at the bottom, so re-sort the whole (still filtered)
            # result set instead of appending piecemeal.
            if self._sort_col is not None:
                self._refresh_table()
            else:
                for fr in batch:
                    if self._row_passes_filter(fr):
                        self._append_row(fr)
                self._update_result_count()
            c = self._live_counts
            self.card_scanned.set_value(c["scanned"], self._mode)
            self.card_malware.set_value(c["malware"], self._mode,
                                        sub=f"{c['malware_unsigned']} unsigned")
            self.card_safe.set_value(c["safe"], self._mode,
                                     sub=f"{c['safe_verified']} verified")

        # ── summary + table ──────────────────────────────────────────────────
        @staticmethod
        def _shown_verdict(fr):
            return signature.display_verdict(
                fr.ml_verdict, fr.signature_status, fr.hash_verdict)

        def _update_summary(self, scan):
            s = scan.summary
            malware_unsigned = sum(1 for r in scan.results
                                   if r.ml_flagged
                                   and r.signature_status != signature.TRUSTED)
            safe_verified = sum(1 for r in scan.results
                                if r.ml_verdict == SAFE
                                and (r.signature_status == signature.TRUSTED
                                     or r.hash_verdict == NOT_IN_DB))
            self.card_scanned.set_value(s.scanned, self._mode)
            self.card_malware.set_value(s.malware, self._mode,
                                        sub=f"{malware_unsigned} unsigned")
            self.card_safe.set_value(s.safe, self._mode,
                                     sub=f"{safe_verified} verified")

        def _row_passes_filter(self, fr):
            mode = self.filter_box.currentIndex()
            if mode == 1:  # Malware only
                return fr.ml_flagged
            if mode == 2:  # ML-only catches
                return fr.comparison_tag == ML_ONLY_CATCH
            return True

        # Rank used when sorting the Verdict column — severity order, not
        # alphabetical, so MALWARE sorts to one end.
        _VERDICT_RANK = {MALWARE: 0, ERROR: 1,
                         signature.SIGNED_SAFE: 2, SAFE: 3}

        def _sort_key(self, col):
            if col == 0:
                return lambda fr: fr.name.lower()
            if col == 1:
                return lambda fr: self._VERDICT_RANK.get(self._shown_verdict(fr), 99)
            if col == 2:
                return lambda fr: fr.lgbm_prob if fr.lgbm_prob is not None else -1.0
            if col == 3:
                return lambda fr: ((fr.hash_verdict or ""), (fr.signature_signer or ""))
            if col == 4:
                return lambda fr: fr.path.lower()
            return lambda fr: 0

        def _on_header_clicked(self, col):
            if self._sort_col == col:
                self._sort_reverse = not self._sort_reverse
            else:
                self._sort_col, self._sort_reverse = col, False
            order = (QtCore.Qt.SortOrder.DescendingOrder if self._sort_reverse
                     else QtCore.Qt.SortOrder.AscendingOrder)
            header = self.table.horizontalHeader()
            header.setSortIndicatorShown(True)
            header.setSortIndicator(col, order)
            self._refresh_table()

        def _sorted_filtered_results(self):
            rows = [fr for fr in self._results if self._row_passes_filter(fr)]
            if self._sort_col is not None:
                rows.sort(key=self._sort_key(self._sort_col), reverse=self._sort_reverse)
            return rows

        def _append_row(self, fr):
            row = self.table.rowCount()
            self.table.insertRow(row)
            shown = self._shown_verdict(fr)
            prob = "" if fr.lgbm_prob is None else f"{fr.lgbm_prob * 100:.1f}%"
            sig = fr.hash_verdict or "—"
            tip = f"ML verdict: {fr.ml_verdict}"
            # A validly signed file is shown green, but its real ML verdict
            # stays visible in the row so the table remains auditable.
            if shown == signature.SIGNED_SAFE:
                signer = fr.signature_signer or "trusted publisher"
                sig = f"Signed: {signer}  ·  ML: {fr.ml_verdict}"
                tip = (f"The model flagged this file as {fr.ml_verdict}, but it "
                       f"carries a valid Authenticode signature from {signer}, "
                       f"so it is shown as clean.")
            cells = [fr.name, shown, prob, sig, fr.path]
            for col, text in enumerate(cells):
                item = QtWidgets.QTableWidgetItem(text)
                item.setData(QtCore.Qt.ItemDataRole.UserRole, fr)
                item.setToolTip(tip if col in (1, 3) else text)
                if col == 1:
                    item.setData(BadgeDelegate.ROLE, shown)
                if col == 2:
                    item.setTextAlignment(
                        QtCore.Qt.AlignmentFlag.AlignRight
                        | QtCore.Qt.AlignmentFlag.AlignVCenter)
                if col == 3 and fr.hash_verdict == KNOWN_MALWARE:
                    item.setForeground(
                        QtGui.QColor(theme.palette(self._mode)["danger"]))
                self.table.setItem(row, col, item)

        def _update_result_count(self):
            if not hasattr(self, "result_count"):
                return
            n, total = self.table.rowCount(), len(self._results)
            self.result_count.setText("" if not total else f"{n} of {total} row(s)")

        def _refresh_table(self):
            if not hasattr(self, "table"):
                return
            self.table.setRowCount(0)
            for fr in self._sorted_filtered_results():
                self._append_row(fr)
            self._update_result_count()

        # ── right-click copy ─────────────────────────────────────────────────
        @staticmethod
        def _exec_context_menu(menu, global_pos):
            """Thin wrapper around QMenu.exec so tests can stub the modal call.

            QMenu.exec is a shiboken-bound method; monkeypatching it directly on
            the class does not reliably override the call (confirmed: the real
            modal menu still opened and blocked headless test runs indefinitely).
            Routing through this plain Python method gives tests something
            actually patchable without ever touching Qt internals.
            """
            return menu.exec(global_pos)

        def _show_row_context_menu(self, pos):
            item = self.table.itemAt(pos)
            if item is None:
                return
            row = item.row()
            fr = self.table.item(row, 0).data(QtCore.Qt.ItemDataRole.UserRole)
            if fr is None:
                return
            menu = QtWidgets.QMenu(self)
            act_row = menu.addAction("Copy row")
            act_cell = menu.addAction("Copy cell")
            menu.addSeparator()
            act_name = menu.addAction("Copy file name")
            act_path = menu.addAction("Copy path")
            act_sha = menu.addAction("Copy SHA-256")
            chosen = self._exec_context_menu(menu, self.table.viewport().mapToGlobal(pos))
            if chosen is None:
                return
            clip = QtWidgets.QApplication.clipboard()
            if chosen == act_row:
                cells = [self.table.item(row, c).text()
                        for c in range(self.table.columnCount())]
                clip.setText("\t".join(cells))
            elif chosen == act_cell:
                clip.setText(item.text())
            elif chosen == act_name:
                clip.setText(fr.name)
            elif chosen == act_path:
                clip.setText(fr.path)
            elif chosen == act_sha:
                clip.setText(fr.sha256 or "")

        # ── action buttons ───────────────────────────────────────────────────
        def _open_report(self):
            if self._report_path and os.path.exists(self._report_path):
                self._open_path(str(self._report_path))
            else:
                QtWidgets.QMessageBox.information(self, "No report", "Run a scan first.")

        def _open_quarantine(self):
            # Resolve via Quarantine() itself (not config.QUARANTINE_DIR directly) so
            # this opens wherever files actually landed, including the local-drive
            # fallback used when the project folder isn't writable (e.g. a read-only
            # network share) — see quarantine.py's _resolve_writable_dir().
            q = Quarantine()
            self._open_path(str(q.dir))

        def _explain_selected(self):
            rows = {i.row() for i in self.table.selectedIndexes()}
            if not rows:
                QtWidgets.QMessageBox.information(self, "Explain", "Select a row first.")
                return
            if self._explain_worker is not None and self._explain_worker.isRunning():
                return   # one explanation at a time
            item = self.table.item(min(rows), 0)
            fr = item.data(QtCore.Qt.ItemDataRole.UserRole) if item else None
            if not fr:
                return
            if not fr.path or not os.path.isfile(fr.path):
                QtWidgets.QMessageBox.warning(
                    self, "Explain",
                    "The file is no longer at its original path (it may have "
                    "been quarantined or removed), so it can't be re-read to "
                    "generate an explanation.")
                return

            self.btn_explain.setEnabled(False)
            self.btn_explain.setText("Explaining…")
            self._explain_worker = ExplainWorker(fr)
            self._explain_worker.done.connect(
                lambda result: self._on_explain_done(fr.name, result))
            self._explain_worker.failed.connect(self._on_explain_failed)
            self._explain_worker.start()

        def _reset_explain_button(self):
            self.btn_explain.setEnabled(True)
            self.btn_explain.setText("Explain")

        def _on_explain_done(self, file_name, result):
            self._reset_explain_button()
            ExplainDialog(self, file_name, result).exec()

        def _on_explain_failed(self, msg):
            self._reset_explain_button()
            QtWidgets.QMessageBox.critical(self, "Explain failed", msg)

        def _restore_selected(self):
            rows = {i.row() for i in self.table.selectedIndexes()}
            if not rows:
                QtWidgets.QMessageBox.information(self, "Restore", "Select a row first.")
                return
            q = Quarantine()
            restored, errors = [], []
            for r in rows:
                item = self.table.item(r, 0)
                fr = item.data(QtCore.Qt.ItemDataRole.UserRole) if item else None
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

        # ── shutdown ─────────────────────────────────────────────────────────
        def closeEvent(self, event):
            """Let running workers finish before the window goes away.

            Qt aborts the process with "QThread: Destroyed while thread is still
            running" if a QThread outlives its owner, which is exactly what
            happens when the window is closed during the ~30s startup
            self-check. Waiting is bounded so a wedged worker cannot hang the
            close.
            """
            self._live_flush.stop()
            for worker in (getattr(self, "_sc_worker", None), self._worker,
                          self._explain_worker, self._model_worker):
                if worker is not None and worker.isRunning():
                    worker.requestInterruption()
                    worker.wait(5000)
            super().closeEvent(event)

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
    app.setApplicationName("AntivirusAI V7")
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
