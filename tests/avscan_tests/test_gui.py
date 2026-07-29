"""Tests for the PySide6 desktop UI (avscan/gui.py).

Runs against a real QApplication on Qt's "offscreen" platform, so the actual
widgets are built, laid out and painted — no mocking of the UI itself. The
startup self-check is stubbed, because running the real one (a full regression
over 12k samples) would make every test take half a minute.
"""
import os
import tempfile

import pytest

# Must be set before QApplication is constructed.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="the desktop GUI requires PySide6")
from PySide6 import QtCore, QtGui, QtWidgets  # noqa: E402

from avscan import gui, signature, theme  # noqa: E402
from avscan.orchestrator import (FileResult, ScanResult,  # noqa: E402
                                 ScanSummary, ML_ONLY_CATCH)


# ── fixtures ────────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def qapp():
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    yield app


class _FakeCheck:
    def __init__(self, name, passed):
        self.name, self.passed = name, passed


class _FakeSelfCheck:
    def __init__(self, ok=True):
        self.ok = ok
        self.checks = [_FakeCheck("versions", ok)]


def _stub_selfcheck(monkeypatch, ok=True):
    """Replace the self-check worker with one that reports synchronously."""
    class FakeWorker(QtCore.QThread):
        done = QtCore.Signal(object)

        def start(self):                      # emit inline, no thread
            self.done.emit(_FakeSelfCheck(ok))

    monkeypatch.setattr(gui, "SelfCheckWorker", FakeWorker)
    monkeypatch.setattr(gui, "status_line", lambda r: "environment verified")


@pytest.fixture
def win(qapp, monkeypatch):
    _stub_selfcheck(monkeypatch, ok=True)
    w = gui.MainWindow()
    w.show()
    qapp.processEvents()
    yield w
    w.close()


def mk(name, verdict, *, prob=0.99, hash_verdict="NOT_IN_DB", tag=None,
       sig_status=None, signer=None):
    return FileResult(
        path=rf"C:\samples\{name}", name=name, sha256="ab" * 32, size=1024,
        ml_verdict=verdict, lgbm_prob=prob, hash_verdict=hash_verdict,
        comparison_tag=tag, signature_status=sig_status, signature_signer=signer)


def mk_scan(results, *, ml_only=0, malware=0, zeroday=0, safe=0, scanned=None):
    return ScanResult(
        folder=r"C:\samples", scan_id="test", started_at="", finished_at="",
        duration_seconds=1.5,
        summary=ScanSummary(scanned=scanned if scanned is not None else len(results),
                            malware=malware, potential_zeroday=zeroday, safe=safe),
        results=results,
        hash_comparison={"files": {ML_ONLY_CATCH: ml_only}})


# ── construction ────────────────────────────────────────────────────────────
def test_window_builds_all_core_widgets(win):
    for attr in ("path_edit", "scan_btn", "table", "progress", "filter_box",
                 "health_pill", "theme_btn", "cur_file", "status",
                 "card_mlonly", "card_malware", "card_signed"):
        assert hasattr(win, attr), f"missing widget: {attr}"
    assert win.table.columnCount() == len(win.COLUMNS)


def test_scan_button_enabled_only_after_selfcheck_passes(qapp, monkeypatch):
    _stub_selfcheck(monkeypatch, ok=True)
    w = gui.MainWindow()
    assert w.scan_btn.isEnabled()
    assert w._selfcheck_ok is True
    w.close()


def test_failed_selfcheck_blocks_scanning(qapp, monkeypatch):
    """A broken environment must leave Scan disabled — the safety gate in the UI."""
    _stub_selfcheck(monkeypatch, ok=False)
    monkeypatch.setattr(QtWidgets.QMessageBox, "critical",
                        staticmethod(lambda *a, **k: None))
    w = gui.MainWindow()
    assert w._selfcheck_ok is False
    assert not w.scan_btn.isEnabled()
    assert "✗" in w.health_pill.text()
    w.close()


def test_progress_bar_hidden_until_a_scan_runs(win):
    assert not win.progress.isVisible()


def test_scan_rejects_a_nonexistent_folder(win, monkeypatch):
    seen = {}
    monkeypatch.setattr(QtWidgets.QMessageBox, "warning",
                        staticmethod(lambda *a, **k: seen.setdefault("warned", True)))
    win.path_edit.setText(r"C:\definitely\not\a\real\folder")
    win._start_scan()
    assert seen.get("warned") is True
    assert win._worker is None          # no scan thread was started


# ── theming ─────────────────────────────────────────────────────────────────
def test_stylesheet_is_applied_to_the_application(win, qapp):
    assert "QPushButton#Primary" in qapp.styleSheet()


def test_theme_toggle_switches_palette_and_restyles(win, qapp):
    assert win._mode == "dark"
    before = qapp.styleSheet()
    win.theme_btn.click()
    qapp.processEvents()
    assert win._mode == "light"
    assert qapp.styleSheet() != before
    assert qapp.styleSheet() == theme.stylesheet("light")
    # the delegate must follow, or badges keep painting in the old palette
    assert win.badge_delegate.mode == "light"
    win.theme_btn.click()
    assert win._mode == "dark"


def test_theme_toggle_survives_populated_table(win, qapp):
    win._results = [mk("a.exe", "MALWARE"), mk("b.exe", "SAFE")]
    win._refresh_table()
    win.theme_btn.click()
    qapp.processEvents()
    assert win.table.rowCount() == 2      # rebuilt, not cleared


# ── table rendering ─────────────────────────────────────────────────────────
def test_table_populates_one_row_per_result(win):
    win._results = [mk("a.exe", "MALWARE"), mk("b.exe", "SAFE"),
                    mk("c.exe", "POTENTIAL_ZERODAY")]
    win._refresh_table()
    assert win.table.rowCount() == 3
    assert win.table.item(0, 0).text() == "a.exe"
    assert win.table.item(0, 2).text() == "99.0%"


def test_verdict_cell_carries_the_badge_role(win):
    win._results = [mk("a.exe", "MALWARE")]
    win._refresh_table()
    item = win.table.item(0, 1)
    assert item.data(gui.BadgeDelegate.ROLE) == "MALWARE"
    assert item.text() == "MALWARE"      # plain text kept for copy/paste


def test_signed_file_row_is_green_but_still_auditable(win):
    """The signed row shows a SIGNED badge, yet the real ML verdict and the
    signer must both remain visible in the row."""
    win._results = [mk("Claude Setup.exe", "MALWARE", prob=0.9987,
                       sig_status="TRUSTED", signer="Anthropic, PBC")]
    win._refresh_table()
    badge_item = win.table.item(0, 1)
    assert badge_item.data(gui.BadgeDelegate.ROLE) == signature.SIGNED_SAFE
    detail = win.table.item(0, 3).text()
    assert "Anthropic, PBC" in detail
    assert "MALWARE" in detail            # ML verdict not hidden
    assert "MALWARE" in badge_item.toolTip()


def test_known_malware_hash_row_stays_red_even_when_signed(win):
    """UI reflection of the safety carve-out in signature.display_verdict."""
    win._results = [mk("evil.exe", "MALWARE", hash_verdict="KNOWN_MALWARE",
                       sig_status="TRUSTED", signer="Stolen Cert Inc")]
    win._refresh_table()
    assert win.table.item(0, 1).data(gui.BadgeDelegate.ROLE) == "MALWARE"


def test_filter_malware_only(win):
    win._results = [mk("a.exe", "MALWARE"), mk("b.exe", "SAFE")]
    win.filter_box.setCurrentIndex(1)
    assert win.table.rowCount() == 1
    assert win.table.item(0, 0).text() == "a.exe"


def test_filter_ml_only_catches(win):
    win._results = [mk("a.exe", "MALWARE", tag=ML_ONLY_CATCH),
                    mk("b.exe", "MALWARE", hash_verdict="KNOWN_MALWARE")]
    win.filter_box.setCurrentIndex(2)
    assert win.table.rowCount() == 1
    assert win.table.item(0, 0).text() == "a.exe"


def test_row_count_label_reports_the_filter(win):
    win._results = [mk("a.exe", "MALWARE"), mk("b.exe", "SAFE")]
    win.filter_box.setCurrentIndex(1)
    assert "1 of 2" in win.result_count.text()


# ── summary cards ───────────────────────────────────────────────────────────
def test_stat_cards_update_from_a_scan(win):
    scan = mk_scan([mk("a.exe", "MALWARE", tag=ML_ONLY_CATCH),
                    mk("b.exe", "SAFE")],
                   ml_only=1, malware=1, safe=1, scanned=2)
    win._update_summary(scan)
    assert win.card_scanned.value.text() == "2"
    assert win.card_malware.value.text() == "1"
    assert win.card_mlonly.value.text() == "1"
    assert win.card_safe.value.text() == "1"


def test_signed_file_counts_as_signed_not_as_malware(win):
    """A file shown green must not also be tallied in the red MALWARE card, or
    the cards would contradict the badges directly beside them."""
    scan = mk_scan([mk("Claude Setup.exe", "MALWARE", sig_status="TRUSTED",
                       signer="Anthropic, PBC")],
                   malware=1, scanned=1)
    win._update_summary(scan)
    assert win.card_signed.value.text() == "1"
    assert win.card_malware.value.text() == "0"


def test_stat_card_colour_follows_theme(win):
    win.card_malware.set_value(3, "dark")
    assert theme.palette("dark")["danger"] in win.card_malware.value.styleSheet()
    win.card_malware.set_value(3, "light")
    assert theme.palette("light")["danger"] in win.card_malware.value.styleSheet()


# ── the badge is really painted ─────────────────────────────────────────────
def _render(widget, w=760, h=180):
    widget.resize(w, h)
    img = QtGui.QImage(w, h, QtGui.QImage.Format.Format_ARGB32)
    img.fill(QtGui.QColor("#000000"))
    widget.render(img)          # QImage is a QPaintDevice
    return img


def _colours(img):
    return {img.pixel(x, y) for x in range(0, img.width(), 2)
            for y in range(0, img.height(), 2)}


@pytest.mark.parametrize("verdict,key", [("MALWARE", "danger"),
                                         ("SAFE", "success"),
                                         ("POTENTIAL_ZERODAY", "warn")])
def test_badge_pill_is_actually_drawn(win, qapp, verdict, key):
    """Paint the table and look for the badge fill in the pixels — this is the
    only way to catch a delegate that silently stops rendering."""
    win._results = [mk("sample.exe", verdict)]
    win._refresh_table()
    qapp.processEvents()
    img = _render(win.table)
    want = QtGui.QColor(theme.palette(win._mode)[f"{key}_bg"]).rgb()
    assert want in _colours(img), f"{verdict}: no {key}_bg pill fill was painted"


def test_badge_repaints_in_the_new_theme_after_toggle(win, qapp):
    win._results = [mk("sample.exe", "MALWARE")]
    win._refresh_table()
    win.theme_btn.click()                       # -> light
    qapp.processEvents()
    img = _render(win.table)
    light_fill = QtGui.QColor(theme.palette("light")["danger_bg"]).rgb()
    assert light_fill in _colours(img)


def test_close_waits_for_a_running_worker(qapp, monkeypatch):
    """Closing during the startup self-check must not abort the process with
    "QThread: Destroyed while thread is still running"."""
    started = {}

    class SlowWorker(QtCore.QThread):
        done = QtCore.Signal(object)

        def run(self):
            started["ran"] = True
            self.msleep(250)          # still running when close() is called
            self.done.emit(_FakeSelfCheck(True))

    monkeypatch.setattr(gui, "SelfCheckWorker", SlowWorker)
    monkeypatch.setattr(gui, "status_line", lambda r: "ok")
    w = gui.MainWindow()
    qapp.processEvents()
    assert w._sc_worker.isRunning()
    w.close()                          # must block until the worker is done
    assert not w._sc_worker.isRunning()
    assert started.get("ran") is True


def test_unknown_verdict_does_not_crash_the_delegate(win, qapp):
    win._results = [mk("weird.exe", "SOMETHING_NEW")]
    win._refresh_table()
    qapp.processEvents()
    _render(win.table)                          # must not raise
    assert win.table.item(0, 1).data(gui.BadgeDelegate.ROLE) == "SOMETHING_NEW"


# ── live dashboard updates ───────────────────────────────────────────────────
def _reset_live_state(win):
    win._results = []
    win._pending_live = []
    win._live_counts = dict(scanned=0, malware=0, zeroday=0, safe=0,
                            signed=0, ml_only=0)
    win.table.setRowCount(0)


def test_live_result_updates_counts_before_any_flush(win):
    """_on_result_live must update the running tally immediately — the table
    repaint is what's deferred, not the bookkeeping."""
    _reset_live_state(win)
    win._on_result_live(mk("a.exe", "MALWARE"))
    win._on_result_live(mk("b.exe", "SAFE"))
    win._on_result_live(mk("c.exe", "POTENTIAL_ZERODAY"))
    assert win._live_counts == {"scanned": 3, "malware": 1, "zeroday": 1,
                                "safe": 1, "signed": 0, "ml_only": 0}
    assert len(win._pending_live) == 3
    assert win.table.rowCount() == 0            # not flushed yet


def test_live_signed_malware_counts_as_signed_not_malware(win):
    _reset_live_state(win)
    win._on_result_live(mk("Claude Setup.exe", "MALWARE",
                          sig_status="TRUSTED", signer="Anthropic, PBC"))
    assert win._live_counts["signed"] == 1
    assert win._live_counts["malware"] == 0


def test_flush_paints_pending_rows_and_stat_cards(win):
    _reset_live_state(win)
    win._on_result_live(mk("a.exe", "MALWARE"))
    win._on_result_live(mk("b.exe", "SAFE"))
    win._flush_live_results()
    assert win.table.rowCount() == 2
    assert win.card_malware.value.text() == "1"
    assert win.card_safe.value.text() == "1"
    assert win._pending_live == []


def test_flush_respects_the_active_filter(win):
    """A live row that fails the current filter must not appear mid-scan."""
    _reset_live_state(win)
    win.filter_box.setCurrentIndex(1)            # Malware only
    win._on_result_live(mk("a.exe", "MALWARE"))
    win._on_result_live(mk("b.exe", "SAFE"))
    win._flush_live_results()
    assert win.table.rowCount() == 1
    assert win.table.item(0, 0).text() == "a.exe"
    win.filter_box.setCurrentIndex(0)


def test_flush_with_no_pending_results_is_a_noop(win):
    _reset_live_state(win)
    win._flush_live_results()                    # must not raise
    assert win.table.rowCount() == 0


def test_flush_while_sorted_keeps_new_rows_in_order(win):
    """If the user sorted the table, a mid-scan arrival must not just append at
    the bottom out of order — it should land in its sorted place."""
    _reset_live_state(win)
    win._on_result_live(mk("bravo.exe", "SAFE"))
    win._flush_live_results()
    win._on_header_clicked(0)                    # sort by File, ascending
    win._on_result_live(mk("alpha.exe", "SAFE"))
    win._flush_live_results()
    names = [win.table.item(r, 0).text() for r in range(win.table.rowCount())]
    assert names == ["alpha.exe", "bravo.exe"]
    win._sort_col = None                          # reset for later tests


def test_start_scan_resets_live_state(win, monkeypatch):
    """A previous scan's leftovers must not bleed into a new one."""
    win._results = [mk("stale.exe", "MALWARE")]
    win._live_counts["malware"] = 99

    class _NoopSignal:
        def connect(self, *a):
            pass

    class DummyWorker:
        def __init__(self, *a, **k):
            self.progress = _NoopSignal()
            self.result = _NoopSignal()
            self.flagged = _NoopSignal()
            self.finished_scan = _NoopSignal()
            self.failed = _NoopSignal()
        def start(self):
            pass
        def isRunning(self):
            return False
        def requestInterruption(self):
            pass
        def wait(self, ms=0):
            return True

    monkeypatch.setattr(gui, "ScanWorker", DummyWorker)
    win.path_edit.setText(tempfile.gettempdir())
    win._selfcheck_ok = True
    win._start_scan()
    assert win._live_counts["malware"] == 0
    assert win.card_malware.value.text() == "0"
    win._live_flush.stop()


# ── column sorting ───────────────────────────────────────────────────────────
def test_sort_by_file_name_ascending_then_descending(win):
    win._results = [mk("charlie.exe", "SAFE"), mk("alpha.exe", "SAFE"),
                    mk("bravo.exe", "SAFE")]
    win._sort_col = None
    win._refresh_table()
    win._on_header_clicked(0)
    names = [win.table.item(r, 0).text() for r in range(win.table.rowCount())]
    assert names == ["alpha.exe", "bravo.exe", "charlie.exe"]
    win._on_header_clicked(0)                    # same column again -> reverse
    names_rev = [win.table.item(r, 0).text() for r in range(win.table.rowCount())]
    assert names_rev == ["charlie.exe", "bravo.exe", "alpha.exe"]
    win._sort_col = None


def test_sort_by_verdict_uses_severity_not_alphabetical(win):
    win._results = [mk("a.exe", "SAFE"), mk("b.exe", "MALWARE"),
                    mk("c.exe", "POTENTIAL_ZERODAY")]
    win._sort_col = None
    win._refresh_table()
    win._on_header_clicked(1)
    verdicts = [win.table.item(r, 1).data(gui.BadgeDelegate.ROLE)
               for r in range(win.table.rowCount())]
    assert verdicts == ["MALWARE", "POTENTIAL_ZERODAY", "SAFE"]
    win._sort_col = None


def test_sort_by_confidence_treats_missing_probability_as_lowest(win):
    win._results = [mk("a.exe", "SAFE", prob=0.5), mk("b.exe", "ERROR", prob=None),
                    mk("c.exe", "SAFE", prob=0.9)]
    win._sort_col = None
    win._refresh_table()
    win._on_header_clicked(2)
    names = [win.table.item(r, 0).text() for r in range(win.table.rowCount())]
    assert names == ["b.exe", "a.exe", "c.exe"]
    win._sort_col = None


def test_sort_indicator_shown_on_the_clicked_header(win):
    win._results = [mk("a.exe", "SAFE")]
    win._sort_col = None
    win._refresh_table()
    win._on_header_clicked(4)
    header = win.table.horizontalHeader()
    assert header.sortIndicatorSection() == 4
    assert header.sortIndicatorOrder() == QtCore.Qt.SortOrder.AscendingOrder
    win._sort_col = None


def test_sort_indicator_hidden_until_a_header_is_clicked(win):
    """No arrow should claim a sort is active before the user asks for one."""
    assert not win.table.horizontalHeader().isSortIndicatorShown()


# ── right-click copy ─────────────────────────────────────────────────────────
def test_context_menu_copy_row_puts_tab_separated_text_on_clipboard(win, qapp, monkeypatch):
    win._results = [mk("a.exe", "MALWARE")]
    win._sort_col = None
    win._refresh_table()

    # Stub the modal call, not QMenu.exec itself — QMenu.exec is a
    # shiboken-bound method and monkeypatching it directly does not reliably
    # override the call (confirmed: the real menu still opened and blocked).
    monkeypatch.setattr(gui.MainWindow, "_exec_context_menu",
                        staticmethod(lambda menu, pos: menu.actions()[0]))

    rect = win.table.visualItemRect(win.table.item(0, 0))
    win._show_row_context_menu(rect.center())
    qapp.processEvents()
    text = QtWidgets.QApplication.clipboard().text()
    assert "a.exe" in text and "MALWARE" in text
    assert "\t" in text


def test_context_menu_copy_path(win, qapp, monkeypatch):
    win._results = [mk("a.exe", "MALWARE")]
    win._sort_col = None
    win._refresh_table()

    def fake_exec(menu, pos):
        for act in menu.actions():
            if act.text() == "Copy path":
                return act
        return None
    monkeypatch.setattr(gui.MainWindow, "_exec_context_menu", staticmethod(fake_exec))

    rect = win.table.visualItemRect(win.table.item(0, 0))
    win._show_row_context_menu(rect.center())
    qapp.processEvents()
    assert QtWidgets.QApplication.clipboard().text() == r"C:\samples\a.exe"


def test_context_menu_on_empty_area_does_not_crash(win):
    win._results = [mk("a.exe", "MALWARE")]
    win._sort_col = None
    win._refresh_table()
    win._show_row_context_menu(QtCore.QPoint(-5, -5))   # outside any row


def test_context_menu_dismissed_without_a_choice_does_not_crash(win, monkeypatch):
    win._results = [mk("a.exe", "MALWARE")]
    win._sort_col = None
    win._refresh_table()
    monkeypatch.setattr(gui.MainWindow, "_exec_context_menu",
                        staticmethod(lambda menu, pos: None))
    rect = win.table.visualItemRect(win.table.item(0, 0))
    win._show_row_context_menu(rect.center())    # must not raise


# ── Explain button ───────────────────────────────────────────────────────────
class _FakeExplainWorker(QtCore.QThread):
    """Emits synchronously in start() rather than running on a real OS thread —
    same stubbing pattern as _stub_selfcheck's FakeWorker, and confirmed there
    to fire connected slots immediately (no event-pump needed in the test)."""
    done = QtCore.Signal(dict)
    failed = QtCore.Signal(str)
    _outcome = ("done", {"summary": "fake explanation", "status": "ok"})

    def __init__(self, fr):
        super().__init__()
        self.fr = fr

    def start(self):
        kind, payload = self._outcome
        (self.done if kind == "done" else self.failed).emit(payload)


class _FakeExplainDialog:
    """Stand-in for gui.ExplainDialog — a real QDialog.exec() is modal and
    would hang a headless test (the same class of problem as QMenu.exec,
    confirmed earlier in this file); this is a plain Python class instead."""
    last = None

    def __init__(self, parent, file_name, result):
        self.file_name, self.result = file_name, result
        _FakeExplainDialog.last = self

    def exec(self):
        self.executed = True


def test_explain_no_selection_shows_message_and_starts_nothing(win, monkeypatch):
    seen = {}
    monkeypatch.setattr(QtWidgets.QMessageBox, "information",
                        staticmethod(lambda *a, **k: seen.setdefault("shown", True)))
    win._results = []
    win._refresh_table()
    win.table.clearSelection()
    win._explain_selected()
    assert seen.get("shown") is True
    assert win._explain_worker is None


def test_explain_missing_file_shows_warning_and_starts_nothing(win, monkeypatch, tmp_path):
    win._results = [mk("gone.exe", "MALWARE")]
    win._results[0].path = str(tmp_path / "does_not_exist.exe")
    win._refresh_table()
    win.table.selectRow(0)
    seen = {}
    monkeypatch.setattr(QtWidgets.QMessageBox, "warning",
                        staticmethod(lambda *a, **k: seen.setdefault("shown", True)))
    win._explain_selected()
    assert seen.get("shown") is True
    assert win._explain_worker is None


def test_explain_success_shows_dialog_with_summary_and_resets_button(win, monkeypatch, tmp_path):
    f = tmp_path / "sample.exe"
    f.write_bytes(b"MZ" + b"\0" * 100)
    win._results = [mk("sample.exe", "MALWARE")]
    win._results[0].path = str(f)
    win._refresh_table()
    win.table.selectRow(0)

    monkeypatch.setattr(gui, "ExplainWorker", _FakeExplainWorker)
    monkeypatch.setattr(gui, "ExplainDialog", _FakeExplainDialog)

    win._explain_selected()

    dlg = _FakeExplainDialog.last
    assert dlg is not None
    assert dlg.file_name == "sample.exe"
    assert dlg.result["summary"] == "fake explanation"
    assert dlg.executed is True
    assert win.btn_explain.isEnabled()
    assert win.btn_explain.text() == "Explain"


def test_explain_failure_shows_error_and_resets_button(win, monkeypatch, tmp_path):
    f = tmp_path / "sample.exe"
    f.write_bytes(b"MZ" + b"\0" * 100)
    win._results = [mk("sample.exe", "MALWARE")]
    win._results[0].path = str(f)
    win._refresh_table()
    win.table.selectRow(0)

    class FailingWorker(_FakeExplainWorker):
        _outcome = ("failed", "boom")
    monkeypatch.setattr(gui, "ExplainWorker", FailingWorker)
    seen = {}
    monkeypatch.setattr(QtWidgets.QMessageBox, "critical",
                        staticmethod(lambda *a, **k: seen.setdefault("msg", a[-1] if a else None)))

    win._explain_selected()

    assert seen.get("msg") == "boom"
    assert win.btn_explain.isEnabled()
    assert win.btn_explain.text() == "Explain"


def test_explain_button_disabled_while_a_call_is_in_flight(win, monkeypatch, tmp_path):
    """A worker that never finishes must block a second click rather than
    starting an overlapping explanation."""
    f = tmp_path / "sample.exe"
    f.write_bytes(b"MZ" + b"\0" * 100)
    win._results = [mk("sample.exe", "MALWARE")]
    win._results[0].path = str(f)
    win._refresh_table()
    win.table.selectRow(0)

    class StuckWorker(QtCore.QThread):
        done = QtCore.Signal(dict)
        failed = QtCore.Signal(str)
        def __init__(self, fr):
            super().__init__()
        def start(self):
            pass   # never emits, never finishes
        def isRunning(self):
            return True

    monkeypatch.setattr(gui, "ExplainWorker", StuckWorker)
    win._explain_selected()
    first_worker = win._explain_worker
    assert win.btn_explain.text() == "Explaining…"

    win._explain_selected()          # second click while "in flight"
    assert win._explain_worker is first_worker   # no new worker was created
