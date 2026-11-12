#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles SELinux Inspector - dedicated privileged inspection window
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

"""Ephemeral SELinux privileged-inspection surface.

The privileged window deliberately reuses the established 0.0.3 visual/workflow
language instead of inventing a second inspector UI.  It contains the same
inspection tabs, table/search/category/metadata pattern, Refresh List and Export
controls.  Recent Denials remains explicitly scan-only and retains Scan Normally
and Scan with Privileged Access... .

Before authorization the replicated pages use ordinary-user visibility.  Once
the fixed helper session is active, only the helper-supported deep policy pages
route their fixed read-only queries through the helper.  There are no stacked
Basic/Elevated duplicate panes.  Closing this dialog stops the helper session.
"""

from __future__ import annotations

from typing import Any

from PyQt6.QtCore import QTimer, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QHeaderView,
)
from PyQt6.QtGui import QColor, QKeySequence, QShortcut

from .privilege import (
    PrivilegeClient,
    helper_contract,
    helper_status_details,
    install_or_update_helper,
    remove_helper,
)
from .privileged_pages import (
    SELinuxBooleansPage,
    SELinuxDenialsPage,
    SELinuxProcessesPage,
)
from .privileged_deep_pages import (
    SELinuxFileContextRulesPage,
    SELinuxPermissiveDomainsPage,
    SELinuxPolicyModulesPage,
    SELinuxPortContextsPage,
    SELinuxUsersLoginsPage,
    set_privilege_client,
    set_observed_callback,
)

AMBER = "#d6a23d"
AMBER_LIGHT = "#f2d18b"
AMBER_DARK = "#3a2d13"
AMBER_DEEP = "#6a4b0c"
BG = "#171717"
PANEL = "#1e1e1e"
FG = "#dcdcdc"
MUTED = "#b8b8b8"
BORDER = "#666"


def _state_word(details: dict[str, Any]) -> str:
    if details.get("ready"):
        return "Installed and verified"
    if details.get("installed"):
        return "Installed — update/repair required"
    return "Not installed"


def _comparison_key(op: str) -> tuple[str, str]:
    mapping = {
        "denials": ("denials", "Recent AVC audit denials"),
        "policy_modules_full": ("policy_modules", "Policy modules"),
        "policy_modules_standard": ("policy_modules", "Policy modules"),
        "policy_modules_legacy": ("policy_modules", "Policy modules"),
        "permissive_domains": ("permissive_domains", "Permissive domains"),
        "users": ("users", "SELinux users"),
        "logins": ("logins", "Login mappings"),
        "ports": ("ports", "Port contexts"),
        "fcontexts": ("fcontexts", "File-context rules"),
    }
    return mapping.get(str(op), (str(op), str(op).replace("_", " ").title()))


def _result_snapshot(op: str, result) -> dict[str, Any]:
    if result is None:
        return {"ok": False, "returncode": None, "lines": (), "message": "Not inspected"}
    try:
        rc = int(result.returncode)
    except Exception:
        rc = 125
    stdout = str(getattr(result, "stdout", "") or "")
    stderr = str(getattr(result, "stderr", "") or "").strip()
    ok = rc == 0 or (op == "denials" and rc == 1)
    lines = tuple(sorted({line.strip() for line in stdout.splitlines() if line.strip()}))
    if ok:
        message = f"Available — {len(lines)} data line(s)"
    else:
        message = stderr or f"Unavailable (exit {rc})"
    return {"ok": ok, "returncode": rc, "lines": lines, "message": message}


def _compare_snapshots(ordinary: dict[str, Any], elevated: dict[str, Any]) -> str:
    if not elevated.get("ok"):
        return "Elevated unavailable"
    if not ordinary.get("ok") and elevated.get("ok"):
        return "Access added"
    o_lines = set(ordinary.get("lines") or ())
    e_lines = set(elevated.get("lines") or ())
    if o_lines == e_lines:
        return "Same — no additional access observed"
    if o_lines < e_lines:
        return f"Additional data observed (+{len(e_lines - o_lines)} line(s))"
    return "Different observed result"


class ComparisonReportDialog(QDialog):
    """Observed ordinary-vs-helper SELinux report; no declarative/theoretical rows."""

    def __init__(self, observed_pairs: dict[str, dict[str, Any]], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Comparison Report — SELinux Inspector")
        self.resize(1120, 560)
        self.setMinimumSize(820, 420)
        self.setStyleSheet(f"""
            QDialog {{ background: {BG}; color: {FG}; }}
            QLabel {{ color: {FG}; }}
            QTableWidget {{ background: {PANEL}; color: {FG}; border: 1px solid {BORDER}; }}
            QTableWidget::item:selected {{ background: {AMBER_DEEP}; color: #fff4d2; }}
            QHeaderView::section {{ background: #252526; color: {FG}; border: 0; border-right: 1px solid {BORDER}; border-bottom: 1px solid {BORDER}; padding: 5px; font-weight: 600; }}
            QPushButton {{ background: {PANEL}; color: {FG}; border: 1px solid {BORDER}; border-radius: 4px; padding: 5px 10px; }}
            QPushButton:hover {{ border-color: {AMBER}; }}
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        heading = QLabel("Comparison Report")
        font = heading.font()
        font.setBold(True)
        font.setPointSize(max(font.pointSize(), 11))
        heading.setFont(font)
        root.addWidget(heading)

        note = QLabel(
            "Observed comparison of ordinary-user and helper-backed results captured by the latest "
            "user-requested scans/refreshes in this privileged session. No theoretical helper-contract "
            "claims are shown."
        )
        note.setWordWrap(True)
        root.addWidget(note)

        table = QTableWidget(0, 4)
        table.setHorizontalHeaderLabels(["Inspection", "Standard access", "With helper", "Comparison"])
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.verticalHeader().setVisible(False)
        header = table.horizontalHeader()
        for index in range(4):
            header.setSectionResizeMode(index, QHeaderView.ResizeMode.Interactive)
        table.setColumnWidth(0, 230)
        table.setColumnWidth(1, 270)
        table.setColumnWidth(2, 270)
        table.setColumnWidth(3, 320)

        rows = sorted(observed_pairs.values(), key=lambda row: str(row.get("label", "")).casefold())
        table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            ordinary = row.get("ordinary") or {}
            elevated = row.get("elevated") or {}
            values = (
                row.get("label", "Inspection"),
                ordinary.get("message", "Not inspected"),
                elevated.get("message", "Not inspected"),
                _compare_snapshots(ordinary, elevated),
            )
            for column_index, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column_index == 2:
                    item.setForeground(QColor(AMBER_LIGHT))
                table.setItem(row_index, column_index, item)
        root.addWidget(table, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        root.addWidget(buttons)


class PrivilegedInspectionDialog(QDialog):
    session_state_changed = pyqtSignal()
    closing = pyqtSignal(bool)

    def __init__(self, client: PrivilegeClient, metadata_font: str = "", details_orientation: str = "horizontal", parent=None, metadata_panel_visible: bool = True):
        super().__init__(parent)
        self.setObjectName("PrivilegedInspectionDialog")
        self.setWindowTitle("Privileged Inspection — SELinux Inspector")
        self.resize(1220, 820)
        self.setMinimumSize(900, 640)
        self.client = client
        self.metadata_font = metadata_font or ""
        self.details_orientation = str(details_orientation or "horizontal").lower()
        if self.details_orientation not in {"horizontal", "vertical"}:
            self.details_orientation = "horizontal"
        self.metadata_panel_visible = bool(metadata_panel_visible)
        self._shortcuts = []
        self.contract = helper_contract()
        self.session_ever_active = False
        self._closing = False
        self._pending_denial_page = None
        self._last_state = self.client.state
        self._host_column_callback = None
        self._hidden_columns: set[str] = set()
        self._observed_pairs: dict[str, dict[str, Any]] = {}

        set_privilege_client(self.client)
        set_observed_callback(self._record_observed_pair)
        self._build_ui()
        self._apply_page_settings()
        self.set_metadata_panel_visible(self.metadata_panel_visible)
        self._install_shortcuts()

        self._timer = QTimer(self)
        self._timer.setInterval(200)
        self._timer.timeout.connect(self._poll)
        self._timer.start()
        self._refresh_helper_ui()
        self._tab_changed(self.tabs.currentIndex())

    # ---------- construction ----------
    def _build_ui(self):
        self.setStyleSheet(
            f"""
            QDialog#PrivilegedInspectionDialog {{ background: {BG}; color: {FG}; }}
            QFrame#PrivilegeHeader {{ background: {AMBER_DARK}; border: 1px solid {AMBER}; border-radius: 5px; }}
            QLabel {{ color: {FG}; }}
            QLabel#PrivilegeTitle {{ color: {AMBER_LIGHT}; font-weight: 700; }}
            QLabel#PrivilegeState {{ color: {AMBER_LIGHT}; font-weight: 600; }}
            QPushButton {{ background: {PANEL}; color: {FG}; border: 1px solid {BORDER}; border-radius: 4px; padding: 5px 10px; }}
            QPushButton:hover {{ border-color: {AMBER}; }}
            QPushButton#PrivilegePrimary {{ background: {AMBER_DEEP}; color: #fff4d2; border: 1px solid {AMBER}; font-weight: 600; }}
            QPushButton#PrivilegeActive {{ background: {AMBER}; color: #171717; border: 1px solid {AMBER_LIGHT}; font-weight: 700; }}
            QPushButton:disabled {{ color: #777; border-color: #444; background: #1b1b1b; }}
            QTabWidget::pane {{ border: 1px solid {BORDER}; background: {BG}; }}
            QTabBar::tab {{ background: {PANEL}; color: {FG}; border: 1px solid {BORDER}; border-bottom: none; padding: 7px 12px; }}
            QTabBar::tab:selected {{ color: {AMBER_LIGHT}; border-bottom: 2px solid {AMBER}; }}
            QTableWidget, QTextEdit, QLineEdit, QComboBox {{ background: {PANEL}; color: {FG}; border: 1px solid {BORDER}; }}
            QTableWidget::item:selected {{ background: {AMBER_DEEP}; color: #fff4d2; }}
            QHeaderView::section {{ background: #252526; color: {FG}; border: 0; border-right: 1px solid {BORDER}; border-bottom: 1px solid {BORDER}; padding: 5px; font-weight: 600; }}
            """
        )
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        header = QFrame()
        header.setObjectName("PrivilegeHeader")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(12, 9, 12, 9)
        title = QLabel("Privileged Inspection — SELinux Inspector")
        title.setObjectName("PrivilegeTitle")
        font = title.font()
        font.setBold(True)
        font.setPointSize(max(font.pointSize(), 11))
        title.setFont(font)
        header_layout.addWidget(title)
        note = QLabel(
            "This window mirrors the normal SELinux Inspector workflow. Before authorization it uses ordinary-user visibility; "
            "after authorization, helper-supported read-only queries can use elevated visibility. Recent Denials is never scanned automatically. "
            "Closing this window ends the helper session."
        )
        note.setWordWrap(True)
        header_layout.addWidget(note)
        root.addWidget(header)

        status_row = QHBoxLayout()
        self.helper_status_label = QLabel()
        self.helper_status_label.setWordWrap(True)
        status_row.addWidget(self.helper_status_label, 1)
        self.session_label = QLabel("Session: Inactive")
        self.session_label.setObjectName("PrivilegeState")
        status_row.addWidget(self.session_label)
        root.addLayout(status_row)

        action_row = QHBoxLayout()
        self.install_button = QPushButton("Install Helper...")
        self.install_button.clicked.connect(self._install_helper)
        action_row.addWidget(self.install_button)
        self.remove_button = QPushButton("Remove Helper...")
        self.remove_button.clicked.connect(self._remove_helper)
        action_row.addWidget(self.remove_button)
        action_row.addStretch(1)
        self.inspect_button = QPushButton("Inspect with Privileged Access...")
        self.inspect_button.setObjectName("PrivilegePrimary")
        self.inspect_button.clicked.connect(self._inspect)
        action_row.addWidget(self.inspect_button)
        self.comparison_button = QPushButton("Comparison Report...")
        self.comparison_button.clicked.connect(self._show_comparison_report)
        self.comparison_button.setEnabled(False)
        action_row.addWidget(self.comparison_button)
        root.addLayout(action_row)

        self.tabs = QTabWidget()
        self.tabs.setUsesScrollButtons(True)
        self.tabs.tabBar().setExpanding(False)
        self.tabs.tabBar().setElideMode(Qt.TextElideMode.ElideNone)
        root.addWidget(self.tabs, 1)

        # Established 0.0.3 page surfaces.  No paired Basic/Elevated panes.
        self.booleans_page = SELinuxBooleansPage()
        self.processes_page = SELinuxProcessesPage()
        self.denials_page = SELinuxDenialsPage()
        self.denials_page.privilege_client = self.client
        self.denials_page.privilege_activator = self._activate_for_denials
        self.denials_page.comparison_callback = self._record_observed_pair
        self.policy_modules_page = SELinuxPolicyModulesPage()
        self.permissive_domains_page = SELinuxPermissiveDomainsPage()
        self.users_logins_page = SELinuxUsersLoginsPage()
        self.port_contexts_page = SELinuxPortContextsPage()
        self.file_context_rules_page = SELinuxFileContextRulesPage()

        for page, label in (
            (self.booleans_page, "Booleans"),
            (self.processes_page, "Process Contexts"),
            (self.denials_page, "Recent Denials"),
            (self.policy_modules_page, "Policy Modules"),
            (self.permissive_domains_page, "Permissive Domains"),
            (self.users_logins_page, "Users & Logins"),
            (self.port_contexts_page, "Port Contexts"),
            (self.file_context_rules_page, "File Context Rules"),
        ):
            self.tabs.addTab(page, label)

        self.tabs.currentChanged.connect(self._tab_changed)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.close)
        root.addWidget(buttons)

    def _apply_page_settings(self):
        table_pages = (
            self.booleans_page,
            self.processes_page,
            self.denials_page,
            self.policy_modules_page,
            self.permissive_domains_page,
            self.users_logins_page,
            self.port_contexts_page,
            self.file_context_rules_page,
        )
        for page in table_pages:
            page.apply_host_settings({"metadata_font": self.metadata_font, "hidden_columns": []})
            page.set_theme_colors(
                PANEL,
                FG,
                AMBER_LIGHT,
                "#e5bd70",
                AMBER_DARK,
                AMBER_LIGHT,
            )
        self.set_details_orientation(self.details_orientation)

    def set_details_orientation(self, orientation):
        orientation = str(orientation or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.details_orientation = orientation
        for page in (
            self.booleans_page,
            self.processes_page,
            self.denials_page,
            self.policy_modules_page,
            self.permissive_domains_page,
            self.users_logins_page,
            self.port_contexts_page,
            self.file_context_rules_page,
        ):
            splitter = getattr(page, "splitter", None)
            if splitter is None:
                continue
            details_panel = splitter.widget(1)
            details_layout = details_panel.layout() if details_panel is not None else None
            if orientation == "vertical":
                splitter.setOrientation(Qt.Orientation.Vertical)
                if details_layout is not None:
                    details_layout.setContentsMargins(0, 8, 0, 0)
                splitter.setSizes([430, 330])
            else:
                splitter.setOrientation(Qt.Orientation.Horizontal)
                if details_layout is not None:
                    details_layout.setContentsMargins(8, 0, 0, 0)
                splitter.setSizes([480, 700])

    def _table_pages(self):
        return (
            self.booleans_page, self.processes_page, self.denials_page,
            self.policy_modules_page, self.permissive_domains_page,
            self.users_logins_page, self.port_contexts_page,
            self.file_context_rules_page,
        )

    def set_metadata_panel_visible(self, visible):
        self.metadata_panel_visible = bool(visible)
        for page in self._table_pages():
            splitter = getattr(page, "splitter", None)
            if splitter is not None and splitter.widget(1) is not None:
                splitter.widget(1).setVisible(self.metadata_panel_visible)
        if self.metadata_panel_visible:
            self.set_details_orientation(self.details_orientation)

    def toggle_metadata_panel(self):
        self.set_metadata_panel_visible(not self.metadata_panel_visible)

    def _add_shortcut(self, sequence, callback):
        shortcut = QShortcut(QKeySequence(sequence), self)
        shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        shortcut.activated.connect(callback)
        self._shortcuts.append(shortcut)

    def _install_shortcuts(self):
        self._add_shortcut("F3", self.toggle_metadata_panel)
        self._add_shortcut("Shift+F5", self._refresh_active_inventory)
        self._add_shortcut("Ctrl+L", self.toggle_details_orientation)

    def _refresh_active_inventory(self):
        page = self.tabs.currentWidget()
        refresh = getattr(page, "refresh_btn", None)
        if refresh is not None and refresh.isEnabled():
            refresh.click()  # Never bypass the page's existing privilege/scan controls.

    def toggle_details_orientation(self):
        target = "vertical" if self.details_orientation == "horizontal" else "horizontal"
        parent = self.parentWidget()
        setter = getattr(parent, "set_details_orientation", None)
        if callable(setter):
            setter(target, persist=True)  # Keep the shared orientation setting in sync.
        else:
            self.set_details_orientation(target)

    # ---------- established page behaviour ----------
    def _tab_changed(self, _index):
        page = self.tabs.currentWidget()
        ensure_loaded = getattr(page, "ensure_loaded", None)
        if callable(ensure_loaded):
            ensure_loaded()

    def _reset_deep_lazy_state_for_elevation(self):
        # A page inspected before authorization may contain ordinary-user data.
        # Mark helper-supported lazy pages stale so the next visit/Refresh List
        # performs the same collector through the now-active fixed helper.
        for page in (
            self.policy_modules_page,
            self.permissive_domains_page,
            self.users_logins_page,
            self.port_contexts_page,
            self.file_context_rules_page,
        ):
            if hasattr(page, "_loaded_once"):
                page._loaded_once = False

    # ---------- observed comparison ----------
    def _record_observed_pair(self, op, command, ordinary_result, elevated_result):
        key, label = _comparison_key(str(op))
        self._observed_pairs[key] = {
            "label": label,
            "command": " ".join(str(part) for part in (command or [])),
            "ordinary": _result_snapshot(str(op), ordinary_result),
            "elevated": _result_snapshot(str(op), elevated_result),
        }
        if hasattr(self, "comparison_button"):
            self.comparison_button.setEnabled(bool(self._observed_pairs))

    def _show_comparison_report(self):
        if not self._observed_pairs:
            QMessageBox.information(
                self,
                "Comparison Report",
                "No paired ordinary/helper inspection has been observed yet. Authorize privileged access, then scan or refresh a helper-supported SELinux view.",
            )
            return
        dialog = ComparisonReportDialog(self._observed_pairs, self)
        dialog.exec()

    # ---------- helper lifecycle ----------
    def _refresh_helper_ui(self):
        details = helper_status_details()
        self.helper_status_label.setText(
            f"Helper: {_state_word(details)}"
            + (f" · {details.get('installed_version')}" if details.get("installed_version") else "")
        )
        active = bool(self.client.enabled)
        self.install_button.setEnabled(not active)
        self.remove_button.setVisible(bool(details.get("installed")))
        self.remove_button.setEnabled(not active)
        if active:
            self.inspect_button.setText("Privileged Access: Active")
            self.inspect_button.setObjectName("PrivilegeActive")
            self.inspect_button.setEnabled(False)
        elif self.client.state == "connecting":
            self.inspect_button.setText("Authorizing...")
            self.inspect_button.setObjectName("PrivilegePrimary")
            self.inspect_button.setEnabled(False)
        else:
            self.inspect_button.setText("Inspect with Privileged Access...")
            self.inspect_button.setObjectName("PrivilegePrimary")
            self.inspect_button.setEnabled(bool(details.get("ready")))
        # Re-polish when objectName changes so the active colour takes effect.
        self.inspect_button.style().unpolish(self.inspect_button)
        self.inspect_button.style().polish(self.inspect_button)
        if hasattr(self, "comparison_button"):
            self.comparison_button.setEnabled(bool(self._observed_pairs))

    def _install_helper(self):
        details = helper_status_details()
        verb = "update or repair" if details.get("installed") else "install"
        answer = QMessageBox.question(
            self,
            "SELinux Privileged Helper",
            f"{verb.capitalize()} the optional root-owned SELinux Inspector helper?\n\n"
            "PolicyKit will request administrator authorization. The helper exposes only fixed read-only SELinux queries; the GUI itself is not elevated.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.install_button.setEnabled(False)
        QApplication.processEvents()
        ok, message = install_or_update_helper()
        (QMessageBox.information if ok else QMessageBox.warning)(self, "SELinux Privileged Helper", message)
        self._refresh_helper_ui()
        self.session_state_changed.emit()

    def _remove_helper(self):
        answer = QMessageBox.question(
            self,
            "Remove SELinux Privileged Helper",
            "Remove the optional root-owned SELinux Inspector helper?\n\n"
            "The normal read-only SELinux Inspector will continue to work. PolicyKit will request administrator authorization for removal.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        ok, message = remove_helper()
        (QMessageBox.information if ok else QMessageBox.warning)(self, "SELinux Privileged Helper", message)
        self._refresh_helper_ui()
        self.session_state_changed.emit()

    def _inspect(self):
        if self.client.enabled or self.client.state == "connecting":
            return
        ok, why = self.client.availability()
        if not ok:
            QMessageBox.information(self, "Privileged Inspection", why)
            self._refresh_helper_ui()
            return
        answer = QMessageBox.question(
            self,
            "Privileged SELinux Inspection",
            "Start an ephemeral read-only privileged inspection session?\n\n"
            "PolicyKit will request authorization. Only fixed SELinux audit/policy queries are available to the helper. "
            "No inspection is started automatically; use the normal tab controls after authorization. Closing this window ends the helper session.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.client.start_async()
        self.session_label.setText("Session: Authorizing…")
        self._refresh_helper_ui()
        self.session_state_changed.emit()

    def _activate_for_denials(self, page):
        """Honor 0.0.3's Scan with Privileged Access button without auto-scanning."""
        if self.client.enabled:
            page._scan(privileged=True)
            return
        ok, why = self.client.availability()
        if not ok:
            QMessageBox.information(self, "Privileged SELinux Inspection", why)
            return
        # The denial page has already shown its explicit scan confirmation.
        self._pending_denial_page = page
        self.client.start_async()
        self.session_label.setText("Session: Authorizing…")
        self._refresh_helper_ui()
        self.session_state_changed.emit()

    def _poll(self):
        if self._closing:
            return
        state = self.client.state
        if state == "on" and self.client.enabled:
            newly_active = self._last_state != "on"
            self.session_ever_active = True
            self.session_label.setText("Session: Active")
            if newly_active:
                self._reset_deep_lazy_state_for_elevation()
            if self._pending_denial_page is not None:
                page = self._pending_denial_page
                self._pending_denial_page = None
                QTimer.singleShot(0, lambda p=page: p._scan(privileged=True))
        elif state == "connecting":
            self.session_label.setText("Session: Authorizing…")
        elif state == "error":
            self.session_label.setText("Session: Inactive — " + self.client.message)
            self._pending_denial_page = None
        else:
            self.session_label.setText("Session: Inactive")
        self._last_state = state
        self._refresh_helper_ui()
        self.session_state_changed.emit()

    def closeEvent(self, event):
        # Keep the Python/Qt dialog object alive until Qt has completely
        # unwound the native close/finished signal stack.  r3 cleared the
        # shared page client during closeEvent itself; queued page work and
        # parent finished handlers could consequently observe a half-torn-
        # down dialog when the window-manager X button was used.
        if self._closing:
            event.accept()
            return

        self._closing = True
        self._timer.stop()
        try:
            self._timer.timeout.disconnect(self._poll)
        except (TypeError, RuntimeError):
            pass

        had_session = bool(self.session_ever_active or self.client.enabled)
        self._pending_denial_page = None

        # End privilege synchronously before accepting the close.  Do not
        # clear the page-level client here: it is the same (now inactive)
        # PrivilegeClient owned by the applet and is safe for any already-
        # queued page callback to observe while Qt finishes closing.
        self.client.stop()
        set_observed_callback(None)
        self._observed_pairs.clear()
        self.session_state_changed.emit()
        self.closing.emit(had_session)

        event.accept()
        super().closeEvent(event)
