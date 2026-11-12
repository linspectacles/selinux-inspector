#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspector Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

APPLET_ID = "linspectacles-selinux-inspector"
APPLET_NAME = "SELinux Inspector"
APPLET_AUTHOR = "brunonlinespace"
APPLET_EDITOR = "brunonlinespace"
APPLET_ORGANIZATION_ID = "linspectacles"
APPLET_ORGANIZATION_URL = "https://github.com/linspectacles/"
APPLET_REPOSITORY = "https://github.com/linspectacles/selinux-inspector"
APPLET_VERSION = "0.0.10"

import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QSettings, QTimer, Qt, QUrl
from PyQt6.QtGui import QColor, QKeySequence, QPixmap, QShortcut, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ._support import (
    BaseInspectorTab,
    apply_metadata_font,
    export_records_dialog,
    metadata_font_qss,
)

from .deep_pages import (
    SELinuxFileContextRulesPage,
    SELinuxPermissiveDomainsPage,
    SELinuxPolicyModulesPage,
    SELinuxPortContextsPage,
    SELinuxUsersLoginsPage,
    SOURCES_TEXT,
)
from .privilege import PrivilegeClient
from .privileged_window import PrivilegedInspectionDialog


def _run(command, timeout=10):
    """Run a fixed argv command without a shell and return CompletedProcess."""
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _command_output(command, timeout=10):
    try:
        result = _run(command, timeout=timeout)
    except FileNotFoundError:
        return None, "Command not available."
    except subprocess.TimeoutExpired:
        return None, "Command timed out."
    except Exception as exc:
        return None, str(exc)
    output = (result.stdout or result.stderr or "").strip()
    return (output, None) if result.returncode == 0 else (output, output or f"Command exited with status {result.returncode}.")


def _context_domain(context):
    parts = str(context or "").split(":")
    return parts[2] if len(parts) >= 3 else "-"


def _quoted_or_word(text, key):
    match = re.search(rf"\b{re.escape(key)}=(?:\"([^\"]*)\"|'([^']*)'|(\S+))", text)
    if not match:
        return ""
    return next((group for group in match.groups() if group is not None), "")


class MetadataTextPage(QWidget):
    """Small base for non-table SELinux pages that use the shared metadata font."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._metadata_font = None
        self._text_bg = "#1e1e1e"
        self._text_fg = "#dcdcdc"

    def _make_text(self):
        text = QTextEdit()
        text.setReadOnly(True)
        self._metadata_font = apply_metadata_font(text)
        text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        return text

    def _apply_text_style(self, text):
        text.setStyleSheet(
            "QTextEdit { "
            f"background: {self._text_bg}; color: {self._text_fg}; border: 1px solid #666; "
            f"{metadata_font_qss(self._metadata_font)} "
            "}"
        )

    def apply_metadata_setting(self, serialized):
        if not hasattr(self, "info_text"):
            return
        self._metadata_font = apply_metadata_font(self.info_text, serialized)
        self._apply_text_style(self.info_text)


class SELinuxStatusPage(MetadataTextPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.records = []
        self.setup_ui()
        self.refresh_status()

    def setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        top = QHBoxLayout()
        self.title_label = QLabel("SELinux Status")
        font = self.title_label.font()
        font.setBold(True)
        font.setPointSize(max(font.pointSize(), 11))
        self.title_label.setFont(font)
        top.addWidget(self.title_label)
        top.addStretch(1)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_status)
        top.addWidget(self.refresh_btn)

        self.export_btn = QPushButton("Export...")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_status)
        top.addWidget(self.export_btn)
        root.addLayout(top)

        note = QLabel("Read-only summary of the active SELinux policy and this process context.")
        note.setWordWrap(True)
        root.addWidget(note)

        self.info_text = self._make_text()
        self._apply_text_style(self.info_text)
        root.addWidget(self.info_text, 1)

        self.status_lbl = QLabel("Ready")
        status_font = self.status_lbl.font()
        status_font.setItalic(True)
        self.status_lbl.setFont(status_font)
        self.status_lbl.setStyleSheet(
            "QLabel { background: #252526; color: #b5cea8; padding: 4px; }"
        )
        root.addWidget(self.status_lbl)

    def refresh_status(self):
        self.refresh_btn.setEnabled(False)
        self.info_text.setPlainText("Reading SELinux status...")
        QApplication.processEvents()

        records = []
        status_map = {}

        sestatus = shutil.which("sestatus")
        if sestatus:
            output, error = _command_output([sestatus], timeout=8)
            if output:
                for line in output.splitlines():
                    if ":" not in line:
                        continue
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()
                    if key:
                        status_map[key] = value
            elif error:
                status_map["SELinux status"] = error
        else:
            status_map["SELinux status"] = "sestatus command is not installed."

        getenforce = shutil.which("getenforce")
        if getenforce:
            output, _error = _command_output([getenforce], timeout=5)
            if output:
                status_map.setdefault("Current mode", output.splitlines()[0].strip())
        else:
            enforce_file = Path("/sys/fs/selinux/enforce")
            try:
                value = enforce_file.read_text(encoding="utf-8").strip()
                status_map.setdefault("Current mode", "Enforcing" if value == "1" else "Permissive")
            except OSError:
                status_map.setdefault("Current mode", "Unavailable")

        id_cmd = shutil.which("id")
        if id_cmd:
            output, _error = _command_output([id_cmd, "-Z"], timeout=5)
            if output:
                status_map["Current process context"] = output.splitlines()[0].strip()

        status_map["SELinux filesystem"] = (
            "Mounted" if Path("/sys/fs/selinux").is_dir() else "Not mounted"
        )

        config_path = Path("/etc/selinux/config")
        if config_path.is_file():
            try:
                for raw in config_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    if key == "SELINUX":
                        status_map.setdefault("Mode from config file", value)
                    elif key == "SELINUXTYPE":
                        status_map.setdefault("Policy from config file", value)
            except OSError:
                pass

        for key, value in status_map.items():
            records.append({"property": key, "value": value})

        self.records = records
        lines = [f"{record['property']}: {record['value']}" for record in records]
        self.info_text.setPlainText("\n".join(lines) if lines else "SELinux status is unavailable.")
        enabled_value = str(status_map.get("SELinux status", "")).lower()
        if enabled_value == "enabled":
            self.status_lbl.setText("SELinux is enabled. No settings were changed.")
        elif "disabled" in enabled_value:
            self.status_lbl.setText("SELinux is disabled on this system.")
        else:
            self.status_lbl.setText("SELinux status inspected. No settings were changed.")
        self.export_btn.setEnabled(bool(self.records))
        self.refresh_btn.setEnabled(True)

    def export_status(self):
        if not self.records:
            QMessageBox.information(self, "Export", "There is no SELinux status data to export yet.")
            return
        path = export_records_dialog(
            self,
            "SELinux Status",
            self.records,
            columns=[("property", "Property"), ("value", "Value")],
        )
        if path is not None:
            self.status_lbl.setText(f"Exported SELinux status to {path}")


class SELinuxBooleansPage(BaseInspectorTab):
    def __init__(self, parent=None):
        columns = [
            ("name", "Boolean", 250, "left"),
            ("state", "State", 80, "left"),
            ("default", "Default", 80, "left"),
            ("description", "Description", 380, "left"),
        ]
        categories = ["All Categories", "Enabled", "Disabled"]
        super().__init__("Total SELinux Booleans", columns, categories, parent)
        self.export_title = "SELinux Booleans"
        self.load_modules()

    @staticmethod
    def _semanage_metadata():
        semanage = shutil.which("semanage")
        if not semanage:
            return {}
        try:
            result = _run([semanage, "boolean", "-l"], timeout=12)
        except Exception:
            return {}
        if result.returncode != 0:
            return {}
        metadata = {}
        pattern = re.compile(r"^(\S+)\s+\((on|off)\s*,\s*(on|off)\)\s*(.*)$", re.IGNORECASE)
        for line in result.stdout.splitlines():
            match = pattern.match(line.strip())
            if not match:
                continue
            name, current, default, description = match.groups()
            metadata[name] = {
                "current": current.lower(),
                "default": default.lower(),
                "description": description.strip() or "-",
            }
        return metadata

    def load_modules(self):
        self.modules_data.clear()
        getsebool = shutil.which("getsebool")
        if not getsebool:
            self.stats_label.setText("Total SELinux Booleans: 0")
            self.table.setRowCount(0)
            self.clear_info()
            self.append_info("The getsebool command is not installed.\n")
            self.set_status("SELinux boolean tools are unavailable.")
            self.export_btn.setEnabled(False)
            return

        self.set_status("Reading SELinux booleans...")
        QApplication.processEvents()
        try:
            result = _run([getsebool, "-a"], timeout=12)
        except subprocess.TimeoutExpired:
            self.set_status("Timed out while reading SELinux booleans.")
            return
        except Exception as exc:
            self.set_status(f"Could not read SELinux booleans: {exc}")
            return

        if result.returncode != 0:
            message = (result.stderr or result.stdout or "getsebool returned an error.").strip()
            self.clear_info()
            self.append_info(message + "\n")
            self.stats_label.setText("Total SELinux Booleans: 0")
            self.table.setRowCount(0)
            self.export_btn.setEnabled(False)
            self.set_status("SELinux booleans are unavailable on this system.")
            return

        extra = self._semanage_metadata()
        for line in result.stdout.splitlines():
            match = re.match(r"^\s*(\S+)\s+-->\s+(on|off)\s*$", line, re.IGNORECASE)
            if not match:
                continue
            name, state = match.groups()
            state = state.lower()
            meta = extra.get(name, {})
            self.modules_data.append(
                {
                    "name": name,
                    "state": state,
                    "default": meta.get("default", "-"),
                    "description": meta.get("description", "-"),
                    "category": "Enabled" if state == "on" else "Disabled",
                }
            )
        self.modules_data.sort(key=lambda item: item["name"].lower())
        self.stats_label.setText(f"Total SELinux Booleans: {len(self.modules_data)}")
        self.filter_modules()
        self.clear_info()
        self.set_status("Successfully refreshed SELinux booleans.")

    def on_module_select(self):
        record = self.current_record()
        if not record:
            return
        self.clear_info()
        self.append_key_value("Boolean", record.get("name", ""))
        self.append_key_value("Current State", record.get("state", ""))
        self.append_key_value("Policy Default", record.get("default", "-"))
        self.append_key_value("Description", record.get("description", "-"))
        self.append_info("\nRead-only inspection: LinSpectacles does not change SELinux booleans.\n")
        self.set_status(f"Inspecting SELinux boolean [{record.get('name', '')}].")


class SELinuxProcessesPage(BaseInspectorTab):
    def __init__(self, parent=None):
        columns = [
            ("process", "Process", 180, "left"),
            ("pid", "PID", 85, "right"),
            ("user", "User", 120, "left"),
            ("domain", "Domain", 180, "left"),
            ("context", "SELinux Context", 360, "left"),
        ]
        super().__init__("Total Process Contexts", columns, ["All Domains"], parent)
        self.export_title = "SELinux Process Contexts"
        self.category_label.setText("Domain:")
        self.load_modules()

    def load_modules(self):
        self.modules_data.clear()
        ps = shutil.which("ps")
        if not ps:
            self.set_status("ps command unavailable.")
            return
        try:
            result = _run([ps, "-e", "-o", "label=", "-o", "pid=", "-o", "user=", "-o", "comm="], timeout=10)
        except subprocess.TimeoutExpired:
            self.set_status("Timed out while reading process security contexts.")
            return
        except Exception as exc:
            self.set_status(f"Could not read process contexts: {exc}")
            return

        if result.returncode != 0:
            message = (result.stderr or result.stdout or "ps could not return security contexts.").strip()
            self.clear_info()
            self.append_info(message + "\n")
            self.stats_label.setText("Total Process Contexts: 0")
            self.table.setRowCount(0)
            self.export_btn.setEnabled(False)
            self.set_status("Process SELinux contexts are unavailable.")
            return

        for line in result.stdout.splitlines():
            parts = line.strip().split(None, 3)
            if len(parts) < 4:
                continue
            context, pid_text, user, process = parts
            try:
                pid = int(pid_text)
            except ValueError:
                continue
            self.modules_data.append(
                {
                    "process": process,
                    "pid": pid,
                    "user": user,
                    "domain": _context_domain(context),
                    "context": context,
                    "category": _context_domain(context),
                }
            )
        self.modules_data.sort(key=lambda item: (item["domain"].lower(), item["process"].lower(), item["pid"]))
        current_domain = self.category_dropdown.currentText()
        domains = sorted(
            {str(item.get("domain", "-") or "-") for item in self.modules_data},
            key=str.casefold,
        )
        self.category_dropdown.blockSignals(True)
        self.category_dropdown.clear()
        self.category_dropdown.addItem("All Domains")
        self.category_dropdown.addItems(domains)
        if current_domain in domains:
            self.category_dropdown.setCurrentText(current_domain)
        else:
            self.category_dropdown.setCurrentIndex(0)
        self.category_dropdown.blockSignals(False)
        self.stats_label.setText(f"Total Process Contexts: {len(self.modules_data)}")
        self.filter_modules()
        self.clear_info()
        self.set_status("Successfully refreshed process SELinux contexts.")

    def filter_modules(self, *_):
        # Reuse the authoritative BaseInspectorTab filtering implementation while
        # presenting its generic category slot as a SELinux Domain filter.
        if self.category_dropdown.currentText() != "All Domains":
            return super().filter_modules()
        self.category_dropdown.blockSignals(True)
        self.category_dropdown.setItemText(0, "All Categories")
        try:
            super().filter_modules()
        finally:
            self.category_dropdown.setItemText(0, "All Domains")
            self.category_dropdown.blockSignals(False)

    def on_module_select(self):
        record = self.current_record()
        if not record:
            return
        self.clear_info()
        self.append_key_value("Process", record.get("process", ""))
        self.append_key_value("PID", record.get("pid", ""))
        self.append_key_value("User", record.get("user", ""))
        self.append_key_value("SELinux Domain", record.get("domain", ""))
        self.append_key_value("Full Context", record.get("context", ""))
        self.set_status(f"Inspecting SELinux process context for PID {record.get('pid', '')}.")


class SELinuxDenialsPage(BaseInspectorTab):
    AUDIT_TS_RE = re.compile(r"msg=audit\((\d+(?:\.\d+)?):")
    PERMISSION_RE = re.compile(r"avc:\s+denied\s+\{\s*([^}]*)\s*\}", re.IGNORECASE)

    def __init__(self, parent=None):
        columns = [
            ("time", "Time", 145, "left"),
            ("process", "Process", 150, "left"),
            ("pid", "PID", 75, "right"),
            ("permission", "Denied Permission", 160, "left"),
            ("target_class", "Target Class", 110, "left"),
            ("path", "Path / Target", 300, "left"),
        ]
        categories = ["All Categories", "Enforcing Denial", "Permissive Denial"]
        super().__init__("Recent SELinux Denials", columns, categories, parent)
        self.export_title = "Recent SELinux Denials"
        self.has_scanned = False
        self.stats_label.setText("Recent SELinux Denials: Not scanned")
        self.refresh_btn.setText("Scan")
        self.export_btn.setEnabled(False)
        self.clear_info()
        self.append_info(
            "Recent audit denials are not scanned automatically.\n\n"
            "Scan reads audit records with the current user's permissions. If access is "
            "restricted, the applet-level Privileged Inspection window can compare the "
            "ordinary result with the optional fixed read-only helper.\n"
        )
        self.set_status("Not scanned - choose Scan when needed.")

    @classmethod
    def _event_time(cls, raw):
        match = cls.AUDIT_TS_RE.search(raw)
        if not match:
            return "-"
        try:
            timestamp = float(match.group(1))
            return datetime.fromtimestamp(timestamp).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError, OverflowError):
            return "-"

    @classmethod
    def _parse_events(cls, text):
        events = []
        blocks = []
        current = []
        for line in (text or "").splitlines():
            if line.strip() == "----":
                if current:
                    blocks.append("\n".join(current).strip())
                    current = []
                continue
            current.append(line)
        if current:
            blocks.append("\n".join(current).strip())

        for block in blocks:
            if not block or block.strip().lower() == "<no matches>":
                continue
            permission_match = cls.PERMISSION_RE.search(block)
            if not permission_match and "type=USER_AVC" not in block:
                continue
            permission = " ".join(permission_match.group(1).split()) if permission_match else "denied"
            pid_text = _quoted_or_word(block, "pid")
            try:
                pid = int(pid_text)
            except (TypeError, ValueError):
                pid = 0
            process = _quoted_or_word(block, "comm") or Path(_quoted_or_word(block, "exe") or "").name or "-"
            path = _quoted_or_word(block, "path") or _quoted_or_word(block, "name") or _quoted_or_word(block, "dest") or "-"
            scontext = _quoted_or_word(block, "scontext") or "-"
            tcontext = _quoted_or_word(block, "tcontext") or "-"
            tclass = _quoted_or_word(block, "tclass") or "-"
            permissive = _quoted_or_word(block, "permissive")
            category = "Permissive Denial" if permissive == "1" else "Enforcing Denial"
            events.append(
                {
                    "time": cls._event_time(block),
                    "process": process,
                    "pid": pid,
                    "permission": permission,
                    "target_class": tclass,
                    "path": path,
                    "source_context": scontext,
                    "target_context": tcontext,
                    "category": category,
                    "_raw": block,
                }
            )
        return events

    def _scan(self):
        ausearch = shutil.which("ausearch")
        if not ausearch:
            self.clear_info()
            self.append_info(
                "The ausearch command is not installed. Install the Linux audit userspace "
                "tools to inspect AVC denials.\n"
            )
            self.set_status("ausearch command unavailable.")
            self.stats_label.setText("Recent SELinux Denials: 0")
            self.export_btn.setEnabled(False)
            return

        command = [ausearch, "-m", "AVC,USER_AVC", "-ts", "recent", "-i"]
        self.refresh_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.set_status("Reading recent SELinux audit denials as the current user...")
        QApplication.processEvents()

        try:
            result = _run(command, timeout=60)
        except subprocess.TimeoutExpired:
            self.set_status("SELinux denial scan timed out.")
            self.refresh_btn.setEnabled(True)
            return
        except Exception as exc:
            self.set_status(f"Could not scan SELinux denials: {exc}")
            self.refresh_btn.setEnabled(True)
            return

        output = result.stdout or ""
        self.modules_data = self._parse_events(output)
        self.has_scanned = True
        self.stats_label.setText(f"Recent SELinux Denials: {len(self.modules_data)}")
        self.filter_modules()
        self.clear_info()

        stderr = (result.stderr or "").strip()
        if result.returncode not in (0, 1) and not self.modules_data:
            message = stderr or output.strip() or f"ausearch exited with status {result.returncode}."
            self.append_info(message + "\n")
            self.append_info(
                "\nIf this is an audit-log permission restriction, use Privileged Inspection "
                "at the applet level for an explicit elevated scan in the dedicated window.\n"
            )
            self.set_status("SELinux audit records could not be read completely as the current user.")
        elif self.modules_data:
            self.set_status(
                f"Found {len(self.modules_data)} recent SELinux denial(s) using ordinary-user inspection."
            )
        else:
            self.append_info(
                "The ordinary-user query returned no matching AVC or USER_AVC denials. "
                "This does not prove that no restricted audit records exist.\n"
            )
            self.set_status("Ordinary-user query returned no recent SELinux denials.")

        self.export_btn.setEnabled(bool(self.modules_data))
        self.refresh_btn.setEnabled(True)

    def load_modules(self):
        self._scan()

    def on_module_select(self):
        record = self.current_record()
        if not record:
            return
        self.clear_info()
        self.append_key_value("Time", record.get("time", "-"))
        self.append_key_value("Process", record.get("process", "-"))
        self.append_key_value("PID", record.get("pid", 0) or "-")
        self.append_key_value("Denied Permission", record.get("permission", "-"))
        self.append_key_value("Target Class", record.get("target_class", "-"))
        self.append_key_value("Path / Target", record.get("path", "-"))
        self.append_key_value("Source Context", record.get("source_context", "-"))
        self.append_key_value("Target Context", record.get("target_context", "-"))
        self.append_key_value("Mode", record.get("category", "-"))
        self.append_info("\n--- Raw Audit Event ---\n")
        self.append_info(record.get("_raw", "") + "\n")
        self.set_status("Inspecting selected SELinux denial event.")


class SELinuxFileContextPage(MetadataTextPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.records = []
        self.setup_ui()

    def setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        top = QHBoxLayout()
        title = QLabel("File Context Check")
        font = title.font()
        font.setBold(True)
        font.setPointSize(max(font.pointSize(), 11))
        title.setFont(font)
        top.addWidget(title)
        top.addStretch(1)

        self.export_btn = QPushButton("Export...")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_result)
        top.addWidget(self.export_btn)
        root.addLayout(top)

        note = QLabel(
            "Compare a file or directory's current SELinux context with the context expected by the active policy. "
            "This check is read-only; LinSpectacles never runs chcon or restorecon."
        )
        note.setWordWrap(True)
        root.addWidget(note)

        chooser = QHBoxLayout()
        self.path_entry = QLineEdit()
        self.path_entry.setPlaceholderText("Choose a file or directory to inspect...")
        self.path_entry.returnPressed.connect(self.check_path)
        chooser.addWidget(self.path_entry, 1)

        file_btn = QPushButton("Choose File...")
        file_btn.clicked.connect(self.choose_file)
        chooser.addWidget(file_btn)

        folder_btn = QPushButton("Choose Folder...")
        folder_btn.clicked.connect(self.choose_folder)
        chooser.addWidget(folder_btn)

        check_btn = QPushButton("Check")
        check_btn.clicked.connect(self.check_path)
        chooser.addWidget(check_btn)
        root.addLayout(chooser)

        self.info_text = self._make_text()
        self._apply_text_style(self.info_text)
        self.info_text.setPlainText("No path has been checked yet.")
        root.addWidget(self.info_text, 1)

        self.status_lbl = QLabel("Ready - choose a file or directory to compare SELinux contexts.")
        status_font = self.status_lbl.font()
        status_font.setItalic(True)
        self.status_lbl.setFont(status_font)
        self.status_lbl.setStyleSheet(
            "QLabel { background: #252526; color: #b5cea8; padding: 4px; }"
        )
        root.addWidget(self.status_lbl)

    def choose_file(self):
        path, _selected = QFileDialog.getOpenFileName(self, "Choose File for SELinux Context Check")
        if path:
            self.path_entry.setText(path)
            self.check_path()

    def choose_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Choose Directory for SELinux Context Check")
        if path:
            self.path_entry.setText(path)
            self.check_path()

    @staticmethod
    def _actual_context(path):
        ls_cmd = shutil.which("ls")
        if not ls_cmd:
            return "Unavailable", "ls command is not available."
        try:
            result = _run([ls_cmd, "-Zd", "--", path], timeout=8)
        except Exception as exc:
            return "Unavailable", str(exc)
        output = (result.stdout or result.stderr or "").strip()
        if result.returncode != 0 or not output:
            return "Unavailable", output or "Could not read current file context."
        context = output.split(None, 1)[0]
        return context, ""

    @staticmethod
    def _expected_context(path):
        matchpathcon = shutil.which("matchpathcon")
        if not matchpathcon:
            return "Unavailable", "matchpathcon is not installed."
        try:
            result = _run([matchpathcon, "-n", path], timeout=8)
        except Exception as exc:
            return "Unavailable", str(exc)
        output = (result.stdout or result.stderr or "").strip()
        if result.returncode != 0 or not output:
            return "Unavailable", output or "No expected policy context was returned."
        return output.splitlines()[0].strip(), ""

    def check_path(self):
        raw = self.path_entry.text().strip()
        if not raw:
            QMessageBox.information(self, "File Context Check", "Choose or enter a file or directory first.")
            return
        path = os.path.abspath(os.path.expanduser(raw))
        if not os.path.lexists(path):
            QMessageBox.warning(self, "File Context Check", "The selected path does not exist.")
            return
        self.path_entry.setText(path)

        actual, actual_error = self._actual_context(path)
        expected, expected_error = self._expected_context(path)
        if actual != "Unavailable" and expected != "Unavailable":
            match = actual == expected
            result_text = "Matches policy" if match else "Differs from policy expectation"
        else:
            match = None
            result_text = "Comparison unavailable"

        record = {
            "path": path,
            "actual_context": actual,
            "expected_context": expected,
            "result": result_text,
        }
        self.records = [record]

        lines = [
            f"Path: {path}",
            f"Actual Context: {actual}",
            f"Expected Context: {expected}",
            f"Result: {result_text}",
        ]
        if actual_error:
            lines.extend(["", f"Actual Context Note: {actual_error}"])
        if expected_error:
            lines.extend(["", f"Expected Context Note: {expected_error}"])
        lines.extend(["", "Read-only inspection: no file labels were changed."])
        self.info_text.setPlainText("\n".join(lines))
        self.export_btn.setEnabled(True)
        if match is True:
            self.status_lbl.setText("The current file context matches the policy expectation.")
        elif match is False:
            self.status_lbl.setText("The current file context differs from the policy expectation.")
        else:
            self.status_lbl.setText("File context checked, but a complete comparison was unavailable.")

    def export_result(self):
        if not self.records:
            QMessageBox.information(self, "Export", "No file-context check has been performed yet.")
            return
        path = export_records_dialog(
            self,
            "SELinux File Context Check",
            self.records,
            columns=[
                ("path", "Path"),
                ("actual_context", "Actual Context"),
                ("expected_context", "Expected Context"),
                ("result", "Result"),
            ],
        )
        if path is not None:
            self.status_lbl.setText(f"Exported file-context check to {path}")


class SELinuxFileContextDialogPage(QWidget):
    """File Context Check surface embedded in the ordinary Status dialog."""

    def __init__(self, metadata_font="", initial_records=None, record_callback=None, parent=None):
        super().__init__(parent)
        self.records = list(initial_records or [])
        self._record_callback = record_callback

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        note = QLabel(
            "Compare a file or directory's current SELinux context with the context expected by the active policy. "
            "This check is read-only; LinSpectacles never runs chcon or restorecon."
        )
        note.setWordWrap(True)
        root.addWidget(note)

        chooser = QHBoxLayout()
        self.path_entry = QLineEdit()
        self.path_entry.setPlaceholderText("Choose a file or directory to inspect...")
        self.path_entry.returnPressed.connect(self.check_path)
        chooser.addWidget(self.path_entry, 1)

        file_btn = QPushButton("Choose File...")
        file_btn.clicked.connect(self.choose_file)
        chooser.addWidget(file_btn)

        folder_btn = QPushButton("Choose Folder...")
        folder_btn.clicked.connect(self.choose_folder)
        chooser.addWidget(folder_btn)

        check_btn = QPushButton("Check")
        check_btn.clicked.connect(self.check_path)
        chooser.addWidget(check_btn)
        root.addLayout(chooser)

        self.canvas = QTextEdit()
        self.canvas.setReadOnly(True)
        self.canvas.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        chosen_font = apply_metadata_font(self.canvas, metadata_font)
        self.canvas.setStyleSheet(
            "QTextEdit { "
            f"{metadata_font_qss(chosen_font)} "
            "background-color: #151719; color: #dcdcdc; "
            "border: 1px solid #333333; "
            "}"
        )
        root.addWidget(self.canvas, 1)

        if self.records:
            self._render_record(self.records[-1])
        else:
            self._render_message("No path has been checked yet.")

    def _formats(self):
        key_format = QTextCharFormat()
        key_format.setForeground(QColor("#9cdcfe"))
        key_format.setFontWeight(600)
        value_format = QTextCharFormat()
        value_format.setForeground(QColor("#dcdcdc"))
        return key_format, value_format

    def _render_message(self, message):
        self.canvas.clear()
        _key, value_format = self._formats()
        cursor = self.canvas.textCursor()
        cursor.insertText(str(message) + "\n", value_format)
        self.canvas.setTextCursor(cursor)
        self.canvas.moveCursor(QTextCursor.MoveOperation.Start)
        self.canvas.verticalScrollBar().setValue(0)

    def _render_record(self, record):
        self.canvas.clear()
        key_format, value_format = self._formats()
        cursor = self.canvas.textCursor()
        fields = [
            ("Path", record.get("path", "")),
            ("Actual Context", record.get("actual_context", "")),
            ("Expected Context", record.get("expected_context", "")),
            ("Result", record.get("result", "")),
        ]
        if record.get("actual_note"):
            fields.append(("Actual Context Note", record.get("actual_note", "")))
        if record.get("expected_note"):
            fields.append(("Expected Context Note", record.get("expected_note", "")))
        fields.append(("Inspection", "Read-only; no file labels were changed."))
        for label, value in fields:
            cursor.insertText(f"{label}: ", key_format)
            cursor.insertText(f"{value}\n", value_format)
        self.canvas.setTextCursor(cursor)
        self.canvas.moveCursor(QTextCursor.MoveOperation.Start)
        self.canvas.verticalScrollBar().setValue(0)

    def choose_file(self):
        path, _selected = QFileDialog.getOpenFileName(self, "Choose File for SELinux Context Check")
        if path:
            self.path_entry.setText(path)
            self.check_path()

    def choose_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Choose Directory for SELinux Context Check")
        if path:
            self.path_entry.setText(path)
            self.check_path()

    def check_path(self):
        raw = self.path_entry.text().strip()
        if not raw:
            QMessageBox.information(self, "File Context Check", "Choose or enter a file or directory first.")
            return
        path = os.path.abspath(os.path.expanduser(raw))
        if not os.path.lexists(path):
            QMessageBox.warning(self, "File Context Check", "The selected path does not exist.")
            return
        self.path_entry.setText(path)

        actual, actual_error = SELinuxFileContextPage._actual_context(path)
        expected, expected_error = SELinuxFileContextPage._expected_context(path)
        if actual != "Unavailable" and expected != "Unavailable":
            result_text = "Matches policy" if actual == expected else "Differs from policy expectation"
        else:
            result_text = "Comparison unavailable"

        record = {
            "path": path,
            "actual_context": actual,
            "expected_context": expected,
            "result": result_text,
            "actual_note": actual_error,
            "expected_note": expected_error,
        }
        self.records = [record]
        self._render_record(record)
        if callable(self._record_callback):
            self._record_callback(list(self.records))


class SELinuxStatusDialog(QDialog):
    """Status + File Context Check using the Systemd Unit Details dialog structure."""

    def __init__(self, owner, parent=None):
        super().__init__(parent or owner)
        self.owner = owner
        metadata_font = owner._serialized_metadata_font
        self.setWindowTitle("SELinux Status — SELinux Inspector")
        self.resize(980, 720)

        root = QVBoxLayout(self)
        note = QLabel(
            "Values below are reported by SELinux and the local system interfaces. "
            "LinSpectacles does not change SELinux state."
        )
        note.setWordWrap(True)
        root.addWidget(note)

        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        status_page = SELinuxStatusPage()
        records = list(status_page.records)
        status_page.deleteLater()

        page = QWidget()
        page_layout = QVBoxLayout(page)
        canvas = QTextEdit()
        canvas.setReadOnly(True)
        canvas.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        chosen_font = apply_metadata_font(canvas, metadata_font)
        canvas.setStyleSheet(
            "QTextEdit { "
            f"{metadata_font_qss(chosen_font)} "
            "background-color: #151719; color: #dcdcdc; "
            "border: 1px solid #333333; "
            "}"
        )

        key_format = QTextCharFormat()
        key_format.setForeground(QColor("#9cdcfe"))
        key_format.setFontWeight(600)
        value_format = QTextCharFormat()
        value_format.setForeground(QColor("#dcdcdc"))
        cursor = canvas.textCursor()
        if records:
            for record in records:
                cursor.insertText(f"{record.get('property', '')}: ", key_format)
                cursor.insertText(f"{record.get('value', '')}\n", value_format)
        else:
            cursor.insertText("SELinux status is unavailable.\n", value_format)
        canvas.setTextCursor(cursor)
        canvas.moveCursor(QTextCursor.MoveOperation.Start)
        canvas.verticalScrollBar().setValue(0)
        page_layout.addWidget(canvas, 1)
        tabs.addTab(page, "Status")

        file_page = SELinuxFileContextDialogPage(
            metadata_font,
            initial_records=owner._file_context_records,
            record_callback=owner._set_file_context_records,
        )
        tabs.addTab(file_page, "File Context Check")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)


class SELinuxOptionsDialog(QDialog):
    """Standard LinSpectacles applet Options surface for SELinux Inspector."""

    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle("Options — SELinux Inspector")
        self.resize(980, 720)

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        appearance_page = QWidget()
        appearance_layout = QVBoxLayout(appearance_page)
        appearance_layout.setContentsMargins(12, 12, 12, 12)
        appearance_layout.setSpacing(10)

        appearance_heading = QLabel("Metadata display")
        heading_font = appearance_heading.font()
        heading_font.setBold(True)
        appearance_heading.setFont(heading_font)
        appearance_layout.addWidget(appearance_heading)

        appearance_note = QLabel(
            "Choose how table inventories and Metadata Details panes are arranged. "
            "The same setting is used by the ordinary and privileged SELinux table views."
        )
        appearance_note.setWordWrap(True)
        appearance_layout.addWidget(appearance_note)

        layout_row = QHBoxLayout()
        layout_row.addWidget(QLabel("Record details layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Horizontal", "Vertical"])
        self.layout_combo.setCurrentText(
            "Vertical" if owner.details_orientation == "vertical" else "Horizontal"
        )
        self.layout_combo.currentTextChanged.connect(self._layout_changed)
        layout_row.addWidget(self.layout_combo)
        layout_row.addStretch(1)
        appearance_layout.addLayout(layout_row)

        self.show_metadata_panel = QCheckBox("Show Metadata Details panel (F3)")
        self.show_metadata_panel.setChecked(owner.metadata_panel_visible)
        self.show_metadata_panel.toggled.connect(self._metadata_panel_changed)
        appearance_layout.addWidget(self.show_metadata_panel)

        shortcut_note = QLabel(
            "Shortcuts: F3 hides/restores Metadata Details; "
            "Shift+F5 refreshes or scans the active inventory; "
            "Ctrl+L toggles Horizontal/Vertical layout; Ctrl+/ opens Options. "
            "F3 also works independently in the privileged inspection window."
        )
        shortcut_note.setWordWrap(True)
        appearance_layout.addWidget(shortcut_note)
        appearance_layout.addStretch(1)
        tabs.addTab(appearance_page, "Appearance")

        sources_page = QWidget()
        sources_layout = QVBoxLayout(sources_page)
        sources_layout.setContentsMargins(12, 12, 12, 12)
        sources_layout.setSpacing(10)

        sources_heading = QLabel("Data Sources")
        sources_heading_font = sources_heading.font()
        sources_heading_font.setBold(True)
        sources_heading_font.setPointSize(max(sources_heading_font.pointSize(), 11))
        sources_heading.setFont(sources_heading_font)
        sources_layout.addWidget(sources_heading)

        sources_note = QLabel(
            "Commands and system interfaces used by each read-only SELinux Inspector view."
        )
        sources_note.setWordWrap(True)
        sources_layout.addWidget(sources_note)

        sources_text = QTextEdit()
        sources_text.setReadOnly(True)
        sources_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        chosen_font = apply_metadata_font(sources_text, owner._serialized_metadata_font)
        sources_text.setStyleSheet(
            "QTextEdit { "
            f"{metadata_font_qss(chosen_font)} "
            "background-color: #151719; color: #dcdcdc; "
            "border: 1px solid #333333; }"
        )

        source_key_format = QTextCharFormat()
        source_key_format.setForeground(QColor("#9cdcfe"))
        source_key_format.setFontWeight(600)
        source_value_format = QTextCharFormat()
        source_value_format.setForeground(QColor("#dcdcdc"))

        cursor = sources_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        for line in SOURCES_TEXT.splitlines():
            if line and not line[:1].isspace():
                cursor.insertText(line + "\n", source_key_format)
            else:
                cursor.insertText(line + "\n", source_value_format)
        sources_text.setTextCursor(cursor)
        sources_text.moveCursor(QTextCursor.MoveOperation.Start)
        sources_layout.addWidget(sources_text, 1)
        tabs.addTab(sources_page, "Sources")

        export_page = QWidget()
        export_layout = QVBoxLayout(export_page)
        export_layout.setContentsMargins(12, 12, 12, 12)
        export_layout.setSpacing(10)

        export_heading = QLabel("Export")
        export_heading_font = export_heading.font()
        export_heading_font.setBold(True)
        export_heading.setFont(export_heading_font)
        export_layout.addWidget(export_heading)

        export_note = QLabel(
            "Choose which ordinary SELinux Inspector views to include in one export. "
            "Export uses the data currently collected by each view; scan-only views remain unscanned unless you scan them first."
        )
        export_note.setWordWrap(True)
        export_layout.addWidget(export_note)

        self.export_view_checks = {}
        for key, label in owner.export_view_specs():
            checkbox = QCheckBox(label)
            checkbox.setChecked(True)
            self.export_view_checks[key] = checkbox
            export_layout.addWidget(checkbox)
        export_layout.addStretch(1)

        export_row = QHBoxLayout()
        export_row.addStretch(1)
        export_button = QPushButton("Export Selected Views...")
        export_button.clicked.connect(self._export_selected)
        export_row.addWidget(export_button)
        export_layout.addLayout(export_row)
        tabs.addTab(export_page, "Export")

        about_page = QWidget()
        about_layout = QVBoxLayout(about_page)
        about_layout.setContentsMargins(24, 20, 24, 18)
        about_layout.setSpacing(8)

        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setFixedSize(112, 112)
        icon_path = Path(__file__).resolve().parent / "icon.png"
        if icon_path.is_file():
            pixmap = QPixmap(str(icon_path))
            if not pixmap.isNull():
                icon_label.setPixmap(
                    pixmap.scaled(
                        112,
                        112,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
        about_layout.addWidget(icon_label, alignment=Qt.AlignmentFlag.AlignHCenter)

        name = QLabel("<h2 style='margin:0'>SELinux Inspector</h2>")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(name)

        version = QLabel(f"Version {APPLET_VERSION}")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(version)

        slogan = QLabel("<b>Expose. Explore. Explain.</b>")
        slogan.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(slogan)

        description = QLabel(
            "A read-only LinSpectacles applet for SELinux status, booleans, process contexts, "
            "audit denials, policy mappings and optional narrowly-scoped privileged inspection."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(description)

        details = QLabel(
            "<b>Build:</b> Standalone LinSpectacles applet<br>"
            "<b>Organisation ID:</b> "
            f"<a href='{APPLET_ORGANIZATION_URL}'>{APPLET_ORGANIZATION_ID}</a><br>"
            f"<b>Applet ID:</b> {APPLET_ID}"
        )
        details.setWordWrap(True)
        details.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction
            | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        details.setOpenExternalLinks(True)
        details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(details)

        copyright_label = QLabel(
            "Copyright © 2026 "
            "<a href='https://github.com/brunonlinespace'>brunonlinespace</a>"
        )
        copyright_label.setOpenExternalLinks(True)
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(copyright_label)

        license_label = QLabel("Licensed under GNU GPLv3 or later.")
        license_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(license_label)

        readme_url = QUrl.fromLocalFile(
            str(Path(__file__).resolve().parent.parent / "README.md")
        ).toString()
        license_url = QUrl.fromLocalFile(
            str(Path(__file__).resolve().parent.parent / "LICENSE")
        ).toString()
        links = QLabel(
            f"<a href='{readme_url}'>README</a> &nbsp;·&nbsp; "
            f"<a href='{license_url}'>License</a> &nbsp;·&nbsp; "
            f"<a href='{APPLET_REPOSITORY}'>Repository</a>"
        )
        links.setOpenExternalLinks(True)
        links.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(links)
        about_layout.addStretch(1)
        tabs.addTab(about_page, "About")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _layout_changed(self, text):
        self.owner.set_details_orientation(str(text).strip().lower(), persist=True)

    def _metadata_panel_changed(self, checked):
        self.owner.set_metadata_panel_visible(bool(checked), persist=True)

    def _export_selected(self):
        selected = [
            key for key, checkbox in self.export_view_checks.items()
            if checkbox.isChecked()
        ]
        self.owner.export_selected_views(selected, parent=self)


class SELinuxInspectorWidget(QWidget):
    """Read-only SELinux inspector with isolated optional privileged inspection."""

    SECTION_PREFIXES = {
        "booleans": "booleans:",
        "processes": "processes:",
        "denials": "denials:",
        "policy_modules": "policy_modules:",
        "permissive_domains": "permissive_domains:",
        "users_logins": "users_logins:",
        "port_contexts": "port_contexts:",
        "file_context_rules": "file_context_rules:",
    }

    PRIVILEGE_ACTIVE_QSS = (
        "QPushButton { background: #6a4b0c; color: #fff4d2; "
        "border: 1px solid #d6a23d; border-radius: 4px; padding: 5px 10px; font-weight: 600; } "
        "QPushButton:hover { border-color: #f2c96d; }"
    )

    def __init__(self, parent=None):
        super().__init__(parent)
        self._host_column_callback = None
        self._hidden_columns = set()
        self._serialized_metadata_font = ""
        self._file_context_records = []
        self._shutting_down = False
        self._priv_dialog = None
        self.privilege = PrivilegeClient()
        self._settings = QSettings("brunonlinespace", "SELinux Inspector")
        self.details_orientation = str(
            self._settings.value("details_orientation", "horizontal") or "horizontal"
        ).lower()
        if self.details_orientation not in {"horizontal", "vertical"}:
            self.details_orientation = "horizontal"
        saved_metadata_visible = self._settings.value("metadata_panel_visible", True)
        self.metadata_panel_visible = (
            saved_metadata_visible.strip().lower() not in {"0", "false", "no", "off"}
            if isinstance(saved_metadata_visible, str) else bool(saved_metadata_visible)
        )
        self._shortcuts = []

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        title_row = QHBoxLayout()
        title_label = QLabel(APPLET_NAME)
        title_font = title_label.font()
        title_font.setBold(True)
        title_font.setPointSize(max(title_font.pointSize(), 11))
        title_label.setFont(title_font)
        title_row.addWidget(title_label)
        title_row.addStretch(1)

        self.status_btn = QPushButton("Status...")
        self.status_btn.setToolTip("Open the current SELinux status summary.")
        self.status_btn.clicked.connect(self._show_status)
        title_row.addWidget(self.status_btn)

        self.priv_button = QPushButton("Privileged Inspection...")
        self.priv_button.setToolTip(
            "Open the separate optional read-only privileged inspection window. "
            "The normal applet remains ordinary-user only."
        )
        self.priv_button.clicked.connect(self._show_privileged_inspection)
        title_row.addWidget(self.priv_button)

        self.options_btn = QPushButton("Options...")
        self.options_btn.clicked.connect(self._show_options)
        title_row.addWidget(self.options_btn)
        root.addLayout(title_row)

        self.tabs = QTabWidget()
        self.tabs.setUsesScrollButtons(True)
        self.tabs.tabBar().setExpanding(False)
        self.tabs.tabBar().setElideMode(Qt.TextElideMode.ElideNone)
        root.addWidget(self.tabs, 1)

        self.booleans_page = SELinuxBooleansPage()
        self.processes_page = SELinuxProcessesPage()
        self.denials_page = SELinuxDenialsPage()
        self.policy_modules_page = SELinuxPolicyModulesPage()
        self.permissive_domains_page = SELinuxPermissiveDomainsPage()
        self.users_logins_page = SELinuxUsersLoginsPage()
        self.port_contexts_page = SELinuxPortContextsPage()
        self.file_context_rules_page = SELinuxFileContextRulesPage()

        self.tabs.addTab(self.booleans_page, "Booleans")
        self.tabs.addTab(self.processes_page, "Process Contexts")
        self.tabs.addTab(self.denials_page, "Recent Denials")
        self.tabs.addTab(self.policy_modules_page, "Policy Modules")
        self.tabs.addTab(self.permissive_domains_page, "Permissive Domains")
        self.tabs.addTab(self.users_logins_page, "Users & Logins")
        self.tabs.addTab(self.port_contexts_page, "Port Contexts")
        self.tabs.addTab(self.file_context_rules_page, "File Context Rules")
        self.tabs.currentChanged.connect(self._tab_changed)

        # Export is consolidated into Options on the ordinary applet surface.
        for page in self._table_pages():
            page.export_btn.hide()

        self.set_details_orientation(self.details_orientation, persist=False)
        self.set_metadata_panel_visible(self.metadata_panel_visible, persist=False)
        self._install_shortcuts()
        self._tab_changed(self.tabs.currentIndex())

        self._priv_timer = QTimer(self)
        self._priv_timer.setInterval(250)
        self._priv_timer.timeout.connect(self._update_privilege_ui)
        self._priv_timer.start()
        self._update_privilege_ui()

    def _table_pages(self):
        return (
            self.booleans_page,
            self.processes_page,
            self.denials_page,
            self.policy_modules_page,
            self.permissive_domains_page,
            self.users_logins_page,
            self.port_contexts_page,
            self.file_context_rules_page,
        )

    def _show_status(self):
        dialog = SELinuxStatusDialog(self, self)
        dialog.exec()

    def _show_options(self):
        dialog = SELinuxOptionsDialog(self)
        dialog.exec()

    def _add_shortcut(self, sequence, callback):
        shortcut = QShortcut(QKeySequence(sequence), self)
        shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        shortcut.activated.connect(callback)
        self._shortcuts.append(shortcut)

    def _install_shortcuts(self):
        self._add_shortcut("F3", self.toggle_metadata_panel)
        self._add_shortcut("Shift+F5", self._refresh_active_inventory)
        self._add_shortcut("Ctrl+L", self.toggle_details_orientation)
        self._add_shortcut("Ctrl+/", self._show_options)

    def _refresh_active_inventory(self):
        page = self.tabs.currentWidget()
        refresh = getattr(page, "refresh_btn", None)
        if refresh is not None and refresh.isEnabled():
            refresh.click()  # Follow the view's existing scan/refresh path.

    def toggle_details_orientation(self):
        target = "vertical" if self.details_orientation == "horizontal" else "horizontal"
        self.set_details_orientation(target, persist=True)

    def set_metadata_panel_visible(self, visible, *, persist=True):
        self.metadata_panel_visible = bool(visible)
        for page in self._table_pages():
            splitter = getattr(page, "splitter", None)
            if splitter is not None and splitter.widget(1) is not None:
                splitter.widget(1).setVisible(self.metadata_panel_visible)
        if self.metadata_panel_visible:
            self.set_details_orientation(self.details_orientation, persist=False)
        if persist:
            self._settings.setValue("metadata_panel_visible", self.metadata_panel_visible)
            self._settings.sync()

    def toggle_metadata_panel(self):
        self.set_metadata_panel_visible(not self.metadata_panel_visible, persist=True)

    def _set_file_context_records(self, records):
        self._file_context_records = list(records or [])

    def export_view_specs(self):
        return [
            ("status", "Status"),
            ("file_context_check", "File Context Check"),
            ("booleans", "Booleans"),
            ("processes", "Process Contexts"),
            ("denials", "Recent Denials"),
            ("policy_modules", "Policy Modules"),
            ("permissive_domains", "Permissive Domains"),
            ("users_logins", "Users & Logins"),
            ("port_contexts", "Port Contexts"),
            ("file_context_rules", "File Context Rules"),
        ]

    @staticmethod
    def _append_export_view(flat_records, label, records, columns):
        records = list(records or [])
        if not records:
            flat_records.append({
                "view": label,
                "record": "",
                "field": "Status",
                "value": "No collected data.",
            })
            return
        for index, record in enumerate(records, 1):
            for column in columns:
                key = column[0]
                field_label = column[1]
                flat_records.append({
                    "view": label,
                    "record": str(index),
                    "field": field_label,
                    "value": record.get(key, ""),
                })

    def export_selected_views(self, selected, parent=None):
        selected = list(selected or [])
        if not selected:
            QMessageBox.information(parent or self, "Export", "Select at least one SELinux view to export.")
            return

        by_key = {
            "booleans": ("Booleans", self.booleans_page),
            "processes": ("Process Contexts", self.processes_page),
            "denials": ("Recent Denials", self.denials_page),
            "policy_modules": ("Policy Modules", self.policy_modules_page),
            "permissive_domains": ("Permissive Domains", self.permissive_domains_page),
            "users_logins": ("Users & Logins", self.users_logins_page),
            "port_contexts": ("Port Contexts", self.port_contexts_page),
            "file_context_rules": ("File Context Rules", self.file_context_rules_page),
        }
        flat_records = []

        if "status" in selected:
            status_page = SELinuxStatusPage()
            status_records = list(status_page.records)
            status_page.deleteLater()
            self._append_export_view(
                flat_records,
                "Status",
                status_records,
                [("property", "Property"), ("value", "Value")],
            )

        if "file_context_check" in selected:
            self._append_export_view(
                flat_records,
                "File Context Check",
                self._file_context_records,
                [
                    ("path", "Path"),
                    ("actual_context", "Actual Context"),
                    ("expected_context", "Expected Context"),
                    ("result", "Result"),
                ],
            )

        for key, label in self.export_view_specs():
            if key not in selected or key in {"status", "file_context_check"}:
                continue
            view_label, page = by_key[key]
            self._append_export_view(flat_records, view_label, page.modules_data, page.columns)

        path = export_records_dialog(
            parent or self,
            "SELinux Inspector",
            flat_records,
            columns=[
                ("view", "View"),
                ("record", "Record"),
                ("field", "Field"),
                ("value", "Value"),
            ],
        )
        if path is not None:
            page = self.tabs.currentWidget()
            setter = getattr(page, "set_status", None)
            if callable(setter):
                setter(f"Exported selected SELinux views to {path}")

    def set_details_orientation(self, orientation, *, persist=True):
        orientation = str(orientation or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.details_orientation = orientation

        for page in self._table_pages():
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

        if self._priv_dialog is not None and self._priv_dialog.isVisible():
            setter = getattr(self._priv_dialog, "set_details_orientation", None)
            if callable(setter):
                setter(orientation)

        if persist:
            self._settings.setValue("details_orientation", orientation)
            self._settings.sync()

    def _show_privileged_inspection(self):
        if self._priv_dialog is not None and self._priv_dialog.isVisible():
            self._priv_dialog.raise_()
            self._priv_dialog.activateWindow()
            return
        dialog = PrivilegedInspectionDialog(
            self.privilege,
            metadata_font=self._serialized_metadata_font,
            details_orientation=self.details_orientation,
            metadata_panel_visible=self.metadata_panel_visible,
            parent=self,
        )
        self._priv_dialog = dialog
        dialog.session_state_changed.connect(self._update_privilege_ui)
        dialog.closing.connect(self._privileged_window_closed)
        dialog.finished.connect(self._privileged_dialog_finished)
        dialog.show()
        self._update_privilege_ui()

    def _privileged_dialog_finished(self, _result):
        QTimer.singleShot(0, self._finalize_privileged_dialog_close)

    def _finalize_privileged_dialog_close(self):
        dialog = self._priv_dialog
        if dialog is not None and not dialog.isVisible():
            self._priv_dialog = None
        self._update_privilege_ui()

    def _privileged_window_closed(self, had_session):
        self._update_privilege_ui()
        if self._shutting_down or not had_session:
            return
        show_message = self._settings.value(
            "privileged/show_end_confirmation", True, type=bool
        )
        if show_message:
            QTimer.singleShot(0, self._show_privilege_end_message)

    def _show_privilege_end_message(self):
        if self._shutting_down:
            return
        box = QMessageBox(self)
        box.setWindowTitle("Privileged Inspection Ended")
        box.setIcon(QMessageBox.Icon.Information)
        box.setText("Privileged inspection ended")
        box.setInformativeText(
            "The SELinux privileged helper session has been closed. LinSpectacles will not "
            "perform elevated SELinux inspection again until you explicitly open "
            "Privileged Inspection and authorize a new session."
        )
        checkbox = QCheckBox("Don't show this message again")
        box.setCheckBox(checkbox)
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.exec()
        if checkbox.isChecked():
            self._settings.setValue("privileged/show_end_confirmation", False)

    def _update_privilege_ui(self):
        active = bool(
            self._priv_dialog is not None
            and self._priv_dialog.isVisible()
            and self.privilege.enabled
        )
        if active:
            self.priv_button.setText("Privileged Inspection: Active...")
            self.priv_button.setStyleSheet(self.PRIVILEGE_ACTIVE_QSS)
            self.priv_button.setToolTip(
                "An authorised read-only helper session is active only for the separate "
                "Privileged Inspection window. Closing that window ends the session."
            )
        elif self.privilege.state == "connecting" and self._priv_dialog is not None:
            self.priv_button.setText("Privileged Inspection: Authorizing...")
            self.priv_button.setStyleSheet("")
            self.priv_button.setToolTip(
                "Waiting for PolicyKit authorization in the privileged inspection window."
            )
        else:
            self.priv_button.setText("Privileged Inspection...")
            self.priv_button.setStyleSheet("")
            self.priv_button.setToolTip(
                "Open the separate optional read-only privileged inspection window. "
                "The normal applet remains ordinary-user only."
            )

    def shutdown(self):
        self._shutting_down = True
        if hasattr(self, "_priv_timer"):
            self._priv_timer.stop()
        if self._priv_dialog is not None:
            try:
                self._priv_dialog.close()
            except Exception:
                pass
            self._priv_dialog = None
        self.privilege.stop()

    def _tab_changed(self, _index):
        page = self.tabs.currentWidget()
        ensure_loaded = getattr(page, "ensure_loaded", None)
        if callable(ensure_loaded):
            ensure_loaded()

    def _local_hidden(self, section):
        prefix = self.SECTION_PREFIXES[section]
        return sorted(
            item[len(prefix):]
            for item in self._hidden_columns
            if item.startswith(prefix)
        )

    def _child_columns_changed(self, section, hidden):
        prefix = self.SECTION_PREFIXES[section]
        self._hidden_columns = {
            item for item in self._hidden_columns if not item.startswith(prefix)
        }
        self._hidden_columns.update(prefix + str(item) for item in (hidden or []))
        if callable(self._host_column_callback):
            self._host_column_callback(sorted(self._hidden_columns))

    def apply_host_settings(self, settings=None, column_visibility_callback=None):
        settings = settings or {}
        self._host_column_callback = (
            column_visibility_callback if callable(column_visibility_callback) else None
        )
        self._hidden_columns = {str(item) for item in settings.get("hidden_columns", [])}
        serialized_font = settings.get("metadata_font", "")
        self._serialized_metadata_font = serialized_font

        for section, page in (
            ("booleans", self.booleans_page),
            ("processes", self.processes_page),
            ("denials", self.denials_page),
            ("policy_modules", self.policy_modules_page),
            ("permissive_domains", self.permissive_domains_page),
            ("users_logins", self.users_logins_page),
            ("port_contexts", self.port_contexts_page),
            ("file_context_rules", self.file_context_rules_page),
        ):
            page.apply_host_settings(
                {
                    "metadata_font": serialized_font,
                    "hidden_columns": self._local_hidden(section),
                },
                lambda hidden, target=section: self._child_columns_changed(target, hidden),
            )

def create_applet(parent=None):
    return SELinuxInspectorWidget(parent=parent)


def run_standalone():
    import sys
    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication, QMainWindow
    from ._support import STANDALONE_STYLESHEET

    app = QApplication(sys.argv)
    app.setApplicationName(APPLET_NAME)
    app.setOrganizationName(APPLET_ORGANIZATION_ID)
    icon_path = Path(__file__).resolve().parent / "icon.png"
    if icon_path.is_file():
        app.setWindowIcon(QIcon(str(icon_path)))
    app.setStyleSheet(STANDALONE_STYLESHEET)

    window = QMainWindow()
    if icon_path.is_file():
        window.setWindowIcon(QIcon(str(icon_path)))
    window.setWindowTitle(f"{APPLET_NAME} {APPLET_VERSION} — LinSpectacles Applet")
    window.resize(1200, 780)
    widget = create_applet()
    window.setCentralWidget(widget)
    app.aboutToQuit.connect(widget.shutdown)
    window.show()
    return app.exec()
