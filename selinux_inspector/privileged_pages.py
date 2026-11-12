#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles SELinux Inspector - replicated privileged-window pages
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
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
        self.privilege_client = None
        self.privilege_activator = None
        self.comparison_callback = None
        self.stats_label.setText("Recent SELinux Denials: Not scanned")
        self.refresh_btn.setText("Scan Normally")
        self.privileged_btn = QPushButton("Scan with Privileged Access...")
        self.privileged_btn.clicked.connect(self.scan_privileged)
        self.dash_layout.insertWidget(self.dash_layout.count() - 1, self.privileged_btn)
        if not shutil.which("pkexec"):
            self.privileged_btn.setEnabled(False)
            self.privileged_btn.setToolTip("pkexec is not available on this system.")
        self.export_btn.setEnabled(False)
        self.clear_info()
        self.append_info(
            "Recent audit denials are not scanned automatically.\n\n"
            "Use Scan Normally first. If audit-log permissions prevent access, "
            "the optional privileged scan runs only the ausearch command through pkexec; "
            "the LinSpectacles GUI itself remains unprivileged.\n"
        )
        self.set_status("Not scanned - choose a denial scan when needed.")

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

    def _scan(self, privileged=False):
        use_persistent_helper = bool(
            privileged
            and self.privilege_client is not None
            and getattr(self.privilege_client, "enabled", False)
        )
        ausearch = shutil.which("ausearch")
        if not ausearch and not use_persistent_helper:
            self.clear_info()
            self.append_info("The ausearch command is not installed. Install the Linux audit userspace tools to inspect AVC denials.\n")
            self.set_status("ausearch command unavailable.")
            self.stats_label.setText("Recent SELinux Denials: 0")
            self.export_btn.setEnabled(False)
            return

        command = [ausearch or "ausearch", "-m", "AVC,USER_AVC", "-ts", "recent", "-i"]
        compare_command = [ausearch or "ausearch", "-m", "AVC,USER_AVC", "-ts", "recent"]
        if privileged and not use_persistent_helper:
            self.set_status("Privileged helper session is not active.")
            return

        self.refresh_btn.setEnabled(False)
        self.privileged_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.set_status("Reading recent SELinux audit denials...")
        QApplication.processEvents()

        try:
            if use_persistent_helper:
                # The helper itself permits the fixed ausearch operation up to
                # 90 seconds.  The client must wait beyond that ceiling rather
                # than abandoning the stdio request at 50 seconds.
                try:
                    ordinary_result = _run(compare_command, timeout=60)
                except subprocess.TimeoutExpired:
                    ordinary_result = subprocess.CompletedProcess(compare_command, 124, "", "Ordinary denial query timed out.")
                except Exception as exc:
                    ordinary_result = subprocess.CompletedProcess(compare_command, 125, "", str(exc))

                response = self.privilege_client.request("denials", timeout=105.0)
                if not response or not response.get("ok"):
                    result = subprocess.CompletedProcess(
                        compare_command,
                        125,
                        "",
                        str(getattr(self.privilege_client, "message", "Privileged helper query failed.")),
                    )
                else:
                    result = subprocess.CompletedProcess(
                        compare_command,
                        int(response.get("returncode", 0)),
                        str(response.get("stdout", "")),
                        str(response.get("stderr", "")),
                    )

                if callable(self.comparison_callback):
                    try:
                        self.comparison_callback("denials", compare_command, ordinary_result, result)
                    except Exception:
                        pass

                if result.returncode == 125 and not result.stdout:
                    raise RuntimeError(result.stderr or "Privileged helper query failed.")
            else:
                result = _run(command, timeout=60)
        except subprocess.TimeoutExpired:
            self.set_status("SELinux denial scan timed out.")
            self.refresh_btn.setEnabled(True)
            self.privileged_btn.setEnabled(bool(shutil.which("pkexec")))
            return
        except Exception as exc:
            self.set_status(f"Could not scan SELinux denials: {exc}")
            self.refresh_btn.setEnabled(True)
            self.privileged_btn.setEnabled(bool(shutil.which("pkexec")))
            return

        output = result.stdout or ""
        self.modules_data = self._parse_events(output)
        self.has_scanned = True
        self.stats_label.setText(f"Recent SELinux Denials: {len(self.modules_data)}")
        self.filter_modules()
        self.clear_info()

        stderr = (result.stderr or "").strip()
        if result.returncode == 126:
            self.append_info("Privileged inspection was cancelled or not authorized.\n")
            self.set_status("Privileged SELinux audit scan was cancelled.")
        elif result.returncode not in (0, 1) and not self.modules_data:
            message = stderr or output.strip() or f"ausearch exited with status {result.returncode}."
            self.append_info(message + "\n")
            if not privileged:
                self.append_info(
                    "\nIf this is an audit-log permission error, you can choose Scan with Privileged Access.\n"
                )
            self.set_status("SELinux audit records could not be read completely.")
        elif self.modules_data:
            mode = "privileged" if privileged else "normal"
            self.set_status(f"Found {len(self.modules_data)} recent SELinux denial(s) using {mode} inspection.")
        else:
            self.append_info("No recent AVC or USER_AVC denials were found.\n")
            self.set_status("No recent SELinux denials found.")

        self.export_btn.setEnabled(bool(self.modules_data))
        self.refresh_btn.setEnabled(True)
        self.privileged_btn.setEnabled(bool(shutil.which("pkexec")))

    def load_modules(self):
        self._scan(privileged=False)

    def scan_privileged(self):
        answer = QMessageBox.question(
            self,
            "Privileged SELinux Inspection",
            "This requests system authentication to run only the ausearch command "
            "for reading recent SELinux AVC audit records.\n\n"
            "LinSpectacles itself will remain unprivileged and no SELinux settings will be changed.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            if self.privilege_client is not None and getattr(self.privilege_client, "enabled", False):
                self._scan(privileged=True)
            elif callable(self.privilege_activator):
                self.privilege_activator(self)
            else:
                QMessageBox.information(
                    self,
                    "Privileged SELinux Inspection",
                    "The dedicated privileged helper session is not active. Start privileged access from the window controls first.",
                )

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
