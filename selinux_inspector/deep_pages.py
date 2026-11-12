#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspector Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

"""Additional read-only SELinux policy views for SELinux Inspector.

Kept in a separate module so the established Status/Booleans/Processes/
Denials collectors can remain untouched.
"""

import os
import re
import shutil
import subprocess

from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QTextEdit,
    QVBoxLayout,
)

from ._support import BaseInspectorTab, apply_metadata_font, metadata_font_qss

def _run(command, timeout=15):
    """Run a fixed read-only SELinux command as the current user.

    The normal applet pages deliberately never borrow the privileged helper;
    elevated collection is confined to the separate Privileged Inspection
    window.
    """
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )

def _which(name):
    found = shutil.which(name)
    if found:
        return found
    for root in ("/usr/sbin", "/usr/bin", "/sbin", "/bin"):
        candidate = f"{root}/{name}"
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _split_columns(line):
    """Split semanage table output on column-sized whitespace."""
    return [part.strip() for part in re.split(r"\s{2,}", line.strip()) if part.strip()]


def _set_unavailable(page, title, message):
    page.modules_data.clear()
    page.stats_label.setText(f"{title}: 0")
    page.table.setRowCount(0)
    page.clear_info()
    page.append_info(message.rstrip() + "\n")
    page.export_btn.setEnabled(False)
    page.set_status(message)


class LazySELinuxTablePage(BaseInspectorTab):
    """A normal inspector table whose collector runs only when first viewed."""

    def __init__(self, *args, **kwargs):
        self._loaded_once = False
        super().__init__(*args, **kwargs)
        self.export_btn.setEnabled(False)
        self.clear_info()
        self.append_info("This view has not been loaded yet. Select the tab to inspect it.\n")
        self.set_status("Not loaded yet.")

    def ensure_loaded(self):
        if not self._loaded_once:
            self.load_modules()

    def _begin_load(self, status):
        self._loaded_once = True
        self.set_status(status)
        QApplication.processEvents()


class SELinuxPolicyModulesPage(LazySELinuxTablePage):
    NUMERIC_COLUMNS = {"priority"}

    def __init__(self, parent=None):
        columns = [
            ("name", "Module", 250, "left"),
            ("priority", "Priority", 85, "right"),
            ("kind", "Kind", 90, "left"),
            ("state", "State", 130, "left"),
        ]
        categories = ["All Categories", "Active", "Disabled", "Shadowed"]
        super().__init__("Total Policy Modules", columns, categories, parent)
        self.export_title = "SELinux Policy Modules"

    @staticmethod
    def _active_module_names(semodule):
        result = None
        for command in (
            [semodule, "--list-modules=standard"],
            [semodule, "-l"],
        ):
            try:
                candidate = _run(command, timeout=20)
            except Exception:
                continue
            if candidate.returncode == 0:
                result = candidate
                break
        if result is None:
            return set()
        names = set()
        for line in result.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            if parts[0].isdigit() and len(parts) > 1:
                names.add(parts[1])
            else:
                names.add(parts[0])
        return names

    def load_modules(self):
        self._begin_load("Reading SELinux policy modules...")
        self.modules_data.clear()
        semodule = _which("semodule")
        if not semodule:
            _set_unavailable(self, "Total Policy Modules", "The semodule command is not installed.")
            return
        try:
            result = _run([semodule, "--list-modules=full"], timeout=30)
        except subprocess.TimeoutExpired:
            _set_unavailable(self, "Total Policy Modules", "Timed out while reading SELinux policy modules.")
            return
        except Exception as exc:
            _set_unavailable(self, "Total Policy Modules", f"Could not read SELinux policy modules: {exc}")
            return

        raw_records = []
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 2 or not parts[0].isdigit():
                    continue
                raw_records.append(
                    {
                        "priority": int(parts[0]),
                        "name": parts[1],
                        "kind": parts[2] if len(parts) > 2 else "-",
                    }
                )
        else:
            # Older policycoreutils may not support the full listing form.
            try:
                fallback = _run([semodule, "-l"], timeout=30)
            except Exception:
                fallback = result
            if fallback.returncode != 0:
                message = (fallback.stderr or fallback.stdout or result.stderr or result.stdout or "semodule returned an error.").strip()
                _set_unavailable(self, "Total Policy Modules", message)
                return
            for line in fallback.stdout.splitlines():
                parts = line.split()
                if not parts:
                    continue
                raw_records.append({"priority": 0, "name": parts[0], "kind": parts[1] if len(parts) > 1 else "-"})

        active_names = self._active_module_names(semodule)
        highest = {}
        for record in raw_records:
            highest[record["name"]] = max(highest.get(record["name"], -1), record["priority"])

        for record in raw_records:
            if record["priority"] < highest.get(record["name"], record["priority"]):
                state = "Shadowed"
            elif record["name"] in active_names:
                state = "Active"
            else:
                state = "Disabled"
            record["state"] = state
            record["category"] = state
            self.modules_data.append(record)

        self.modules_data.sort(key=lambda item: (item["name"].lower(), -item["priority"]))
        self.stats_label.setText(f"Total Policy Modules: {len(self.modules_data)}")
        self.filter_modules()
        self.clear_info()
        self.set_status("Successfully refreshed SELinux policy modules.")

    def on_module_select(self):
        record = self.current_record()
        if not record:
            return
        self.clear_info()
        self.append_key_value("Module", record.get("name", ""))
        self.append_key_value("Priority", record.get("priority", ""))
        self.append_key_value("Kind", record.get("kind", "-"))
        self.append_key_value("State", record.get("state", "-"))
        if record.get("state") == "Shadowed":
            self.append_info("\nA higher-priority module with the same name is currently taking precedence.\n")
        self.append_info("\nSource: semodule --list-modules=full\n")
        self.set_status(f"Inspecting SELinux policy module [{record.get('name', '')}].")


class SELinuxPermissiveDomainsPage(LazySELinuxTablePage):
    def __init__(self, parent=None):
        columns = [
            ("domain", "Permissive Domain", 320, "left"),
            ("origin", "Origin", 180, "left"),
        ]
        categories = ["All Categories", "Built-in", "Customized"]
        super().__init__("Total Permissive Domains", columns, categories, parent)
        self.export_title = "SELinux Permissive Domains"
        self.category_dropdown.setMinimumWidth(150)

    def load_modules(self):
        self._begin_load("Reading permissive SELinux domains...")
        self.modules_data.clear()
        semanage = _which("semanage")
        if not semanage:
            _set_unavailable(
                self,
                "Total Permissive Domains",
                "The semanage command is not installed. Permissive-domain inspection requires policycoreutils semanage tooling.",
            )
            return
        try:
            result = _run([semanage, "permissive", "-l"], timeout=20)
        except subprocess.TimeoutExpired:
            _set_unavailable(self, "Total Permissive Domains", "Timed out while reading permissive SELinux domains.")
            return
        except Exception as exc:
            _set_unavailable(self, "Total Permissive Domains", f"Could not read permissive domains: {exc}")
            return
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "semanage permissive returned an error.").strip()
            _set_unavailable(self, "Total Permissive Domains", message)
            return

        origin = None
        for raw in result.stdout.splitlines():
            line = raw.strip()
            if not line:
                continue
            lower = line.lower()
            if lower.startswith("builtin permissive types"):
                origin = "Built-in"
                continue
            if lower.startswith("customized permissive types"):
                origin = "Customized"
                continue
            if origin is None or line.startswith("-"):
                continue
            for domain in line.split():
                self.modules_data.append(
                    {"domain": domain, "origin": origin, "category": origin}
                )

        self.modules_data.sort(key=lambda item: (item["origin"], item["domain"].lower()))
        self.stats_label.setText(f"Total Permissive Domains: {len(self.modules_data)}")
        self.filter_modules()
        self.clear_info()
        if self.modules_data:
            self.set_status("Successfully refreshed permissive SELinux domains.")
        else:
            self.append_info("No permissive domains were reported by the active policy.\n")
            self.set_status("No permissive SELinux domains were reported.")

    def on_module_select(self):
        record = self.current_record()
        if not record:
            return
        self.clear_info()
        self.append_key_value("Domain", record.get("domain", ""))
        self.append_key_value("Origin", record.get("origin", ""))
        self.append_info(
            "\nThe system may still be globally Enforcing while individual domains are configured permissive.\n"
            "Read-only inspection: this applet does not change domain enforcement.\n"
        )
        self.append_info("\nSource: semanage permissive -l\n")
        self.set_status(f"Inspecting permissive SELinux domain [{record.get('domain', '')}].")


class SELinuxUsersLoginsPage(LazySELinuxTablePage):
    def __init__(self, parent=None):
        columns = [
            ("kind", "Kind", 120, "left"),
            ("name", "Name", 180, "left"),
            ("selinux_user", "SELinux User", 150, "left"),
            ("prefix", "Prefix", 90, "left"),
            ("level", "Level", 90, "left"),
            ("range", "MLS/MCS Range", 210, "left"),
            ("roles_service", "Roles / Service", 300, "left"),
        ]
        categories = ["All Categories", "SELinux User", "Login Mapping"]
        super().__init__("Total Users and Login Mappings", columns, categories, parent)
        self.export_title = "SELinux Users and Login Mappings"
        self.category_dropdown.setMinimumWidth(160)

    @staticmethod
    def _parse_users(text):
        records = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or "SELinux User" in line or "Labeling" in line or line.startswith("-"):
                continue
            parts = _split_columns(raw)
            if len(parts) < 5:
                continue
            name, prefix, level, range_value = parts[:4]
            roles = " ".join(parts[4:])
            records.append(
                {
                    "kind": "SELinux User",
                    "name": name,
                    "selinux_user": name,
                    "prefix": prefix,
                    "level": level,
                    "range": range_value,
                    "roles_service": roles,
                    "category": "SELinux User",
                }
            )
        return records

    @staticmethod
    def _parse_logins(text):
        records = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or "Login Name" in line or line.startswith("-"):
                continue
            parts = _split_columns(raw)
            if len(parts) < 3:
                continue
            name = parts[0]
            selinux_user = parts[1]
            range_value = parts[2]
            service = " ".join(parts[3:]) if len(parts) > 3 else "-"
            records.append(
                {
                    "kind": "Login Mapping",
                    "name": name,
                    "selinux_user": selinux_user,
                    "prefix": "-",
                    "level": "-",
                    "range": range_value,
                    "roles_service": service,
                    "category": "Login Mapping",
                }
            )
        return records

    def load_modules(self):
        self._begin_load("Reading SELinux users and login mappings...")
        self.modules_data.clear()
        semanage = _which("semanage")
        if not semanage:
            _set_unavailable(
                self,
                "Total Users and Login Mappings",
                "The semanage command is not installed. SELinux user/login mapping inspection is unavailable.",
            )
            return

        errors = []
        try:
            user_result = _run([semanage, "user", "-l"], timeout=20)
            if user_result.returncode == 0:
                self.modules_data.extend(self._parse_users(user_result.stdout))
            else:
                errors.append((user_result.stderr or user_result.stdout or "semanage user failed").strip())
        except Exception as exc:
            errors.append(f"semanage user: {exc}")

        try:
            login_result = _run([semanage, "login", "-l"], timeout=20)
            if login_result.returncode == 0:
                self.modules_data.extend(self._parse_logins(login_result.stdout))
            else:
                errors.append((login_result.stderr or login_result.stdout or "semanage login failed").strip())
        except Exception as exc:
            errors.append(f"semanage login: {exc}")

        self.modules_data.sort(key=lambda item: (item["kind"], item["name"].lower()))
        self.stats_label.setText(f"Total Users and Login Mappings: {len(self.modules_data)}")
        self.filter_modules()
        self.clear_info()
        if self.modules_data:
            self.set_status("Successfully refreshed SELinux users and login mappings.")
        else:
            self.append_info("No SELinux user or login mapping records were returned.\n")
            if errors:
                self.append_info("\n" + "\n".join(errors) + "\n")
            self.set_status("SELinux user/login mapping information was unavailable.")

    def on_module_select(self):
        record = self.current_record()
        if not record:
            return
        self.clear_info()
        self.append_key_value("Kind", record.get("kind", ""))
        self.append_key_value("Name", record.get("name", ""))
        self.append_key_value("SELinux User", record.get("selinux_user", ""))
        if record.get("kind") == "SELinux User":
            self.append_key_value("Labeling Prefix", record.get("prefix", "-"))
            self.append_key_value("MLS/MCS Level", record.get("level", "-"))
            self.append_key_value("MLS/MCS Range", record.get("range", "-"))
            self.append_key_value("SELinux Roles", record.get("roles_service", "-"))
            self.append_info("\nSource: semanage user -l\n")
        else:
            self.append_key_value("MLS/MCS Range", record.get("range", "-"))
            self.append_key_value("Service", record.get("roles_service", "-"))
            self.append_info("\nSource: semanage login -l\n")
        self.set_status(f"Inspecting {record.get('kind', 'SELinux identity').lower()} [{record.get('name', '')}].")


class SELinuxPortContextsPage(LazySELinuxTablePage):
    def __init__(self, parent=None):
        columns = [
            ("type", "SELinux Port Type", 260, "left"),
            ("protocol", "Protocol", 90, "left"),
            ("ports", "Port Number(s)", 420, "left"),
        ]
        categories = ["All Categories", "TCP", "UDP", "SCTP", "DCCP", "Other"]
        super().__init__("Total Port Context Rules", columns, categories, parent)
        self.export_title = "SELinux Port Contexts"
        self.category_dropdown.setMinimumWidth(130)

    def load_modules(self):
        self._begin_load("Reading SELinux port contexts...")
        self.modules_data.clear()
        semanage = _which("semanage")
        if not semanage:
            _set_unavailable(self, "Total Port Context Rules", "The semanage command is not installed.")
            return
        try:
            result = _run([semanage, "port", "-l"], timeout=30)
        except subprocess.TimeoutExpired:
            _set_unavailable(self, "Total Port Context Rules", "Timed out while reading SELinux port contexts.")
            return
        except Exception as exc:
            _set_unavailable(self, "Total Port Context Rules", f"Could not read SELinux port contexts: {exc}")
            return
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "semanage port returned an error.").strip()
            _set_unavailable(self, "Total Port Context Rules", message)
            return

        for raw in result.stdout.splitlines():
            line = raw.strip()
            if not line or "SELinux Port Type" in line or line.startswith("-"):
                continue
            parts = _split_columns(raw)
            if len(parts) < 3:
                continue
            port_type, protocol = parts[:2]
            ports = " ".join(parts[2:])
            proto_upper = protocol.upper()
            category = proto_upper if proto_upper in {"TCP", "UDP", "SCTP", "DCCP"} else "Other"
            self.modules_data.append(
                {
                    "type": port_type,
                    "protocol": protocol,
                    "ports": ports,
                    "category": category,
                }
            )

        self.modules_data.sort(key=lambda item: (item["protocol"], item["type"].lower()))
        self.stats_label.setText(f"Total Port Context Rules: {len(self.modules_data)}")
        self.filter_modules()
        self.clear_info()
        self.set_status("Successfully refreshed SELinux port contexts.")

    def on_module_select(self):
        record = self.current_record()
        if not record:
            return
        self.clear_info()
        self.append_key_value("SELinux Port Type", record.get("type", ""))
        self.append_key_value("Protocol", record.get("protocol", ""))
        self.append_key_value("Port Number(s)", record.get("ports", ""))
        self.append_info("\nSource: semanage port -l\n")
        self.append_info("Read-only inspection: this applet does not add, remove, or relabel SELinux port mappings.\n")
        self.set_status(f"Inspecting SELinux port type [{record.get('type', '')}].")


class SELinuxFileContextRulesPage(LazySELinuxTablePage):
    FILE_TYPES = [
        "all files",
        "regular file",
        "directory",
        "symbolic link",
        "character device",
        "block device",
        "socket",
        "named pipe",
    ]

    def __init__(self, parent=None):
        columns = [
            ("file_spec", "File Specification", 380, "left"),
            ("file_type", "File Type", 140, "left"),
            ("context", "Expected Context", 380, "left"),
        ]
        categories = ["All Categories", *[item.title() for item in self.FILE_TYPES], "Other"]
        super().__init__("Total File Context Rules", columns, categories, parent)
        self.export_title = "SELinux File Context Rules"
        self.category_dropdown.setMinimumWidth(150)

    @classmethod
    def _category(cls, file_type):
        normalized = file_type.strip().lower()
        return normalized.title() if normalized in cls.FILE_TYPES else "Other"

    def load_modules(self):
        self._begin_load("Reading SELinux file-context policy rules...")
        self.modules_data.clear()
        semanage = _which("semanage")
        if not semanage:
            _set_unavailable(self, "Total File Context Rules", "The semanage command is not installed.")
            return
        try:
            result = _run([semanage, "fcontext", "-l"], timeout=45)
        except subprocess.TimeoutExpired:
            _set_unavailable(self, "Total File Context Rules", "Timed out while reading SELinux file-context rules.")
            return
        except Exception as exc:
            _set_unavailable(self, "Total File Context Rules", f"Could not read SELinux file-context rules: {exc}")
            return
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "semanage fcontext returned an error.").strip()
            _set_unavailable(self, "Total File Context Rules", message)
            return

        for raw in result.stdout.splitlines():
            line = raw.strip()
            if not line or "SELinux fcontext" in line or line.startswith("-"):
                continue
            parts = _split_columns(raw)
            if len(parts) < 3:
                continue
            file_spec, file_type = parts[:2]
            context = " ".join(parts[2:])
            self.modules_data.append(
                {
                    "file_spec": file_spec,
                    "file_type": file_type,
                    "context": context,
                    "category": self._category(file_type),
                }
            )

        self.modules_data.sort(key=lambda item: item["file_spec"].lower())
        self.stats_label.setText(f"Total File Context Rules: {len(self.modules_data)}")
        self.filter_modules()
        self.clear_info()
        self.set_status("Successfully refreshed SELinux file-context policy rules.")

    def on_module_select(self):
        record = self.current_record()
        if not record:
            return
        self.clear_info()
        self.append_key_value("File Specification", record.get("file_spec", ""))
        self.append_key_value("File Type", record.get("file_type", ""))
        self.append_key_value("Expected Context", record.get("context", ""))
        self.append_info("\nSource: semanage fcontext -l\n")
        self.append_info(
            "This is a policy mapping rule, not the current label of any specific file.\n"
        )
        self.set_status("Inspecting selected SELinux file-context policy rule.")


SOURCES_TEXT = """SELinux Inspector - Data Sources

Status (ordinary top-level Status... dialog only; not duplicated in privileged window)
  sestatus
  getenforce (or /sys/fs/selinux/enforce)
  id -Z
  /etc/selinux/config

Booleans
  getsebool -a
  semanage boolean -l (when available, for defaults/descriptions)

Process Contexts
  ps -e -o label= -o pid= -o user= -o comm=

Recent Denials
  ausearch -m AVC,USER_AVC -ts recent -i
  The normal page always uses the current user's permissions.
  The privileged fixed helper runs the corresponding read-only ausearch query only after explicit user request.

Policy Modules
  semodule --list-modules=full
  semodule --list-modules=standard

Permissive Domains
  semanage permissive -l

Users & Logins
  semanage user -l
  semanage login -l

Port Contexts
  semanage port -l

File Context Rules
  semanage fcontext -l

Privileged Inspection
  Optional fixed root-owned helper, invoked only from the separate Privileged Inspection window.
  That window mirrors the normal applet views and uses the fixed helper only after explicit authorization.
  Recent Denials remains explicit scan-only; authorization does not trigger a bulk inspection.
  Comparison Report records actual paired ordinary/helper query results from user-requested scans or refreshes; it does not reproduce theoretical capability declarations.
  Closing the window ends the helper process; the normal applet pages never switch to elevated collection.

All inspection is read-only. SELinux Inspector does not run setenforce, setsebool,
semanage modification commands, chcon, restorecon, semodule install/remove, or
other policy-changing operations.
"""


def show_sources_dialog(parent=None, metadata_font=""):
    dialog = QDialog(parent)
    dialog.setWindowTitle("SELinux Inspector - Data Sources")
    dialog.resize(720, 560)
    layout = QVBoxLayout(dialog)
    layout.setContentsMargins(12, 12, 12, 12)
    layout.setSpacing(10)

    heading = QLabel("Data Sources")
    font = heading.font()
    font.setBold(True)
    font.setPointSize(max(font.pointSize(), 11))
    heading.setFont(font)
    layout.addWidget(heading)

    note = QLabel("Commands and system interfaces used by each read-only SELinux Inspector view.")
    note.setWordWrap(True)
    layout.addWidget(note)

    text = QTextEdit()
    text.setReadOnly(True)
    chosen_font = apply_metadata_font(text, metadata_font)
    text.setStyleSheet(
        "QTextEdit { background: #1e1e1e; color: #dcdcdc; border: 1px solid #666; "
        f"{metadata_font_qss(chosen_font)} "
        "}"
    )
    text.setPlainText(SOURCES_TEXT)
    layout.addWidget(text, 1)

    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    buttons.rejected.connect(dialog.reject)
    buttons.accepted.connect(dialog.accept)
    layout.addWidget(buttons)
    dialog.exec()
