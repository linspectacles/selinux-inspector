<p align="center">
  <a href="https://github.com/brunonlinespace/brunonlinespace/blob/main/linspectacles/selinux-inspector.png">
    <img
      src="https://raw.githubusercontent.com/brunonlinespace/brunonlinespace/main/linspectacles/selinux-inspector.png"
      alt="SELinux Inspector screenshot"
      width="900"
    >
  </a>
</p>

# SELinux Inspector

**Expose. Explore. Explain.**

SELinux Inspector is a read-only SELinux inspector with status/context views, policy inventories, recent-denial scanning, file-context checking and optional ephemeral privileged inspection through a narrow helper.

Current release: **0.0.10**

Repository: <https://github.com/linspectacles/selinux-inspector>

## What SELinux Inspector is

SELinux Inspector answers a focused question: **what SELinux state, policy-facing metadata and contexts are visible, and where does privileged read-only access reveal additional information?**

It keeps acquisition and interpretation close to the Linux interfaces actually used by the applet. When a source is unavailable, restricted, or does not report a field, the README does not imply that the applet can manufacture the missing information.

## Highlights

- **Status...** dialog with SELinux status plus a separate **File Context Check**.
- Views for **Booleans**, **Process Contexts**, **Recent Denials**, **Policy Modules**, **Permissive Domains**, **Users & Logins**, **Port Contexts** and **File Context Rules**.
- Recent Denials remains explicit scan-only rather than being collected automatically.
- File Context Check compares the selected path's actual context with the policy-expected context using native SELinux tools.
- Separate **Privileged Inspection...** window; the normal applet pages never switch themselves to elevated collection.
- Fixed helper can perform only declared read-only inspection operations after explicit authorization.
- **Comparison Report...** records actual paired ordinary/helper query results that were acquired, rather than theoretical capability claims.

## Data sources and acquisition

- `sestatus`, `getenforce` or `/sys/fs/selinux/enforce`, `id -Z`, and `/etc/selinux/config`.
- `getsebool -a` and optional `semanage boolean -l`.
- `ps -e -o label= -o pid= -o user= -o comm=`.
- `ausearch -m AVC,USER_AVC -ts recent -i` for Recent Denials.
- `ls -Zd -- <path>` and `matchpathcon -n <path>` for File Context Check.
- `semodule` and `semanage` read-only listing commands for policy modules, permissive domains, users/logins, ports and file-context rules.

The applet uses those sources according to the acquisition paths implemented in this release. Optional tools or privileged helpers only affect the views/actions that explicitly use them; they are not treated as silent substitutes for unrelated sources.

## Interface

SELinux Inspector follows the LinSpectacles inventory + **Metadata Details** pattern where applicable: an acquired inventory remains separate from the details for the selected record, and search/filter controls operate on the data the applet has actually collected.

The applet's **Options** surface provides the presentation/source/about controls implemented by this release, together with export controls where present in the source. Applet-specific actions remain explicit rather than being folded into background collection.

## Read-only and scope boundaries

SELinux Inspector does not run `setenforce`, `setsebool`, policy-changing `semanage` commands, `chcon`, `restorecon`, module install/remove operations or other SELinux mutations. Closing the privileged window ends the helper process; the GUI itself is not run as root.

## Running from source

The supplied source is directly runnable on Linux. The Python-side requirements are:

- Python 3.
- PyQt6 for the graphical interface.

Create a local virtual environment if you do not already have the required Python packages in the environment you want to use:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install PyQt6
python3 linspectacles_selinux_inspector/standalone.py
```

Linux commands, procfs/sysfs interfaces, system services, or optional helpers mentioned in **Data sources and acquisition** are applet-specific runtime inputs. A missing optional source is handled by the applet's existing availability/error path; it is not replaced here with an invented dependency or capability.

No RPM installation instructions are included in this README.

## Source layout and LinSpectacles integration

The applet source is contained in:

```text
linspectacles_selinux_inspector/
├── __init__.py
├── applet.json
├── standalone.py
├── LICENSE
├── README.md
└── selinux_inspector/
    ├── __init__.py
    ├── _support.py
    ├── applet.py
    ├── deep_pages.py
    ├── icon.png
    ├── privilege.py
    ├── privileged_deep_pages.py
    ├── privileged_pages.py
    ├── privileged_window.py
    ├── PRIVILEGED.md
    ├── PRIVILEGED-HELPER-CONTRACT-v1.md
    └── privileged/
        ├── install-helper.sh
        └── linspectacles-selinux-helper
```

`applet.json` supplies the LinSpectacles applet identity and entrypoint metadata. `standalone.py` launches the applet directly, while the package's applet factory provides the host-loadable LinSpectacles integration used by the source.

## Configuration

Presentation and inspection preferences are persisted only through the settings mechanisms already implemented by the applet. Persisted UI state does not grant the applet permission to modify the inspected Linux subsystem.

## Scope

SELinux Inspector is intentionally specialist. Related Linux information that belongs to another LinSpectacles subsystem remains outside this applet rather than being inferred or duplicated here.

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).

## Links

- LinSpectacles organisation: <https://github.com/linspectacles/>
- Repository: <https://github.com/linspectacles/selinux-inspector>
- Issues: <https://github.com/linspectacles/selinux-inspector/issues>

<p align="center">
  <a href="https://github.com/linspectacles/selinux-inspector">
    <img
      src="selinux_inspector/icon.png"
      alt="SELinux Inspector"
      width="256"
    >
  </a>
</p>
