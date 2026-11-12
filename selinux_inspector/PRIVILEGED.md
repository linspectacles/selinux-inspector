# SELinux Inspector privileged inspection

SELinux Inspector is always useful as a normal user. Optional elevated visibility is provided by a narrow, fixed-operation helper; the PyQt application itself is never run as root.

## Lifecycle

The helper being installed is not the same as privileged inspection being active.

1. Open **Privileged Inspection...**.
2. The dedicated window initially behaves like the normal SELinux Inspector and uses ordinary-user visibility.
3. Choose **Inspect with Privileged Access...** when elevated visibility is wanted.
4. PolicyKit authorizes the fixed helper session.
5. Authorization itself does **not** run a bulk scan. The user continues to inspect/refresh the individual tabs normally.
6. Helper-supported policy tabs use the fixed helper while that session is active.
7. **Recent Denials** remains explicit scan-only and retains **Scan Normally** and **Scan with Privileged Access...**.
8. Closing the Privileged Inspection window stops the helper process and ends the LinSpectacles elevated session.

The main SELinux Inspector window remains ordinary-user inspection throughout.

## Visual model

The Privileged Inspection window deliberately mirrors the established SELinux Inspector 0.0.3 interface instead of using a second diagnostic layout. It retains the same tab names and, where applicable:

- result count / status heading;
- **Refresh List**;
- **Export...**;
- **Search**;
- **Category** filtering;
- the table + Metadata Details split view;
- right-click column visibility inherited from the common table control.

The privileged window uses the amber/gold accent to make the elevated context visually distinct. It does not stack separate Basic and Elevated copies of the same table. A separate **Comparison Report...** dialog records actual paired ordinary-user and helper-backed results from helper-supported views that the user explicitly scans or refreshes during the session. It does not present theoretical capability differences from the manifest.

## Recent AVC denials

Recent Denials is never read just because the applet, the privileged window, or the helper session is opened. The user chooses either:

- **Scan Normally** — runs the normal fixed `ausearch` query with current-user permissions; or
- **Scan with Privileged Access...** — uses the already-active fixed helper, or requests the helper session first and then performs only that denial scan.

`ausearch` exit status 1 without a permission error is treated as a successful no-match result, as in SELinux Inspector 0.0.3.

## Fixed privileged operations

The helper exposes only these fixed read-only operation families:

- recent AVC / USER_AVC denials;
- policy module listings;
- permissive domains;
- SELinux users;
- login mappings;
- port contexts;
- file-context rules.

There is no arbitrary command interface and no generic privileged file-read interface. The helper cannot run `setenforce`, `setsebool`, `chcon`, `restorecon`, policy install/remove operations, or other SELinux-changing actions.

## Installation and integrity

The applet can install, update/repair, or remove the helper through PolicyKit. The expected install path is fixed by the applet contract. The installed executable is accepted only when it is a regular root-owned executable, is not group/other writable, and its SHA-256 matches the packaged helper declared by `applet.json`.

`applet.json` contains the declarative Privileged Helper Contract v1 metadata so a future Suite-level helper manager can explain, verify and manage the same helper without importing the applet's Python code.
