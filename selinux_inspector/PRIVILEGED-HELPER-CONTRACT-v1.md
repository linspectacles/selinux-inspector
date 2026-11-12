# LinSpectacles Privileged Helper Contract v1

This package is the first reference implementation of the LinSpectacles Privileged Helper Contract v1.

An applet that supports optional elevated inspection may declare a top-level `privileged_helper` object in `applet.json` with these fields:

- `schema`: contract schema number; currently `1`.
- `id`: stable helper identifier.
- `name`: human-readable helper name.
- `version`: helper version required by this applet package.
- `protocol`: helper IPC protocol version.
- `publisher`: publisher identity declared by the applet package.
- `payload`: package-relative helper executable path.
- `install_path`: fixed system installation path.
- `sha256`: expected hash of the packaged and installed helper executable.
- `session_model`: currently `window_ephemeral` for the reference implementation.
- `read_only`: whether the declared helper contract is inspection-only.
- `capabilities`: descriptive Basic-vs-Elevated capability records.

Each capability may declare:

- `id`: stable capability identifier.
- `label`: user-facing name.
- `standard`: what ordinary-user inspection can provide.
- `elevated`: what the optional helper can add.
- `kind`: `common` when privilege adds no visibility for that fact, or `expanded` when the fixed helper may remove a permission barrier or return a more complete result.

## Lifecycle rule

For `window_ephemeral`, installing a helper and using privilege are separate states. The helper process is launched only after explicit authorization from the dedicated Privileged Inspection window and must be stopped when that window closes. Normal applet views remain ordinary-user collectors throughout the elevated session.

## Trust rule

The reference applet validates the installed helper's file type, root ownership, write permissions, and exact manifest hash before use. This contract is metadata, not a blanket trust grant for arbitrary third-party root executables. A future Suite-level manager must apply its own publisher/trust policy before offering centralized one-click installation.

## Scope rule

A privileged helper must expose fixed operations rather than arbitrary commands or unrestricted file reads. Elevated collection must remain read-only unless a future contract explicitly defines a different class of helper; that is outside Contract v1.
