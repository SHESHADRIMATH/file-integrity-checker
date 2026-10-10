# File Integrity Checker (mini-Tripwire)

A desktop tool that stores **SHA-256 fingerprints** of every file in a folder and
alerts you when any file is **modified, added, or deleted** — a lightweight version
of file integrity monitors like Tripwire, AIDE, and OSSEC.

Built with Python + Tkinter (GUI).

---

## How it works

### The idea: hashing

A hash function like **SHA-256** turns any file into a fixed 64-character fingerprint:

```
report.pdf  ->  3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b
```

Three properties make this perfect for integrity checking:

1. **Deterministic** – the same file always produces the same hash.
2. **Avalanche effect** – change a single bit and the hash changes completely.
3. **One-way / collision-resistant** – you can't forge a different file with the same hash.

So the fingerprint *is* the file's identity. If the fingerprint changes, the file changed.

### Two phases

**1. Baseline** (run once, on a trusted system)

```
for each file in the folder:
    compute SHA-256
save all hashes to .integrity_baseline.json
```

This is your known-good snapshot.

**2. Check** (run anytime)

```
for each file now:
    compute SHA-256
    compare against the baseline
```

Each file is reported as:

| Status   | Meaning                                   |
|----------|-------------------------------------------|
| `OK`       | Hash matches the baseline                 |
| `MODIFIED` | File content changed (even by one byte)   |
| `NEW`      | File exists now but wasn't in the baseline |
| `DELETED`  | File was in the baseline but is now gone  |

**3. Update** – if the changes are legitimate, save the current state as the new baseline.

---

## Features

- Recursive folder scanning
- SHA-256 hashing, read in 64 KB chunks (handles large files)
- Colour-coded results table: 🟢 OK · 🔴 MODIFIED · 🟡 NEW · 🟣 DELETED
- One-click **Create Baseline / Check Integrity / Update Baseline**
- Pop-up alert summarising detected changes

---

## Requirements

- Python 3.8+
- Tkinter (bundled with standard Python on Windows and macOS)

No third-party packages needed.

---

## How to run

GitHub only stores the code — the GUI runs locally with Python.

```bash
git clone https://github.com/SHESHADRIMATH/file-integrity-checker.git
cd file-integrity-checker
python integrity_checker.py
```

Then in the window:

1. **Choose Folder…** – pick a folder to watch.
2. **Create Baseline** – saves a trusted snapshot (`.integrity_baseline.json`).
3. **Check Integrity** – compares the folder against that snapshot and lists any changes.
4. **Update Baseline** – accept the current state as the new baseline (after expected changes).

### Quick demo

1. Make a folder with a couple of `.txt` files.
2. Choose Folder → Create Baseline.
3. Edit one file, add another, delete a third.
4. Check Integrity → the alert fires and the table shows `MODIFIED` / `NEW` / `DELETED`.

---

## What it catches vs. doesn't

| Catches                               | Doesn't catch                                   |
|---------------------------------------|-------------------------------------------------|
| Content modified (even 1 byte)        | Changes made *before* the baseline was taken    |
| Files added / deleted                 | An attacker who also rewrites the baseline file |
| Silent corruption (bad disk)          | *Which* bytes changed (only that it changed)    |

### Security note

The baseline file is the tool's **root of trust**. An attacker who can modify files
could also rewrite the baseline. Real Tripwire protects it with a cryptographic
signature; this version keeps it simple and excludes the baseline from its own scan.

---

## Project structure

```
integrity_checker.py   # engine (hashing, scanning, comparing) + Tkinter GUI
.gitignore
README.md
```
