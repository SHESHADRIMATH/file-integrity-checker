"""
File Integrity Checker  (mini-Tripwire, GUI edition)
====================================================
A desktop tool that stores SHA-256 fingerprints of every file in a folder
and alerts you when any file is MODIFIED, ADDED, or DELETED.

How to use:
  1. Run:  python integrity_checker.py
  2. Click "Choose Folder..." and pick a folder to watch.
  3. Click "Create Baseline"  -> saves a trusted snapshot (.integrity_baseline.json).
  4. Later, click "Check Integrity" -> compares the folder against that snapshot.
  5. If changes are legitimate, click "Update Baseline" to accept them.

Security note (good for the report):
  The baseline file is the tool's root of trust. A real attacker who can edit
  files could also rewrite the baseline. Tripwire protects it with a crypto
  signature; here we keep it simple and just hide it from the scan.
"""

import hashlib
import json
import os
from datetime import datetime

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

BASELINE_NAME = ".integrity_baseline.json"   # stored inside the watched folder
CHUNK = 65536                                 # read files in 64 KB chunks


# ======================================================================
#  ENGINE  (no GUI here -- this is the part that does the real work)
# ======================================================================
def sha256_of_file(path):
    """Return the SHA-256 hex digest of one file, reading it in chunks
    so even multi-GB files don't blow up memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def scan_folder(folder):
    """Walk the folder recursively and return {relative_path: sha256}.
    Skips the baseline file itself."""
    result = {}
    for root, _dirs, files in os.walk(folder):
        for name in files:
            if name == BASELINE_NAME:
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, folder)
            try:
                result[rel] = sha256_of_file(full)
            except (OSError, PermissionError):
                result[rel] = "UNREADABLE"
    return result


def baseline_path(folder):
    return os.path.join(folder, BASELINE_NAME)


def save_baseline(folder, hashes):
    data = {"created": datetime.now().isoformat(timespec="seconds"),
            "folder": folder,
            "files": hashes}
    with open(baseline_path(folder), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_baseline(folder):
    with open(baseline_path(folder), "r", encoding="utf-8") as f:
        return json.load(f)


def compare(old, new):
    """Compare two {path: hash} dicts. Returns a list of (path, status)."""
    rows = []
    for path, h in new.items():
        if path not in old:
            rows.append((path, "NEW"))
        elif old[path] != h:
            rows.append((path, "MODIFIED"))
        else:
            rows.append((path, "OK"))
    for path in old:
        if path not in new:
            rows.append((path, "DELETED"))
    # Order: problems first, OK last, alphabetical within each group
    order = {"MODIFIED": 0, "NEW": 1, "DELETED": 2, "OK": 3}
    rows.sort(key=lambda r: (order.get(r[1], 9), r[0].lower()))
    return rows


# ======================================================================
#  GUI
# ======================================================================
STATUS_COLORS = {
    "OK":       "#1a7f37",   # green
    "MODIFIED": "#d1242f",   # red
    "NEW":      "#9a6700",   # amber
    "DELETED":  "#8250df",   # purple
}


class IntegrityApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("File Integrity Checker  -  mini Tripwire")
        self.geometry("760x520")
        self.minsize(640, 420)
        self.folder = None
        self._build_ui()

    # ---- layout --------------------------------------------------------
    def _build_ui(self):
        top = tk.Frame(self, padx=12, pady=10)
        top.pack(fill="x")

        tk.Button(top, text="Choose Folder...", command=self.choose_folder,
                  width=14).pack(side="left")
        self.folder_lbl = tk.Label(top, text="No folder selected",
                                   fg="#555", anchor="w")
        self.folder_lbl.pack(side="left", padx=10, fill="x", expand=True)

        btns = tk.Frame(self, padx=12)
        btns.pack(fill="x")
        self.btn_base = tk.Button(btns, text="Create Baseline",
                                  command=self.create_baseline,
                                  state="disabled", width=16)
        self.btn_check = tk.Button(btns, text="Check Integrity",
                                   command=self.check_integrity,
                                   state="disabled", width=16)
        self.btn_update = tk.Button(btns, text="Update Baseline",
                                    command=self.update_baseline,
                                    state="disabled", width=16)
        for b in (self.btn_base, self.btn_check, self.btn_update):
            b.pack(side="left", padx=(0, 8), pady=6)

        # results table
        wrap = tk.Frame(self, padx=12, pady=6)
        wrap.pack(fill="both", expand=True)
        cols = ("file", "status")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings")
        self.tree.heading("file", text="File")
        self.tree.heading("status", text="Status")
        self.tree.column("file", width=560, anchor="w")
        self.tree.column("status", width=120, anchor="center")
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        for status, color in STATUS_COLORS.items():
            self.tree.tag_configure(status, foreground=color)

        self.status = tk.Label(self, text="Pick a folder to begin.",
                               bd=1, relief="sunken", anchor="w", padx=8)
        self.status.pack(fill="x", side="bottom")

    # ---- actions -------------------------------------------------------
    def choose_folder(self):
        folder = filedialog.askdirectory(title="Choose a folder to watch")
        if not folder:
            return
        self.folder = folder
        self.folder_lbl.config(text=folder, fg="#000")
        self.btn_base.config(state="normal")
        has_base = os.path.exists(baseline_path(folder))
        self.btn_check.config(state="normal" if has_base else "disabled")
        self.btn_update.config(state="normal" if has_base else "disabled")
        self._clear()
        if has_base:
            self._set_status(f"Baseline found. Click 'Check Integrity'.")
        else:
            self._set_status("No baseline yet. Click 'Create Baseline'.")

    def create_baseline(self):
        if os.path.exists(baseline_path(self.folder)):
            if not messagebox.askyesno("Overwrite baseline?",
                                       "A baseline already exists.\nReplace it "
                                       "with the current folder state?"):
                return
        hashes = scan_folder(self.folder)
        save_baseline(self.folder, hashes)
        self._clear()
        self.btn_check.config(state="normal")
        self.btn_update.config(state="normal")
        self._set_status(f"Baseline created: {len(hashes)} files fingerprinted.")
        messagebox.showinfo("Baseline created",
                            f"Stored SHA-256 for {len(hashes)} files.")

    def check_integrity(self):
        try:
            base = load_baseline(self.folder)
        except FileNotFoundError:
            messagebox.showerror("No baseline", "Create a baseline first.")
            return
        now = scan_folder(self.folder)
        rows = compare(base["files"], now)
        self._show(rows)
        counts = {s: 0 for s in STATUS_COLORS}
        for _f, s in rows:
            counts[s] = counts.get(s, 0) + 1
        changed = counts["MODIFIED"] + counts["NEW"] + counts["DELETED"]
        summary = (f"Modified {counts['MODIFIED']} | New {counts['NEW']} | "
                   f"Deleted {counts['DELETED']} | OK {counts['OK']}   "
                   f"(baseline {base['created']})")
        self._set_status(summary)
        if changed:
            messagebox.showwarning("Integrity ALERT",
                                   f"{changed} change(s) detected!\n\n" + summary)
        else:
            messagebox.showinfo("All clear",
                                "No changes. Every file matches the baseline.")

    def update_baseline(self):
        if not messagebox.askyesno("Update baseline?",
                                   "Accept the current folder state as the new "
                                   "trusted baseline?\n\nDo this only if the "
                                   "changes are expected."):
            return
        save_baseline(self.folder, scan_folder(self.folder))
        self._clear()
        self._set_status("Baseline updated to current state.")

    # ---- helpers -------------------------------------------------------
    def _show(self, rows):
        self._clear()
        for path, status in rows:
            self.tree.insert("", "end", values=(path, status), tags=(status,))

    def _clear(self):
        self.tree.delete(*self.tree.get_children())

    def _set_status(self, text):
        self.status.config(text=text)


if __name__ == "__main__":
    IntegrityApp().mainloop()
