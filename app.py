import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from hashing import ALGORITHMS, file_matches_hash, files_match, hash_file, hash_text

APP_TITLE = "Cryptography Toolkit"


class ToolkitApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(640, 480)
        self._build_tabs()

    def _build_tabs(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        notebook.add(self._build_hash_tab(notebook), text="Hash")
        notebook.add(self._build_verify_tab(notebook), text="Verify")

    # ---------- Hash tab ----------
    def _build_hash_tab(self, parent):
        tab = ttk.Frame(parent, padding=10)
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(3, weight=1)

        ttk.Label(tab, text="Algorithm:").grid(row=0, column=0, sticky="w")
        self.hash_algorithm = tk.StringVar(value=ALGORITHMS[0])
        ttk.Combobox(
            tab, textvariable=self.hash_algorithm, values=ALGORITHMS,
            state="readonly", width=10,
        ).grid(row=1, column=0, sticky="w", pady=(0, 10))

        ttk.Label(tab, text="Text to hash:").grid(row=2, column=0, sticky="w")
        self.hash_input = tk.Text(tab, height=6, wrap="word")
        self.hash_input.grid(row=3, column=0, sticky="nsew")

        buttons = ttk.Frame(tab)
        buttons.grid(row=4, column=0, sticky="w", pady=10)
        ttk.Button(buttons, text="Hash text", command=self.on_hash_text).pack(side="left")
        ttk.Button(buttons, text="Hash a file...", command=self.on_hash_file).pack(
            side="left", padx=(8, 0)
        )

        ttk.Label(tab, text="Result:").grid(row=5, column=0, sticky="w")
        self.hash_output = tk.StringVar()
        ttk.Entry(tab, textvariable=self.hash_output, state="readonly").grid(
            row=6, column=0, sticky="ew"
        )
        ttk.Button(tab, text="Copy", command=self.on_copy_hash).grid(
            row=7, column=0, sticky="w", pady=(8, 0)
        )
        return tab

    def on_hash_text(self):
        text = self.hash_input.get("1.0", "end-1c")
        try:
            self.hash_output.set(hash_text(text, self.hash_algorithm.get()))
        except ValueError as error:
            messagebox.showerror("Cannot hash", str(error))

    def on_hash_file(self):
        path = filedialog.askopenfilename(title="Choose a file to hash")
        if not path:
            return
        try:
            self.hash_output.set(hash_file(path, self.hash_algorithm.get()))
        except OSError as error:
            messagebox.showerror("Cannot read file", str(error))

    def on_copy_hash(self):
        value = self.hash_output.get()
        if not value:
            return
        self.clipboard_clear()
        self.clipboard_append(value)

    # ---------- Verify tab ----------
    def _build_verify_tab(self, parent):
        tab = ttk.Frame(parent, padding=10)
        tab.columnconfigure(0, weight=1)

        algorithm_row = ttk.Frame(tab)
        algorithm_row.grid(row=0, column=0, sticky="w")
        ttk.Label(algorithm_row, text="Algorithm:").pack(side="left")
        self.verify_algorithm = tk.StringVar(value=ALGORITHMS[0])
        ttk.Combobox(
            algorithm_row, textvariable=self.verify_algorithm, values=ALGORITHMS,
            state="readonly", width=10,
        ).pack(side="left", padx=(8, 0))

        compare = ttk.LabelFrame(tab, text="Compare two files", padding=10)
        compare.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        compare.columnconfigure(1, weight=1)
        self.file1 = tk.StringVar()
        self.file2 = tk.StringVar()
        self._file_row(compare, 0, "File 1:", self.file1)
        self._file_row(compare, 1, "File 2:", self.file2)
        ttk.Button(compare, text="Compare", command=self.on_compare).grid(
            row=2, column=0, sticky="w", pady=(8, 0)
        )

        check = ttk.LabelFrame(tab, text="Check a file against a hash", padding=10)
        check.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        check.columnconfigure(1, weight=1)
        self.check_file = tk.StringVar()
        self.expected_hash = tk.StringVar()
        self._file_row(check, 0, "File:", self.check_file)
        ttk.Label(check, text="Expected hash:").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Entry(check, textvariable=self.expected_hash).grid(
            row=1, column=1, columnspan=2, sticky="ew", padx=6
        )
        ttk.Button(check, text="Check", command=self.on_check_hash).grid(
            row=2, column=0, sticky="w", pady=(8, 0)
        )

        self.verify_result = ttk.Label(tab, text="", font=("TkDefaultFont", 11, "bold"))
        self.verify_result.grid(row=3, column=0, sticky="w", pady=(12, 0))
        return tab

    def _file_row(self, parent, row, label, variable):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", padx=6)
        ttk.Button(parent, text="Browse...", command=lambda: self._browse(variable)).grid(
            row=row, column=2
        )

    def _browse(self, variable):
        path = filedialog.askopenfilename()
        if path:
            variable.set(path)

    def _show_result(self, ok, message):
        self.verify_result.config(text=message, foreground="green" if ok else "red")

    def on_compare(self):
        path1 = self.file1.get().strip()
        path2 = self.file2.get().strip()
        if not path1 or not path2:
            messagebox.showerror("Missing file", "Please choose both files first.")
            return
        try:
            same = files_match(path1, path2, self.verify_algorithm.get())
        except OSError as error:
            messagebox.showerror("Cannot read file", str(error))
            return
        if same:
            self._show_result(True, "Files are identical. No modifications detected.")
        else:
            self._show_result(False, "Files differ! Modifications detected.")

    def on_check_hash(self):
        path = self.check_file.get().strip()
        if not path:
            messagebox.showerror("Missing file", "Please choose a file first.")
            return
        try:
            matches = file_matches_hash(
                path, self.expected_hash.get(), self.verify_algorithm.get()
            )
        except (OSError, ValueError) as error:
            messagebox.showerror("Cannot check file", str(error))
            return
        if matches:
            self._show_result(True, "Hash matches. The file is intact.")
        else:
            self._show_result(False, "Hash does NOT match. The file was changed or is different.")


if __name__ == "__main__":
    ToolkitApp().mainloop()