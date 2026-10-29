"""
panel.py — Panel de control de la Bóveda para Windows.

Abre las copias cifradas (.vault) exportadas desde la app del iPhone,
las descifra con tu PATRÓN, te deja ver/editar los secretos y guardar
una copia para reimportar en el móvil. Mismo cifrado que la app.

CÓMO USAR EN WINDOWS:
  1. Instala Python 3 desde python.org (marca "Add to PATH").
  2. Abre PowerShell y ejecuta:  pip install cryptography
  3. Doble clic en panel.py  (o:  python panel.py)

El patrón se dibuja pulsando los puntos en orden (igual que en el móvil):
    1 2 3
    4 5 6
    7 8 9
"""

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

import panel_core as core

BG = "#111827"; CARD = "#1a2234"; LINE = "#273047"
TEXT = "#e5e7eb"; MUTED = "#9ca3af"; ACCENT = "#6366f1"; DANGER = "#f87171"; OK = "#34d399"


class PanelApp:
    def __init__(self, root):
        self.root = root
        self.state = None          # estado del .vault cargado
        self.path = None           # ruta del archivo
        self.pattern_seq = []      # índices 0..8 pulsados
        self.data = None           # datos descifrados (cuando está abierto)

        root.title("Bóveda — Panel de control")
        root.configure(bg=BG)
        root.geometry("460x640")

        tk.Label(root, text="🔐 Bóveda — Panel de control", bg=BG, fg=TEXT,
                 font=("Segoe UI", 15, "bold")).pack(pady=(16, 2))
        tk.Label(root, text="Cifrado AES-256 · compatible con la app del iPhone",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack()

        tk.Button(root, text="📂 Abrir copia (.vault)", command=self.open_file,
                  bg=CARD, fg=TEXT, relief="flat", font=("Segoe UI", 11),
                  activebackground=LINE, padx=10, pady=8).pack(pady=12)

        self.file_lbl = tk.Label(root, text="Ningún archivo cargado", bg=BG, fg=MUTED,
                                 font=("Segoe UI", 9))
        self.file_lbl.pack()

        # --- Zona de patrón ---
        self.pad_frame = tk.Frame(root, bg=BG)
        self.pad_frame.pack(pady=10)
        self.dot_btns = []
        for r in range(3):
            for c in range(3):
                idx = r * 3 + c
                b = tk.Button(self.pad_frame, text="•", width=3, height=1,
                              font=("Segoe UI", 18), bg=CARD, fg=MUTED, relief="flat",
                              activebackground=ACCENT,
                              command=lambda i=idx: self.tap_dot(i))
                b.grid(row=r, column=c, padx=6, pady=6)
                self.dot_btns.append(b)

        self.seq_lbl = tk.Label(root, text="Dibuja tu patrón pulsando los puntos",
                                bg=BG, fg=MUTED, font=("Segoe UI", 9))
        self.seq_lbl.pack()

        bar = tk.Frame(root, bg=BG); bar.pack(pady=8)
        tk.Button(bar, text="Borrar patrón", command=self.clear_pattern, bg=CARD, fg=TEXT,
                  relief="flat", padx=8, pady=6).grid(row=0, column=0, padx=5)
        tk.Button(bar, text="🔓 Desbloquear", command=self.unlock, bg=ACCENT, fg="white",
                  relief="flat", padx=10, pady=6, font=("Segoe UI", 10, "bold")).grid(row=0, column=1, padx=5)

        # --- Lista de secretos ---
        self.listbox = tk.Listbox(root, bg=CARD, fg=TEXT, relief="flat", height=8,
                                  selectbackground=ACCENT, font=("Consolas", 10))
        self.listbox.pack(fill="both", expand=True, padx=16, pady=(10, 4))

        add = tk.Frame(root, bg=BG); add.pack(fill="x", padx=16)
        self.e_key = tk.Entry(add, bg=CARD, fg=TEXT, relief="flat", insertbackground=TEXT)
        self.e_val = tk.Entry(add, bg=CARD, fg=TEXT, relief="flat", insertbackground=TEXT)
        self.e_key.insert(0, ""); self.e_val.insert(0, "")
        tk.Label(add, text="Nombre", bg=BG, fg=MUTED, font=("Segoe UI", 8)).grid(row=0, column=0, sticky="w")
        tk.Label(add, text="Valor", bg=BG, fg=MUTED, font=("Segoe UI", 8)).grid(row=0, column=1, sticky="w")
        self.e_key.grid(row=1, column=0, padx=(0, 4), pady=2, sticky="ew")
        self.e_val.grid(row=1, column=1, padx=(4, 0), pady=2, sticky="ew")
        add.columnconfigure(0, weight=1); add.columnconfigure(1, weight=1)

        act = tk.Frame(root, bg=BG); act.pack(pady=8)
        tk.Button(act, text="➕ Añadir", command=self.add_entry, bg=CARD, fg=TEXT,
                  relief="flat", padx=8, pady=6).grid(row=0, column=0, padx=4)
        tk.Button(act, text="🗑 Borrar sel.", command=self.del_entry, bg=CARD, fg=DANGER,
                  relief="flat", padx=8, pady=6).grid(row=0, column=1, padx=4)
        tk.Button(act, text="💾 Guardar copia", command=self.save, bg=OK, fg="#06281d",
                  relief="flat", padx=8, pady=6, font=("Segoe UI", 10, "bold")).grid(row=0, column=2, padx=4)

        self.set_locked(True)

    # ---------- patrón ----------
    def tap_dot(self, i):
        if i in self.pattern_seq:
            return
        self.pattern_seq.append(i)
        self.dot_btns[i].configure(fg="white", bg=ACCENT)
        self.seq_lbl.configure(text="Patrón: " + " → ".join(str(x + 1) for x in self.pattern_seq))

    def clear_pattern(self):
        self.pattern_seq = []
        for b in self.dot_btns:
            b.configure(fg=MUTED, bg=CARD)
        self.seq_lbl.configure(text="Dibuja tu patrón pulsando los puntos")

    def pattern_str(self):
        return "-".join(str(i) for i in self.pattern_seq)

    # ---------- archivo ----------
    def open_file(self):
        path = filedialog.askopenfilename(
            title="Abrir copia de la bóveda",
            filetypes=[("Bóveda", "*.vault *.json"), ("Todos", "*.*")])
        if not path:
            return
        try:
            self.state = core.load_file(path)
            self.path = path
            self.file_lbl.configure(text="Cargado: " + path.split("/")[-1].split("\\")[-1], fg=OK)
            self.set_locked(True)
            self.clear_pattern()
            if self.state.get("destroyed"):
                messagebox.showwarning("Bóveda destruida",
                    "Esta copia fue autodestruida. No contiene datos recuperables.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir: {e}")

    def unlock(self):
        if not self.state:
            return messagebox.showinfo("Falta archivo", "Primero abre una copia (.vault).")
        if len(self.pattern_seq) < 4:
            return messagebox.showinfo("Patrón corto", "El patrón necesita al menos 4 puntos.")
        try:
            self.data = core.decrypt_vault(self.state, self.pattern_str())
            self.set_locked(False)
            self.refresh_list()
            self.clear_pattern()
        except core.WrongPattern as e:
            core.save_file(self.path, self.state)   # persiste el contador de fallos
            self.clear_pattern()
            messagebox.showerror("Patrón incorrecto", f"Intentos restantes: {e.left}")
        except core.VaultDestroyed:
            # Límite alcanzado: crypto-erase de la copia (igual que en el móvil)
            core.save_file(self.path, {"version": 2, "destroyed": True, "failed": 0, "maxAttempts": 0})
            self.state = core.load_file(self.path)
            messagebox.showwarning("Autodestrucción",
                "Límite de intentos superado. La copia se ha autodestruido.")

    # ---------- edición ----------
    def refresh_list(self):
        self.listbox.delete(0, tk.END)
        for e in self.data["entries"]:
            self.listbox.insert(tk.END, f"{e['key']:<22}  {e['val']}")

    def add_entry(self):
        if self.data is None:
            return
        k, v = self.e_key.get().strip(), self.e_val.get().strip()
        if not k or not v:
            return messagebox.showinfo("Faltan datos", "Pon nombre y valor.")
        self.data["entries"].append({"key": k, "val": v})
        self.e_key.delete(0, tk.END); self.e_val.delete(0, tk.END)
        self.refresh_list()

    def del_entry(self):
        if self.data is None:
            return
        sel = self.listbox.curselection()
        if not sel:
            return
        del self.data["entries"][sel[0]]
        self.refresh_list()

    def save(self):
        if self.data is None:
            return messagebox.showinfo("Bloqueada", "Primero desbloquea la bóveda.")
        pat = simpledialog.askstring("Confirmar patrón",
            "Vuelve a escribir tu patrón (números de los puntos separados por guion, p. ej. 0-1-2-5-8):")
        if not pat:
            return
        try:
            core.encrypt_vault(self.state, pat, self.data)
            # verificación: que se pueda volver a descifrar con ese patrón
            core.decrypt_vault(dict(self.state), pat)
        except Exception:
            return messagebox.showerror("Patrón no válido", "No pude cifrar con ese patrón.")
        path = filedialog.asksaveasfilename(
            title="Guardar copia cifrada", defaultextension=".vault",
            initialfile="boveda.vault", filetypes=[("Bóveda", "*.vault")])
        if not path:
            return
        core.save_file(path, self.state)
        messagebox.showinfo("Guardado",
            "Copia cifrada guardada.\n\nPásala al iPhone y usa 'Importar copia del PC' en la app.")

    def set_locked(self, locked):
        state = "disabled" if locked else "normal"
        for w in (self.listbox, self.e_key, self.e_val):
            w.configure(state=state)
        if locked:
            self.listbox.configure(state="normal")
            self.listbox.delete(0, tk.END)
            self.listbox.insert(tk.END, "  🔒 Bloqueada — abre un .vault y dibuja tu patrón")
            self.listbox.configure(state="disabled")
            self.data = None


if __name__ == "__main__":
    root = tk.Tk()
    PanelApp(root)
    root.mainloop()
