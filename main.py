"""Aplikasi tugas Tkinter + SQLite. Jalankan: python main.py."""
import hashlib
import hmac
import secrets
import sqlite3
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog


class Database:
    def __init__(self, path):
        self.conn = sqlite3.connect(path)
        self.conn.execute('PRAGMA foreign_keys = ON')
        self.conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS kategori (
            id INTEGER PRIMARY KEY,
            nama TEXT NOT NULL UNIQUE CHECK(length(trim(nama)) > 0)
        );
        CREATE TABLE IF NOT EXISTS produk (
            id INTEGER PRIMARY KEY,
            nama TEXT NOT NULL CHECK(length(trim(nama)) > 0),
            kategori_id INTEGER NOT NULL REFERENCES kategori(id) ON DELETE RESTRICT,
            harga INTEGER NOT NULL CHECK(harga >= 0),
            stok INTEGER NOT NULL CHECK(stok >= 0)
        );
        ''')
        columns = {row[1] for row in self.conn.execute('PRAGMA table_info(users)')}
        if 'recovery_hash' not in columns:
            with self.conn:
                self.conn.execute('ALTER TABLE users ADD COLUMN recovery_hash TEXT')

    def seed_demo_once(self):
        """Tambahkan data contoh satu kali; pertahankan akun dan data yang ada."""
        if self.conn.execute('PRAGMA user_version').fetchone()[0] >= 2:
            return
        samples = {
            'Makanan': [('Pizza Mini', 10000, 25), ('Roti Tawar', 18000, 15), ('Mi Instan', 3500, 60), ('Nasi Kotak', 25000, 10), ('Ayam Goreng 1 Ekor', 50000, 8), ('Burger', 20000, 20), ('Sate Ayam 10 tusuk', 30000, 12), ('Bakso 5 pcs', 15000, 18), ('Nugget Ayam 250 g', 25000, 14), ('Pasta Spaghetti 200 g', 22000, 16)],
            'Minuman': [('Air Mineral 600 ml', 4000, 48), ('Teh Botol 350 ml', 5000, 36), ('Kopi Susu 250 ml', 8000, 24), ('Jus Jeruk 300 ml', 12000, 20), ('Susu UHT 200 ml', 7000, 30), ('Es Teh Manis 250 ml', 6000, 40), ('Soda 330 ml', 9000, 28), ('Smoothie Buah 300 ml', 15000, 18), ('Minuman Energi 250 ml', 10000, 22), ('Kombucha 250 ml', 14000, 15)],
            'Camilan': [('Keripik Kentang 60 g', 10000, 20), ('Biskuit Cokelat 100 g', 8500, 30), ('Cokelat Batang 30 g', 7000, 25), ('Permen Mint 20 g', 5000, 40), ('Kacang Goreng 50 g', 12000, 15)],
            'Sembako': [('Beras 5 kg', 75000, 12), ('Gula Pasir 1 kg', 18000, 20), ('Minyak Goreng 1 L', 20000, 24), ('Tepung Terigu 1 kg', 15000, 18), ('Telur Ayam 1 kg', 25000, 15)],
            'Perawatan Diri': [('Sabun Mandi 80 g', 4500, 40), ('Sampo 170 ml', 22000, 18), ('Pasta Gigi 120 g', 14000, 24),('Deodoran 150 ml', 30000, 15), ('Hand Sanitizer 100 ml', 25000, 30)],
            'Kebersihan Rumah': [('Detergen 800 g', 18000, 20), ('Pembersih Lantai 800 ml', 16000, 15), ('Sabun Cuci Piring 750 ml', 15000, 18), ('Sikat WC', 12000, 12), ('Lap Serbaguna', 10000, 25)],
            'Alat Tulis': [('Buku Tulis 38 Lembar', 5000, 50), ('Pulpen Biru', 3000, 60), ('Pensil 2B', 2500, 40), ('Penghapus', 2000, 30), ('Penggaris 30 cm', 4000, 25)],
            'Perlengkapan Rumah': [('Gelas Kaca', 12000, 24), ('Piring Makan', 15000, 18), ('Sendok Makan', 5000, 36), ('Sapu Lantai', 25000, 12), ('Ember Plastik 10 L', 30000, 15)],
        }
        with self.conn:
            for category, products in samples.items():
                self.conn.execute('INSERT OR IGNORE INTO kategori(nama) VALUES(?)', (category,))
                cid = self.conn.execute('SELECT id FROM kategori WHERE nama=?', (category,)).fetchone()[0]
                for name, price, stock in products:
                    exists = self.conn.execute('SELECT id FROM produk WHERE nama=? AND kategori_id=?', (name, cid)).fetchone()
                    if not exists:
                        self.conn.execute('INSERT INTO produk(nama,kategori_id,harga,stok) VALUES(?,?,?,?)', (name, cid, price, stock))
            self.conn.execute('PRAGMA user_version = 2')

    def rows(self, sql, params=()):
        return self.conn.execute(sql, params).fetchall()

    def write(self, sql, params=()):
        with self.conn:
            return self.conn.execute(sql, params).lastrowid

    @staticmethod
    def digest(password, salt):
        return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 300000).hex()

    def create_user(self, username, password):
        username = username.strip()
        if not username or len(password) < 8:
            raise ValueError('Username wajib diisi dan password minimal 8 karakter.')
        salt = secrets.token_hex(16)
        code = secrets.token_hex(16).upper()
        self.write('INSERT INTO users(username,salt,password_hash,recovery_hash) VALUES(?,?,?,?)',
                   (username, salt, self.digest(password, salt), self.recovery_digest(code)))
        return code

    def authenticate(self, username, password):
        rows = self.rows('SELECT salt,password_hash FROM users WHERE username=?', (username.strip(),))
        return bool(rows and hmac.compare_digest(self.digest(password, rows[0][0]), rows[0][1]))

    @staticmethod
    def recovery_digest(code):
        normalized = ''.join(code.split()).replace('-', '').upper()
        return hashlib.sha256(normalized.encode()).hexdigest()

    def issue_recovery_code(self, username, password):
        if not self.authenticate(username, password):
            raise ValueError('Password saat ini salah.')
        code = secrets.token_hex(16).upper()
        self.write('UPDATE users SET recovery_hash=? WHERE username=?',
                   (self.recovery_digest(code), username.strip()))
        return code

    def recover_account(self, code, username, password):
        username = username.strip()
        if not username or len(password) < 8:
            raise ValueError('Username baru wajib diisi dan password minimal 8 karakter.')
        # Kode acak 128-bit mengidentifikasi akun tanpa meminta username lama.
        digest = self.recovery_digest(code)
        salt = secrets.token_hex(16)
        password_hash = self.digest(password, salt)
        new_code = secrets.token_hex(16).upper()
        with self.conn:
            result = self.conn.execute(
                'UPDATE users SET username=?,salt=?,password_hash=?,recovery_hash=? WHERE recovery_hash=?',
                (username, salt, password_hash, self.recovery_digest(new_code), digest))
            if result.rowcount != 1:
                raise ValueError('Kode pemulihan tidak valid atau sudah pernah digunakan.')
        return new_code


class App(tk.Tk):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.title('StokToko | Manajemen Persediaan')
        self.geometry('1120x800')
        self.minsize(1000, 740)
        self.configure(bg='#edf3f7')
        self.option_add('*Font', ('Segoe UI', 10))
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('.', background='#ffffff', foreground='#23374b', font=('Segoe UI', 10))
        style.configure('TFrame', background='#ffffff')
        style.configure('TLabel', background='#ffffff')
        style.configure('TButton', padding=(14, 9), background='#e8f2f4', foreground='#185b65', borderwidth=0)
        style.map('TButton', background=[('active', '#cce9e8')])
        style.configure('Primary.TButton', background='#087f8c', foreground='white')
        style.map('Primary.TButton', background=[('active', '#066674')])
        style.configure('Danger.TButton', background='#fff0ef', foreground='#b53f3f')
        style.map('Danger.TButton', background=[('active', '#ffdbd8')])
        style.configure('TEntry', padding=8, fieldbackground='#f5f8fb', bordercolor='#d6e1e8')
        style.configure('TCombobox', padding=8, fieldbackground='#f5f8fb', arrowcolor='#087f8c')
        style.map('TCombobox', fieldbackground=[('readonly', '#f5f8fb')])
        style.configure('TNotebook', background='#edf3f7', borderwidth=0)
        style.configure('TNotebook.Tab', padding=(22, 11), background='#dde7ed')
        style.map('TNotebook.Tab', background=[('selected', '#ffffff')], foreground=[('selected', '#087f8c')])
        style.configure('Treeview', rowheight=34, background='white', fieldbackground='white', borderwidth=0)
        style.configure('Treeview.Heading', background='#e5eef4', foreground='#29485e', font=('Segoe UI', 10, 'bold'), padding=9)
        style.map('Treeview', background=[('selected', '#087f8c')], foreground=[('selected', '#ffffff')])
        style.configure('Title.TLabel', font=('Segoe UI', 25, 'bold'), foreground='#16354b')
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.login_screen()

    def close(self):
        self.db.conn.close()
        self.destroy()

    def clear(self):
        for child in self.winfo_children():
            child.destroy()

    def backdrop(self):
        canvas = tk.Canvas(self, highlightthickness=0, bg='#edf3f7')
        canvas.place(x=0, y=0, relwidth=1, relheight=1)
        def draw(event):
            canvas.delete('all')
            w, h = event.width, event.height
            for y in range(0, h, 4):
                t = y / max(h, 1)
                rgb = tuple(int(a + (b-a)*t) for a, b in zip((231, 240, 246), (247, 250, 252)))
                canvas.create_rectangle(0, y, w, y+4, fill='#%02x%02x%02x' % rgb, outline='')
            for x, y, r in [(w-80, 90, 235), (30, h-30, 180)]:
                canvas.create_oval(x-r, y-r, x+r, y+r, outline='#d7e6ec', width=2)
                canvas.create_oval(x-r+30, y-r+30, x+r-30, y+r-30, outline='#d7e6ec')
            for x in range(25, w, 34):
                for y in range(20, h, 34):
                    canvas.create_oval(x, y, x+2, y+2, fill='#cfdfe6', outline='')
        canvas.bind('<Configure>', draw)

    def login_screen(self):
        self.clear()
        self.backdrop()
        setup = not self.db.rows('SELECT id FROM users LIMIT 1')
        panel = ttk.Frame(self, padding=35)
        panel.place(relx=.5, rely=.5, anchor='center')
        ttk.Label(panel, text='PERSEDIAAN • TOKO', foreground='#087f8c').pack(pady=(0, 5))
        ttk.Label(panel, text='StokToko', style='Title.TLabel').pack(pady=12)
        ttk.Label(panel, text='Buat akun pertama' if setup else 'Masuk untuk mengelola persediaan').pack(pady=10)
        username, password = tk.StringVar(), tk.StringVar()
        for label, variable, hide in [('Username', username, ''), ('Password', password, '*')]:
            ttk.Label(panel, text=label).pack(anchor='w', pady=(10, 3))
            ttk.Entry(panel, textvariable=variable, show=hide, width=35).pack()

        def submit(event=None):
            try:
                if setup:
                    code = self.db.create_user(username.get(), password.get())
                    self.login_screen()
                    self.show_recovery_code(code)
                elif self.db.authenticate(username.get(), password.get()):
                    self.home(username.get().strip())
                else:
                    messagebox.showerror('Login gagal', 'Username atau password salah.')
            except (ValueError, sqlite3.Error) as exc:
                messagebox.showerror('Gagal', str(exc))
        ttk.Button(panel, text='Buat akun' if setup else 'Masuk ke dashboard', style='Primary.TButton', command=submit).pack(fill='x', pady=20)
        if not setup:
            ttk.Button(panel, text='Lupa username / password?', command=self.recovery_screen).pack(fill='x')
        for entry in panel.winfo_children():
            if isinstance(entry, ttk.Entry):
                entry.bind('<Return>', submit)

    def show_recovery_code(self, code):
        dialog = tk.Toplevel(self)
        dialog.title('Simpan kode pemulihan')
        dialog.transient(self)
        dialog.resizable(False, False)
        panel = ttk.Frame(dialog, padding=26)
        panel.pack(fill='both', expand=True)
        ttk.Label(panel, text='Kode pemulihan akun', style='Title.TLabel').pack(anchor='w')
        ttk.Label(panel, text='Simpan kode ini di tempat pribadi sebelum menutup jendela.\n'
                  'Kode dapat mengganti username dan password tanpa data login lama.\n'
                  'Kode hanya ditampilkan sekarang; kode sebelumnya tidak berlaku.',
                  wraplength=500).pack(anchor='w', pady=15)
        value = tk.StringVar(value='-'.join(code[i:i+4] for i in range(0, len(code), 4)))
        ttk.Entry(panel, textvariable=value, state='readonly', width=48).pack(fill='x', pady=8)
        ttk.Label(panel, text='Pilih kode lalu Ctrl+C untuk menyalin. Jangan bagikan kepada orang lain.').pack(pady=8)
        ttk.Button(panel, text='Sudah saya simpan', style='Primary.TButton', command=dialog.destroy).pack(fill='x', pady=8)
        dialog.grab_set()
        self.wait_window(dialog)

    def manage_recovery(self, username):
        password = simpledialog.askstring('Kode pemulihan',
            'Masukkan password saat ini untuk membuat kode baru.\nKode sebelumnya akan dinonaktifkan.',
            show='*', parent=self)
        if password is None:
            return
        try:
            code = self.db.issue_recovery_code(username, password)
        except (ValueError, sqlite3.Error) as exc:
            messagebox.showerror('Gagal', str(exc), parent=self)
            return
        self.show_recovery_code(code)

    def recovery_screen(self):
        self.clear()
        self.backdrop()
        panel = ttk.Frame(self, padding=30)
        panel.place(relx=.5, rely=.5, anchor='center')
        ttk.Label(panel, text='Pulihkan akun', style='Title.TLabel').pack(anchor='w')
        ttk.Label(panel, text='Gunakan kode pemulihan yang pernah kamu simpan.\n'
                  'Username lama tidak perlu diingat. Isi username dan password penggantinya.',
                  wraplength=470).pack(anchor='w', pady=12)
        values = [tk.StringVar() for _ in range(4)]
        for label, value, hide in zip(['Kode pemulihan', 'Username baru', 'Password baru (minimal 8 karakter)',
                                        'Ulangi password baru'], values, ['', '', '*', '*']):
            ttk.Label(panel, text=label).pack(anchor='w', pady=(10, 4))
            ttk.Entry(panel, textvariable=value, show=hide, width=48).pack(fill='x')
        def submit():
            if values[2].get() != values[3].get():
                messagebox.showerror('Validasi', 'Konfirmasi password tidak sama.')
                return
            try:
                code = self.db.recover_account(values[0].get(), values[1].get(), values[2].get())
            except sqlite3.IntegrityError:
                messagebox.showerror('Gagal', 'Username sudah digunakan. Pilih username lain.')
                return
            except (ValueError, sqlite3.Error) as exc:
                messagebox.showerror('Gagal', str(exc))
                return
            self.login_screen()
            self.show_recovery_code(code)
            messagebox.showinfo('Berhasil', 'Username dan password diganti. Silakan login dengan data baru.')
        ttk.Button(panel, text='Simpan username & password', style='Primary.TButton', command=submit).pack(fill='x', pady=(18, 8))
        ttk.Button(panel, text='Kembali ke login', command=self.login_screen).pack(fill='x')
        ttk.Label(panel, text='Belum punya kode? Untuk akun lama, login dahulu lalu pilih Kode pemulihan.\n'
                  'Jika password dan kode sama-sama hilang, akun tidak dapat dipulihkan dari menu ini.',
                  wraplength=470, foreground='#697f90').pack(anchor='w', pady=(14, 0))

    def home(self, username):
        self.clear()
        self.backdrop()
        top = tk.Frame(self, bg='#142f46', padx=24, pady=19)
        top.pack(fill='x')
        brand = tk.Frame(top, bg='#142f46')
        brand.pack(side='left')
        tk.Label(brand, text='StokToko', bg='#142f46', fg='white', font=('Segoe UI', 25, 'bold')).pack(anchor='w')
        tk.Label(brand, text='Kelola persediaan. Jaga toko tetap siap.', bg='#142f46', fg='#b4d1df').pack(anchor='w')
        ttk.Button(top, text='Keluar akun', command=self.login_screen).pack(side='right')
        ttk.Button(top, text='Kode pemulihan', command=lambda: self.manage_recovery(username)).pack(side='right', padx=8)
        tk.Label(top, text=f'Halo, {username}   ', bg='#142f46', fg='#d4e9ef').pack(side='right')
        cards = tk.Frame(self, bg='#edf3f7')
        cards.pack(fill='x', padx=22, pady=(18, 0))
        self.stat_vars = [tk.StringVar() for _ in range(4)]
        for i, (label, color) in enumerate(zip(['KATEGORI', 'PRODUK', 'TOTAL UNIT', 'NILAI STOK'], ['#087f8c', '#396ab1', '#b77923', '#087f8c'])):
            cards.columnconfigure(i, weight=1, uniform='cards')
            card = tk.Frame(cards, bg='white', highlightbackground='#dce6ed', highlightthickness=1)
            card.grid(row=0, column=i, sticky='nsew', padx=(0 if i == 0 else 6, 0 if i == 3 else 6))
            tk.Frame(card, bg=color, height=3).pack(fill='x')
            tk.Label(card, text=label, bg='white', fg='#697f90', font=('Segoe UI', 9, 'bold')).pack(anchor='w', padx=16, pady=(12, 3))
            tk.Label(card, textvariable=self.stat_vars[i], bg='white', fg=color, font=('Segoe UI', 19, 'bold')).pack(anchor='w', padx=16, pady=(0, 13))
        book = ttk.Notebook(self)
        book.pack(fill='both', expand=True, padx=18, pady=15)
        self.category_tab = ttk.Frame(book, padding=14)
        self.product_tab = ttk.Frame(book, padding=14)
        book.add(self.product_tab, text=' Produk ')
        book.add(self.category_tab, text=' Kategori ')
        self.build_categories()
        self.build_products()
        self.refresh()

    def table(self, parent, columns):
        frame = ttk.Frame(parent)
        frame.pack(fill='both', expand=True, pady=12)
        tree = ttk.Treeview(frame, columns=columns, show='headings', selectmode='browse')
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=130, minwidth=50)
        bar = ttk.Scrollbar(frame, command=tree.yview)
        tree.configure(yscrollcommand=bar.set)
        bar.pack(side='right', fill='y')
        tree.pack(fill='both', expand=True)
        tree.tag_configure('even', background='#f0f6f9')
        tree.tag_configure('odd', background='#ffffff')
        return tree

    def build_categories(self):
        self.cat_id = None
        self.cat_name = tk.StringVar()
        ttk.Label(self.category_tab, text='Nama kategori').pack(anchor='w')
        ttk.Entry(self.category_tab, textvariable=self.cat_name, width=45).pack(anchor='w', pady=6)
        actions = ttk.Frame(self.category_tab)
        actions.pack(anchor='w')
        for text, fn in [('Tambah', lambda: self.save_category(False)),
                         ('Ubah terpilih', lambda: self.save_category(True)),
                         ('Hapus terpilih', self.delete_category), ('Bersihkan', self.reset_category)]:
            ttk.Button(actions, text=text, style='Primary.TButton' if text == 'Tambah' else 'Danger.TButton' if text.startswith('Hapus') else 'TButton', command=fn).pack(side='left', padx=3)
        self.cat_tree = self.table(self.category_tab, ('ID', 'Nama kategori'))
        self.cat_tree.bind('<<TreeviewSelect>>', self.select_category)

    def select_category(self, event=None):
        sel = self.cat_tree.selection()
        if sel:
            self.cat_id = int(sel[0])
            self.cat_name.set(self.cat_tree.item(sel[0], 'values')[1])

    def reset_category(self):
        self.cat_id = None
        self.cat_name.set('')
        self.cat_tree.selection_remove(*self.cat_tree.selection())

    def save_category(self, update):
        name = self.cat_name.get().strip()
        if not name:
            return messagebox.showerror('Validasi', 'Nama kategori wajib diisi.')
        if update and self.cat_id is None:
            return messagebox.showwarning('Pilih data', 'Pilih kategori pada tabel dahulu.')
        try:
            if update:
                self.db.write('UPDATE kategori SET nama=? WHERE id=?', (name, self.cat_id))
            else:
                self.db.write('INSERT INTO kategori(nama) VALUES(?)', (name,))
            self.reset_category()
            self.refresh()
        except sqlite3.IntegrityError:
            messagebox.showerror('Gagal', 'Nama kategori sudah digunakan.')

    def delete_category(self):
        if self.cat_id is None:
            return messagebox.showwarning('Pilih data', 'Pilih kategori dahulu.')
        if messagebox.askyesno('Konfirmasi', 'Hapus kategori terpilih?'):
            try:
                self.db.write('DELETE FROM kategori WHERE id=?', (self.cat_id,))
                self.reset_category()
                self.refresh()
            except sqlite3.IntegrityError:
                messagebox.showerror('Kategori digunakan', 'Hapus atau pindahkan produk dalam kategori ini terlebih dahulu.')

    def build_products(self):
        self.product_id = None
        self.fields = {key: tk.StringVar() for key in ('Nama', 'Kategori', 'Harga (Rp)', 'Stok')}
        form = ttk.Frame(self.product_tab)
        form.pack(fill='x')
        for col, (label, variable) in enumerate(self.fields.items()):
            ttk.Label(form, text=label).grid(row=0, column=col, sticky='w', padx=4)
            if label == 'Kategori':
                widget = self.category_combo = ttk.Combobox(form, textvariable=variable, state='readonly', width=23)
            else:
                widget = ttk.Entry(form, textvariable=variable, width=23)
            widget.grid(row=1, column=col, sticky='ew', padx=4, pady=8)
            form.columnconfigure(col, weight=1)
        actions = ttk.Frame(self.product_tab)
        actions.pack(fill='x')
        for label, fn in [('Tambah', lambda: self.save_product(False)),
                          ('Ubah terpilih', lambda: self.save_product(True)),
                          ('Hapus terpilih', self.delete_product), ('Bersihkan', self.reset_product)]:
            ttk.Button(actions, text=label, style='Primary.TButton' if label == 'Tambah' else 'Danger.TButton' if label.startswith('Hapus') else 'TButton', command=fn).pack(side='left', padx=3)
        self.search = tk.StringVar()
        ttk.Label(self.product_tab, text='Cari nama produk / kategori (kosongkan untuk semua)').pack(anchor='w', pady=(14, 4))
        entry = ttk.Entry(self.product_tab, textvariable=self.search)
        entry.pack(fill='x')
        self.search.trace_add('write', lambda *_: self.refresh_products())
        self.prod_tree = self.table(self.product_tab, ('ID', 'Nama', 'Kategori', 'Harga (Rp)', 'Stok', 'Nilai Stok (Rp)'))
        self.prod_tree.bind('<<TreeviewSelect>>', self.select_product)
        ttk.Label(self.product_tab, text='Harga dan stok berupa bilangan bulat tanpa titik/koma. Pilih baris sebelum mengubah atau menghapus.').pack(anchor='w')

    def select_product(self, event=None):
        sel = self.prod_tree.selection()
        if sel:
            self.product_id = int(sel[0])
            row = self.db.rows('SELECT nama,kategori_id,harga,stok FROM produk WHERE id=?', (self.product_id,))[0]
            self.fields['Nama'].set(row[0])
            self.fields['Kategori'].set(next((label for label, cid in self.category_map.items() if cid == row[1]), ''))
            self.fields['Harga (Rp)'].set(row[2])
            self.fields['Stok'].set(row[3])

    def reset_product(self):
        self.product_id = None
        for var in self.fields.values():
            var.set('')
        self.prod_tree.selection_remove(*self.prod_tree.selection())

    def save_product(self, update):
        if update and self.product_id is None:
            return messagebox.showwarning('Pilih data', 'Pilih produk pada tabel dahulu.')
        try:
            name = self.fields['Nama'].get().strip()
            category = self.category_map.get(self.fields['Kategori'].get())
            if not name or category is None:
                raise ValueError('Nama dan kategori wajib diisi. Tambahkan kategori dahulu jika belum ada.')
            try:
                price = int(self.fields['Harga (Rp)'].get())
                stock = int(self.fields['Stok'].get())
            except ValueError:
                raise ValueError('Harga dan stok harus berupa bilangan bulat.') from None
            if not (0 <= price <= 1000000000000 and 0 <= stock <= 1000000000):
                raise ValueError('Harga: 0–1 triliun; stok: 0–1 miliar.')
            params = (name, category, price, stock)
            if update:
                self.db.write('UPDATE produk SET nama=?,kategori_id=?,harga=?,stok=? WHERE id=?', params + (self.product_id,))
            else:
                self.db.write('INSERT INTO produk(nama,kategori_id,harga,stok) VALUES(?,?,?,?)', params)
            self.reset_product()
            self.refresh()
        except (ValueError, sqlite3.Error) as exc:
            messagebox.showerror('Gagal menyimpan', str(exc))

    def delete_product(self):
        if self.product_id is None:
            return messagebox.showwarning('Pilih data', 'Pilih produk dahulu.')
        if messagebox.askyesno('Konfirmasi', 'Hapus produk terpilih?'):
            self.db.write('DELETE FROM produk WHERE id=?', (self.product_id,))
            self.reset_product()
            self.refresh()

    def refresh(self):
        categories = self.db.rows('SELECT id,nama FROM kategori ORDER BY nama')
        self.cat_tree.delete(*self.cat_tree.get_children())
        for i, row in enumerate(categories):
            self.cat_tree.insert('', 'end', iid=str(row[0]), values=row, tags=('even' if i % 2 == 0 else 'odd',))
        self.category_map = {f'{cid} - {name}': cid for cid, name in categories}
        self.category_combo['values'] = list(self.category_map)
        if self.fields['Kategori'].get() not in self.category_map:
            self.fields['Kategori'].set('')
        count, stock, value = self.db.rows('SELECT count(*),coalesce(sum(stok),0),coalesce(total(harga*stok),0) FROM produk')[0]
        for variable, number in zip(self.stat_vars, [len(categories), count, stock, f'Rp {value:,.0f}'.replace(',', '.')]):
            variable.set(number)
        self.refresh_products()

    def refresh_products(self):
        query = '%' + self.search.get().strip() + '%'
        rows = self.db.rows('''SELECT p.id,p.nama,k.nama,p.harga,p.stok,p.harga*p.stok FROM produk p
                            JOIN kategori k ON k.id=p.kategori_id
                            WHERE p.nama LIKE ? OR k.nama LIKE ? ORDER BY p.id DESC''', (query, query))
        self.prod_tree.delete(*self.prod_tree.get_children())
        self.product_id = None
        for i, row in enumerate(rows):
            self.prod_tree.insert('', 'end', iid=str(row[0]), tags=('even' if i % 2 == 0 else 'odd',), values=(row[0], row[1], row[2], f'{row[3]:,}'.replace(',', '.'), row[4], f'{row[5]:,}'.replace(',', '.')))


if __name__ == '__main__':
    database = Database(Path(__file__).resolve().with_name('stok_toko.db'))
    database.seed_demo_once()
    App(database).mainloop()
