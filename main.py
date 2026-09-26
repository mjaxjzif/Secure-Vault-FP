```python
import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import secrets
import string
import time
import webbrowser

from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from crypto import encrypt_data, decrypt_data

from recovery import (
    create_recovery_metadata,
    recover_master_password,
    get_recovery_email,
    update_recovery_metadata,
)


VAULT_FILE = "vault.json"
RECOVERY_META_FILE = "recovery_meta.json"

AUTO_LOCK_TIME = 300

BACKEND_URL = "https://securevaultreal.vercel.app"

FORGOT_PASSWORD_URL = (
    "https://securevaultreal.vercel.app/forgot-password.html"
)


# ============================================================
# SECUREVAULT
# ============================================================

class SecureVault:

    def __init__(self, root):

        self.root = root

        self.root.title("SecureVault")
        self.root.geometry("1180x720")
        self.root.minsize(950, 620)

        self.root.configure(
            bg="#070b14"
        )

        self.master_password = None

        self.vault = {
            "accounts": [],
            "email": ""
        }

        self.recovery_key = None

        self.last_activity = time.time()

        self.setup_styles()

        self.root.bind_all(
            "<Key>",
            self.reset_timer
        )

        self.root.bind_all(
            "<Button>",
            self.reset_timer
        )

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close
        )

        self.check_lock()

        self.login_screen()


    # ========================================================
    # COLORS
    # ========================================================

    BG = "#070b14"
    PANEL = "#0d1422"
    PANEL_2 = "#111a2b"
    PANEL_3 = "#172238"

    TEXT = "#f4f7fb"
    MUTED = "#8b98ad"

    CYAN = "#61dafb"
    BLUE = "#4f9cff"

    GREEN = "#63e6be"
    RED = "#ff6b81"
    YELLOW = "#ffd166"


    # ========================================================
    # STYLE
    # ========================================================

    def setup_styles(self):

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "TButton",
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            padding=10,
            background=self.PANEL_3,
            foreground=self.TEXT,
            borderwidth=0
        )

        style.map(
            "TButton",
            background=[
                (
                    "active",
                    "#20314d"
                )
            ]
        )

        style.configure(
            "Accent.TButton",
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            padding=11,
            background=self.CYAN,
            foreground="#061018",
            borderwidth=0
        )

        style.map(
            "Accent.TButton",
            background=[
                (
                    "active",
                    "#8be8ff"
                )
            ]
        )

        style.configure(
            "Danger.TButton",
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            padding=10,
            background="#321827",
            foreground="#ff9aaa",
            borderwidth=0
        )

        style.configure(
            "TEntry",
            padding=9,
            font=(
                "Segoe UI",
                11
            ),
            fieldbackground="#101a2b",
            foreground=self.TEXT,
            insertcolor=self.CYAN
        )

        style.configure(
            "Treeview",
            background=self.PANEL,
            fieldbackground=self.PANEL,
            foreground=self.TEXT,
            font=(
                "Segoe UI",
                10
            ),
            rowheight=42,
            borderwidth=0
        )

        style.configure(
            "Treeview.Heading",
            background="#141f33",
            foreground="#9fb0c8",
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            padding=10,
            borderwidth=0
        )

        style.map(
            "Treeview",
            background=[
                (
                    "selected",
                    "#183652"
                )
            ],
            foreground=[
                (
                    "selected",
                    "white"
                )
            ]
        )


    # ========================================================
    # TIMER
    # ========================================================

    def reset_timer(self, event=None):

        if self.master_password is not None:
            self.last_activity = time.time()


    def check_lock(self):

        if (
            self.master_password is not None
            and
            time.time()
            - self.last_activity
            >= AUTO_LOCK_TIME
        ):

            self.lock()

        self.root.after(
            5000,
            self.check_lock
        )


    # ========================================================
    # HELPERS
    # ========================================================

    def clear(self):

        for widget in self.root.winfo_children():
            widget.destroy()


    def password_toggle(
        self,
        entry,
        button
    ):

        if entry.cget("show") == "":

            entry.config(
                show="•"
            )

            button.config(
                text="Show"
            )

        else:

            entry.config(
                show=""
            )

            button.config(
                text="Hide"
            )


    # ========================================================
    # LOGIN
    # ========================================================

    def login_screen(self):

        self.clear()

        self.root.configure(
            bg=self.BG
        )

        outer = tk.Frame(
            self.root,
            bg=self.BG
        )

        outer.pack(
            fill="both",
            expand=True
        )

        # ----------------------------------------------------
        # LEFT BRANDING
        # ----------------------------------------------------

        left = tk.Frame(
            outer,
            bg=self.BG
        )

        left.pack(
            side="left",
            fill="both",
            expand=True
        )

        brand_box = tk.Frame(
            left,
            bg=self.BG
        )

        brand_box.place(
            relx=0.5,
            rely=0.5,
            anchor="center"
        )

        tk.Label(
            brand_box,
            text="🔐",
            bg=self.BG,
            fg=self.CYAN,
            font=(
                "Segoe UI Emoji",
                60
            )
        ).pack(
            pady=(0, 15)
        )

        tk.Label(
            brand_box,
            text="SecureVault",
            bg=self.BG,
            fg=self.TEXT,
            font=(
                "Segoe UI",
                38,
                "bold"
            )
        ).pack()

        tk.Label(
            brand_box,
            text="Your passwords. Your control.",
            bg=self.BG,
            fg=self.MUTED,
            font=(
                "Segoe UI",
                12
            )
        ).pack(
            pady=(8, 25)
        )

        feature_text = [
            "🔒  Encrypted local vault",
            "🎲  Strong password generator",
            "⏱  Automatic locking",
            "🔑  Account recovery"
        ]

        for text in feature_text:

            tk.Label(
                brand_box,
                text=text,
                bg=self.BG,
                fg="#aab6c8",
                font=(
                    "Segoe UI",
                    10
                )
            ).pack(
                anchor="w",
                pady=4
            )


        # ----------------------------------------------------
        # RIGHT LOGIN PANEL
        # ----------------------------------------------------

        right = tk.Frame(
            outer,
            bg=self.PANEL
        )

        right.pack(
            side="right",
            fill="both",
            expand=True
        )

        card = tk.Frame(
            right,
            bg=self.PANEL
        )

        card.place(
            relx=0.5,
            rely=0.5,
            anchor="center"
        )

        existing_vault = os.path.exists(
            VAULT_FILE
        )

        tk.Label(
            card,
            text=(
                "Welcome back"
                if existing_vault
                else
                "Create your vault"
            ),
            bg=self.PANEL,
            fg=self.TEXT,
            font=(
                "Segoe UI",
                25,
                "bold"
            )
        ).pack(
            anchor="w"
        )

        tk.Label(
            card,
            text=(
                "Unlock your encrypted password vault."
                if existing_vault
                else
                "Choose a strong master password."
            ),
            bg=self.PANEL,
            fg=self.MUTED,
            font=(
                "Segoe UI",
                10
            )
        ).pack(
            anchor="w",
            pady=(6, 25)
        )

        tk.Label(
            card,
            text="MASTER PASSWORD",
            bg=self.PANEL,
            fg="#8ea0b9",
            font=(
                "Segoe UI",
                9,
                "bold"
            )
        ).pack(
            anchor="w"
        )

        row = tk.Frame(
            card,
            bg=self.PANEL
        )

        row.pack(
            fill="x",
            pady=(8, 12)
        )

        self.password_entry = ttk.Entry(
            row,
            show="•",
            width=35
        )

        self.password_entry.pack(
            side="left",
            fill="x",
            expand=True
        )

        show = tk.Button(
            row,
            text="Show",
            command=lambda:
                self.password_toggle(
                    self.password_entry,
                    show
                ),
            bg=self.PANEL_2,
            fg=self.CYAN,
            activebackground=self.PANEL_2,
            activeforeground="white",
            bd=0,
            padx=12,
            cursor="hand2"
        )

        show.pack(
            side="right",
            padx=(8, 0)
        )

        if existing_vault:

            ttk.Button(
                card,
                text="🔓  Unlock Vault",
                style="Accent.TButton",
                command=self.unlock
            ).pack(
                fill="x"
            )

            tk.Button(
                card,
                text="Forgot Password?",
                command=self.forgot_password,
                bg=self.PANEL,
                fg=self.CYAN,
                activebackground=self.PANEL,
                activeforeground="white",
                bd=0,
                cursor="hand2",
                font=(
                    "Segoe UI",
                    10,
                    "underline"
                )
            ).pack(
                pady=(16, 6)
            )

            tk.Label(
                card,
                text="Auto-lock after 5 minutes of inactivity",
                bg=self.PANEL,
                fg="#617087",
                font=(
                    "Segoe UI",
                    9
                )
            ).pack()

        else:

            ttk.Button(
                card,
                text="🔐  Create SecureVault",
                style="Accent.TButton",
                command=self.create_vault
            ).pack(
                fill="x"
            )

            tk.Label(
                card,
                text="Use at least 10 characters.",
                bg=self.PANEL,
                fg="#617087",
                font=(
                    "Segoe UI",
                    9
                )
            ).pack(
                pady=(12, 0)
            )

        self.password_entry.focus()


    # ========================================================
    # CREATE VAULT
    # ========================================================

    def create_vault(self):

        password = self.password_entry.get()

        if len(password) < 10:

            messagebox.showwarning(
                "Password Too Short",
                "Use at least 10 characters."
            )

            return

        confirm = self.confirm_password()

        if confirm != password:

            messagebox.showerror(
                "Passwords Do Not Match",
                "The passwords do not match."
            )

            return

        recovery_email = (
            self.ask_recovery_email()
        )

        if not recovery_email:
            return

        self.master_password = password

        self.recovery_key = (
            self.generate_recovery_key()
        )

        self.vault = {
            "accounts": [],
            "email": recovery_email,
            "recovery_key": self.recovery_key
        }

        self.last_activity = time.time()

        self.save()

        create_recovery_metadata(
            recovery_email,
            self.master_password,
            self.recovery_key
        )

        self.recovery_screen()


    def confirm_password(self):

        window = tk.Toplevel(
            self.root
        )

        window.title(
            "Confirm Master Password"
        )

        window.geometry(
            "430x250"
        )

        window.configure(
            bg=self.PANEL
        )

        window.transient(
            self.root
        )

        window.grab_set()

        result = [None]

        tk.Label(
            window,
            text="Confirm Password",
            bg=self.PANEL,
            fg=self.TEXT,
            font=(
                "Segoe UI",
                18,
                "bold"
            )
        ).pack(
            pady=(28, 18)
        )

        entry = ttk.Entry(
            window,
            show="•"
        )

        entry.pack(
            padx=35,
            fill="x"
        )

        def done():

            result[0] = entry.get()

            window.destroy()

        ttk.Button(
            window,
            text="Confirm",
            style="Accent.TButton",
            command=done
        ).pack(
            fill="x",
            padx=35,
            pady=22
        )

        entry.focus()

        self.root.wait_window(
            window
        )

        return result[0]


    # ========================================================
    # RECOVERY EMAIL
    # ========================================================

    def ask_recovery_email(self):

        window = tk.Toplevel(
            self.root
        )

        window.title(
            "Recovery Email"
        )

        window.geometry(
            "500x290"
        )

        window.configure(
            bg=self.PANEL
        )

        window.transient(
            self.root
        )

        window.grab_set()

        result = [None]

        tk.Label(
            window,
            text="Recovery Email",
            bg=self.PANEL,
            fg=self.TEXT,
            font=(
                "Segoe UI",
                20,
                "bold"
            )
        ).pack(
            pady=(28, 8)
        )

        tk.Label(
            window,
            text=(
                "Enter the email you will use for\n"
                "SecureVault account recovery."
            ),
            bg=self.PANEL,
            fg=self.MUTED,
            justify="center",
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            pady=(0, 18)
        )

        entry = ttk.Entry(
            window
        )

        entry.pack(
            fill="x",
            padx=35
        )

        def save_email():

            value = (
                entry.get()
                .strip()
                .lower()
            )

            if (
                "@" not in value
                or
                "." not in value
            ):

                messagebox.showwarning(
                    "Invalid Email",
                    "Enter a valid recovery email.",
                    parent=window
                )

                return

            result[0] = value

            window.destroy()

        ttk.Button(
            window,
            text="Continue",
            style="Accent.TButton",
            command=save_email
        ).pack(
            fill="x",
            padx=35,
            pady=22
        )

        entry.focus()

        self.root.wait_window(
            window
        )

        return result[0]


    # ========================================================
    # RECOVERY KEY
    # ========================================================

    def generate_recovery_key(self):

        chars = (
            string.ascii_uppercase
            +
            string.digits
        )

        return "-".join(
            "".join(
                secrets.choice(chars)
                for _ in range(6)
            )
            for _ in range(4)
        )


    def recovery_screen(self):

        self.clear()

        self.root.configure(
            bg=self.BG
        )

        card = tk.Frame(
            self.root,
            bg=self.PANEL
        )

        card.place(
            relx=0.5,
            rely=0.5,
            anchor="center"
        )

        tk.Label(
            card,
            text="🔑",
            bg=self.PANEL,
            fg=self.CYAN,
            font=(
                "Segoe UI Emoji",
                45
            )
        ).pack(
            pady=(28, 5)
        )

        tk.Label(
            card,
            text="Your Recovery Key",
            bg=self.PANEL,
            fg=self.TEXT,
            font=(
                "Segoe UI",
                24,
                "bold"
            )
        ).pack()

        tk.Label(
            card,
            text=(
                "Save this key somewhere safe.\n"
                "You may need it to recover your account."
            ),
            bg=self.PANEL,
            fg=self.MUTED,
            justify="center",
            font=(
                "Segoe UI",
                10
            )
        ).pack(
            pady=12
        )

        key_box = tk.Entry(
            card,
            width=34,
            justify="center",
            font=(
                "Consolas",
                14,
                "bold"
            ),
            bg=self.PANEL_2,
            fg=self.CYAN,
            readonlybackground=self.PANEL_2,
            bd=0
        )

        key_box.insert(
            0,
            self.recovery_key
        )

        key_box.config(
            state="readonly"
        )

        key_box.pack(
            padx=35,
            pady=16,
            ipady=9
        )

        def copy():

            self.root.clipboard_clear()

            self.root.clipboard_append(
                self.recovery_key
            )

            self.root.update()

            messagebox.showinfo(
                "Copied",
                "Recovery key copied.\n"
                "Clipboard will be cleared in 15 seconds."
            )

            self.root.after(
                15000,
                self.clear_clipboard
            )

        ttk.Button(
            card,
            text="📋  Copy Recovery Key",
            command=copy
        ).pack(
            fill="x",
            padx=35,
            pady=5
        )

        ttk.Button(
            card,
            text="Continue to SecureVault  →",
            style="Accent.TButton",
            command=self.dashboard
        ).pack(
            fill="x",
            padx=35,
            pady=(5, 28)
        )


    # ========================================================
    # ENCRYPTION
    # ========================================================

    def save(self):

        encrypted = encrypt_data(
            self.vault,
            self.master_password
        )

        temporary = (
            VAULT_FILE
            +
            ".tmp"
        )

        with open(
            temporary,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                encrypted,
                file
            )

        os.replace(
            temporary,
            VAULT_FILE
        )


    def unlock(self):

        password = self.password_entry.get()

        if not password:
            return

        try:

            with open(
                VAULT_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                encrypted = json.load(file)

            vault_data = decrypt_data(
                encrypted,
                password
            )

            self.vault = vault_data

            # ------------------------------------------------
            # RECOVERY MIGRATION FOR OLDER VAULTS
            # ------------------------------------------------

            if not os.path.exists(
                RECOVERY_META_FILE
            ):

                recovery_key = str(
                    self.vault.get(
                        "recovery_key",
                        ""
                    )
                ).strip()

                if recovery_key:

                    recovery_email = str(
                        self.vault.get(
                            "email",
                            ""
                        )
                    ).strip().lower()

                    if not recovery_email:

                        recovery_email = (
                            self.ask_recovery_email()
                        )

                        if not recovery_email:
                            return

                        self.vault[
                            "email"
                        ] = recovery_email

                        self.save()

                    create_recovery_metadata(
                        recovery_email,
                        password,
                        recovery_key
                    )

            self.master_password = password

            self.last_activity = time.time()

            self.dashboard()

        except Exception:

            messagebox.showerror(
                "Access Denied",
                "Incorrect master password."
            )

            self.password_entry.delete(
                0,
                tk.END
            )


    # ========================================================
    # DASHBOARD
    # ========================================================

    def dashboard(self):

        self.clear()

        self.root.configure(
            bg=self.BG
        )

        # ----------------------------------------------------
        # SIDEBAR
        # ----------------------------------------------------

        sidebar = tk.Frame(
            self.root,
            bg=self.PANEL,
            width=230
        )

        sidebar.pack(
            side="left",
            fill="y"
        )

        sidebar.pack_propagate(
            False
        )

        tk.Label(
            sidebar,
            text="🔐",
            bg=self.PANEL,
            fg=self.CYAN,
            font=(
                "Segoe UI Emoji",
                32
            )
        ).pack(
            pady=(28, 5)
        )

        tk.Label(
            sidebar,
            text="SecureVault",
            bg=self.PANEL,
            fg=self.TEXT,
            font=(
                "Segoe UI",
                16,
                "bold"
            )
        ).pack()

        tk.Label(
            sidebar,
            text="PASSWORD MANAGER",
            bg=self.PANEL,
            fg="#64728a",
            font=(
                "Segoe UI",
                8,
                "bold"
            )
        ).pack(
            pady=(2, 35)
        )

        self.sidebar_button(
            sidebar,
            "▣   My Vault",
            self.dashboard,
            active=True
        )

        self.sidebar_button(
            sidebar,
            "＋   Add Account",
            self.account_window
        )

        self.sidebar_button(
            sidebar,
            "⚙   Password Generator",
            self.password_generator
        )

        spacer = tk.Frame(
            sidebar,
            bg=self.PANEL
        )

        spacer.pack(
            fill="both",
            expand=True
        )

        lock_btn = tk.Button(
            sidebar,
            text="🔒   Lock Vault",
            command=self.lock,
            bg="#1a2538",
            fg="#aab9cc",
            activebackground="#253650",
            activeforeground="white",
            bd=0,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            pady=12
        )

        lock_btn.pack(
            fill="x",
            padx=18,
            pady=(10, 6)
        )

        tk.Label(
            sidebar,
            text="Protected by encryption",
            bg=self.PANEL,
            fg="#57657b",
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            pady=(3, 20)
        )


        # ----------------------------------------------------
        # MAIN
        # ----------------------------------------------------

        main = tk.Frame(
            self.root,
            bg=self.BG
        )

        main.pack(
            side="right",
            fill="both",
            expand=True
        )


        # ----------------------------------------------------
        # HEADER
        # ----------------------------------------------------

        header = tk.Frame(
            main,
            bg=self.BG
        )

        header.pack(
            fill="x",
            padx=30,
            pady=(25, 5)
        )

        tk.Label(
            header,
            text="My Vault",
            bg=self.BG,
            fg=self.TEXT,
            font=(
                "Segoe UI",
                26,
                "bold"
            )
        ).pack(
            side="left"
        )

        tk.Label(
            header,
            text="Secure credential storage",
            bg=self.BG,
            fg=self.MUTED,
            font=(
                "Segoe UI",
                10
            )
        ).pack(
            side="left",
            padx=14,
            pady=(10, 0)
        )

        ttk.Button(
            header,
            text="＋ Add Account",
            style="Accent.TButton",
            command=self.account_window
        ).pack(
            side="right"
        )


        # ----------------------------------------------------
        # STATS
        # ----------------------------------------------------

        stats = tk.Frame(
            main,
            bg=self.BG
        )

        stats.pack(
            fill="x",
            padx=30,
            pady=20
        )

        accounts = len(
            self.vault.get(
                "accounts",
                []
            )
        )

        stats_data = [
            (
                "🔐",
                "Saved Accounts",
                str(accounts)
            ),
            (
                "🛡",
                "Vault Status",
                "Protected"
            ),
            (
                "⏱",
                "Auto Lock",
                "5 minutes"
            )
        ]

        for icon, title, value in stats_data:

            card = tk.Frame(
                stats,
                bg=self.PANEL,
                height=88
            )

            card.pack(
                side="left",
                fill="x",
                expand=True,
                padx=(0, 10)
            )

            card.pack_propagate(
                False
            )

            tk.Label(
                card,
                text=icon,
                bg=self.PANEL,
                fg=self.CYAN,
                font=(
                    "Segoe UI Emoji",
                    20
                )
            ).pack(
                side="left",
                padx=(16, 11)
            )

            text = tk.Frame(
                card,
                bg=self.PANEL
            )

            text.pack(
                side="left"
            )

            tk.Label(
                text,
                text=title,
                bg=self.PANEL,
                fg="#738197",
                font=(
                    "Segoe UI",
                    8,
                    "bold"
                )
            ).pack(
                anchor="w"
            )

            tk.Label(
                text,
                text=value,
                bg=self.PANEL,
                fg=self.TEXT,
                font=(
                    "Segoe UI",
                    12,
                    "bold"
                )
            ).pack(
                anchor="w"
            )


        # ----------------------------------------------------
        # SEARCH
        # ----------------------------------------------------

        search_frame = tk.Frame(
            main,
            bg=self.BG
        )

        search_frame.pack(
            fill="x",
            padx=30,
            pady=(0, 12)
        )

        tk.Label(
            search_frame,
            text="🔎",
            bg=self.PANEL_2,
            fg=self.MUTED,
            font=(
                "Segoe UI Emoji",
                12
            )
        ).pack(
            side="left",
            ipadx=12,
            ipady=8
        )

        self.search_entry = ttk.Entry(
            search_frame
        )

        self.search_entry.pack(
            side="left",
            fill="x",
            expand=True
        )

        self.search_entry.bind(
            "<KeyRelease>",
            lambda event:
                self.refresh()
        )


        # ----------------------------------------------------
        # TABLE
        # ----------------------------------------------------

        table_frame = tk.Frame(
            main,
            bg=self.PANEL
        )

        table_frame.pack(
            fill="both",
            expand=True,
            padx=30,
            pady=(0, 15)
        )

        columns = (
            "site",
            "username"
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        self.tree.heading(
            "site",
            text="Website / App"
        )

        self.tree.heading(
            "username",
            text="Username / Email"
        )

        self.tree.column(
            "site",
            width=360,
            anchor="w"
        )

        self.tree.column(
            "username",
            width=430,
            anchor="w"
        )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.tree.yview
        )

        self.tree.configure(
            yscrollcommand=scrollbar.set
        )

        self.tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        self.tree.bind(
            "<Double-1>",
            lambda event:
                self.view_account()
        )


        # ----------------------------------------------------
        # BOTTOM CONTROLS
        # ----------------------------------------------------

        controls = tk.Frame(
            main,
            bg=self.BG
        )

        controls.pack(
            fill="x",
            padx=30,
            pady=(0, 22)
        )

        ttk.Button(
            controls,
            text="View",
            command=self.view_account
        ).pack(
            side="left",
            padx=(0, 6)
        )

        ttk.Button(
            controls,
            text="Edit",
            command=self.edit_account
        ).pack(
            side="left",
            padx=6
        )

        ttk.Button(
            controls,
            text="Delete",
            style="Danger.TButton",
            command=self.delete_account
        ).pack(
            side="left",
            padx=6
        )

        tk.Label(
            controls,
            text="Double-click an account to open it",
            bg=self.BG,
            fg="#59677d",
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            side="right"
        )

        self.refresh()


    def sidebar_button(
        self,
        parent,
        text,
        command,
        active=False
    ):

        bg = (
            "#18364a"
            if active
            else self.PANEL
        )

        fg = (
            self.CYAN
            if active
            else "#8998ad"
        )

        button = tk.Button(
            parent,
            text=text,
            command=command,
            anchor="w",
            bg=bg,
            fg=fg,
            activebackground="#1b3149",
            activeforeground=self.CYAN,
            bd=0,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            padx=20,
            pady=13
        )

        button.pack(
            fill="x",
            padx=10,
            pady=3
        )


    # ========================================================
    # REFRESH
    # ========================================================

    def refresh(self):

        if not hasattr(
            self,
            "tree"
        ):
            return

        for item in self.tree.get_children():

            self.tree.delete(
                item
            )

        search = ""

        if hasattr(
            self,
            "search_entry"
        ):

            search = (
                self.search_entry
                .get()
                .lower()
                .strip()
            )

        for index, account in enumerate(
            self.vault.get(
                "accounts",
                []
            )
        ):

            website = account.get(
                "website",
                ""
            )

            username = account.get(
                "username",
                ""
            )

            if (
                search
                and
                search not in website.lower()
                and
                search not in username.lower()
            ):

                continue

            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    website,
                    username
                )
            )


    # ========================================================
    # ACCOUNT WINDOW
    # ========================================================

    def account_window(
        self,
        index=None
    ):

        editing = (
            index is not None
        )

        window = tk.Toplevel(
            self.root
        )

        window.title(
            "Edit Account"
            if editing
            else
            "Add Account"
        )

        window.geometry(
            "540x500"
        )

        window.configure(
            bg=self.PANEL
        )

        window.transient(
            self.root
        )

        window.grab_set()

        header = tk.Frame(
            window,
            bg=self.PANEL
        )

        header.pack(
            fill="x",
            padx=35,
            pady=(28, 5)
        )

        tk.Label(
            header,
            text=(
                "Edit Account"
                if editing
                else
                "Add Account"
            ),
            bg=self.PANEL,
            fg=self.TEXT,
            font=(
                "Segoe UI",
                21,
                "bold"
            )
        ).pack(
            anchor="w"
        )

        tk.Label(
            header,
            text=(
                "Update your saved credentials."
                if editing
                else
                "Save a credential inside your encrypted vault."
            ),
            bg=self.PANEL,
            fg=self.MUTED,
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            anchor="w",
            pady=(5, 20)
        )

        frame = tk.Frame(
            window,
            bg=self.PANEL
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=35
        )

        def label(text):

            tk.Label(
                frame,
                text=text,
                bg=self.PANEL,
                fg="#91a0b5",
                font=(
                    "Segoe UI",
                    9,
                    "bold"
                )
            ).pack(
                anchor="w",
                pady=(8, 6)
            )

        label(
            "WEBSITE / APP"
        )

        website = ttk.Entry(
            frame
        )

        website.pack(
            fill="x"
        )

        label(
            "USERNAME / EMAIL"
        )

        username = ttk.Entry(
            frame
        )

        username.pack(
            fill="x"
        )

        label(
            "PASSWORD"
        )

        password_row = tk.Frame(
            frame,
            bg=self.PANEL
        )

        password_row.pack(
            fill="x"
        )

        password = ttk.Entry(
            password_row,
            show="•"
        )

        password.pack(
            side="left",
            fill="x",
            expand=True
        )

        show = tk.Button(
            password_row,
            text="Show",
            command=lambda:
                self.password_toggle(
                    password,
                    show
                ),
            bg=self.PANEL_2,
            fg=self.CYAN,
            activebackground=self.PANEL_2,
            activeforeground="white",
            bd=0,
            padx=12
        )

        show.pack(
            side="right",
            padx=(7, 0)
        )

        def generate():

            password.delete(
                0,
                tk.END
            )

            password.insert(
                0,
                self.generate_strong_password()
            )

        ttk.Button(
            frame,
            text="🎲 Generate Strong Password",
            command=generate
        ).pack(
            fill="x",
            pady=16
        )

        if editing:

            account = (
                self.vault[
                    "accounts"
                ][index]
            )

            website.insert(
                0,
                account.get(
                    "website",
                    ""
                )
            )

            username.insert(
                0,
                account.get(
                    "username",
                    ""
                )
            )

            password.insert(
                0,
                account.get(
                    "password",
                    ""
                )
            )

        def save_account():

            site = (
                website
                .get()
                .strip()
            )

            user = (
                username
                .get()
                .strip()
            )

            pwd = password.get()

            if (
                not site
                or
                not user
                or
                not pwd
            ):

                messagebox.showwarning(
                    "Missing Information",
                    "Fill in all three fields.",
                    parent=window
                )

                return

            data = {
                "website": site,
                "username": user,
                "password": pwd
            }

            if editing:

                self.vault[
                    "accounts"
                ][index] = data

            else:

                self.vault[
                    "accounts"
                ].append(data)

            self.save()

            self.refresh()

            window.destroy()

        ttk.Button(
            frame,
            text="💾 Save Securely",
            style="Accent.TButton",
            command=save_account
        ).pack(
            fill="x",
            pady=(5, 25)
        )


    # ========================================================
    # VIEW ACCOUNT
    # ========================================================

    def view_account(self):

        selection = self.tree.selection()

        if not selection:

            messagebox.showinfo(
                "Select Account",
                "Select an account first."
            )

            return

        index = int(
            selection[0]
        )

        account = (
            self.vault[
                "accounts"
            ][index]
        )

        window = tk.Toplevel(
            self.root
        )

        window.title(
            "Credential"
        )

        window.geometry(
            "500x430"
        )

        window.configure(
            bg=self.PANEL
        )

        window.transient(
            self.root
        )

        window.grab_set()

        tk.Label(
            window,
            text="🔐 Credential",
            bg=self.PANEL,
            fg=self.TEXT,
            font=(
                "Segoe UI",
                22,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=30,
            pady=(28, 20)
        )

        content = tk.Frame(
            window,
            bg=self.PANEL
        )

        content.pack(
            fill="both",
            expand=True,
            padx=30
        )

        self.detail_label(
            content,
            "WEBSITE / APP",
            account.get(
                "website",
                ""
            )
        )

        self.detail_label(
            content,
            "USERNAME / EMAIL",
            account.get(
                "username",
                ""
            )
        )

        tk.Label(
            content,
            text="PASSWORD",
            bg=self.PANEL,
            fg="#91a0b5",
            font=(
                "Segoe UI",
                9,
                "bold"
            )
        ).pack(
            anchor="w",
            pady=(10, 6)
        )

        password_text = tk.StringVar(
            value=(
                "•"
                *
                len(
                    account.get(
                        "password",
                        ""
                    )
                )
            )
        )

        tk.Label(
            content,
            textvariable=password_text,
            bg=self.PANEL_2,
            fg=self.TEXT,
            font=(
                "Consolas",
                12
            ),
            anchor="w",
            padx=12,
            pady=10
        ).pack(
            fill="x"
        )

        visible = [False]

        def toggle():

            visible[0] = not visible[0]

            if visible[0]:

                password_text.set(
                    account["password"]
                )

                toggle_btn.config(
                    text="Hide Password"
                )

            else:

                password_text.set(
                    "•"
                    *
                    len(
                        account["password"]
                    )
                )

                toggle_btn.config(
                    text="Show Password"
                )

        toggle_btn = ttk.Button(
            content,
            text="Show Password",
            command=toggle
        )

        toggle_btn.pack(
            fill="x",
            pady=(15, 6)
        )

        def copy():

            self.root.clipboard_clear()

            self.root.clipboard_append(
                account["password"]
            )

            self.root.update()

            messagebox.showinfo(
                "Copied",
                "Password copied to clipboard.\n"
                "Clipboard clears in 15 seconds.",
                parent=window
            )

            self.root.after(
                15000,
                self.clear_clipboard
            )

        ttk.Button(
            content,
            text="📋 Copy Password",
            style="Accent.TButton",
            command=copy
        ).pack(
            fill="x"
        )


    def detail_label(
        self,
        parent,
        title,
        value
    ):

        tk.Label(
            parent,
            text=title,
            bg=self.PANEL,
            fg="#91a0b5",
            font=(
                "Segoe UI",
                9,
                "bold"
            )
        ).pack(
            anchor="w",
            pady=(0, 5)
        )

        tk.Label(
            parent,
            text=value,
            bg=self.PANEL_2,
            fg=self.TEXT,
            font=(
                "Segoe UI",
                11
            ),
            anchor="w",
            padx=12,
            pady=10
        ).pack(
            fill="x",
            pady=(0, 12)
        )


    # ========================================================
    # EDIT
    # ========================================================

    def edit_account(self):

        selection = self.tree.selection()

        if not selection:
            return

        self.account_window(
            int(selection[0])
        )


    # ========================================================
    # DELETE
    # ========================================================

    def delete_account(self):

        selection = self.tree.selection()

        if not selection:
            return

        index = int(
            selection[0]
        )

        account = (
            self.vault[
                "accounts"
            ][index]
        )

        confirmed = messagebox.askyesno(
            "Delete Account",
            (
                "Delete the saved account for\n\n"
                +
                account.get(
                    "website",
                    ""
                )
                +
                "?"
            )
        )

        if not confirmed:
            return

        del self.vault[
            "accounts"
        ][index]

        self.save()

        self.refresh()


    # ========================================================
    # PASSWORD GENERATOR
    # ========================================================

    def generate_strong_password(self):

        characters = (
            string.ascii_letters
            +
            string.digits
            +
            "!@#$%^&*()-_=+"
        )

        while True:

            password = "".join(
                secrets.choice(
                    characters
                )
                for _ in range(24)
            )

            if (
                any(
                    c.islower()
                    for c in password
                )
                and
                any(
                    c.isupper()
                    for c in password
                )
                and
                any(
                    c.isdigit()
                    for c in password
                )
                and
                any(
                    c in "!@#$%^&*()-_=+"
                    for c in password
                )
            ):

                return password


    def password_generator(self):

        window = tk.Toplevel(
            self.root
        )

        window.title(
            "Password Generator"
        )

        window.geometry(
            "560x360"
        )

        window.configure(
            bg=self.PANEL
        )

        window.transient(
            self.root
        )

        window.grab_set()

        tk.Label(
            window,
            text="🎲 Password Generator",
            bg=self.PANEL,
            fg=self.TEXT,
            font=(
                "Segoe UI",
                22,
                "bold"
            )
        ).pack(
            pady=(30, 8)
        )

        tk.Label(
            window,
            text="Generate a strong 24-character password.",
            bg=self.PANEL,
            fg=self.MUTED,
            font=(
                "Segoe UI",
                10
            )
        ).pack()

        password_var = tk.StringVar(
            value=self.generate_strong_password()
        )

        entry = tk.Entry(
            window,
            textvariable=password_var,
            justify="center",
            font=(
                "Consolas",
                12
            ),
            bg=self.PANEL_2,
            fg=self.CYAN,
            insertbackground=self.CYAN,
            bd=0
        )

        entry.pack(
            fill="x",
            padx=35,
            pady=28,
            ipady=12
        )

        def generate():

            password_var.set(
                self.generate_strong_password()
            )

        def copy():

            self.root.clipboard_clear()

            self.root.clipboard_append(
                password_var.get()
            )

            self.root.update()

            messagebox.showinfo(
                "Copied",
                "Password copied to clipboard.\n"
                "Clipboard clears in 15 seconds.",
                parent=window
            )

            self.root.after(
                15000,
                self.clear_clipboard
            )

        buttons = tk.Frame(
            window,
            bg=self.PANEL
        )

        buttons.pack(
            fill="x",
            padx=35
        )

        ttk.Button(
            buttons,
            text="🎲 Generate Again",
            command=generate
        ).pack(
            side="left",
            fill="x",
            expand=True,
            padx=(0, 6)
        )

        ttk.Button(
            buttons,
            text="📋 Copy",
            style="Accent.TButton",
            command=copy
        ).pack(
            side="left",
            fill="x",
            expand=True,
            padx=(6, 0)
        )


    # ========================================================
    # FORGOT PASSWORD
    # ========================================================

    def forgot_password(self):

        try:

            if not os.path.exists(
                RECOVERY_META_FILE
            ):

                messagebox.showwarning(
                    "Recovery Setup Required",
                    (
                        "Unlock SecureVault once with "
                        "your current master password first.\n\n"
                        "This creates the encrypted recovery "
                        "information needed for a future reset."
                    )
                )

                return

            webbrowser.open(
                FORGOT_PASSWORD_URL
            )

            self.root.after(
                800,
                self.reset_password_dialog
            )

        except Exception as error:

            messagebox.showerror(
                "Recovery Error",
                (
                    "Could not open the recovery website.\n\n"
                    +
                    str(error)
                )
            )


    # ========================================================
    # RESET PASSWORD DIALOG
    # ========================================================

    def reset_password_dialog(self):

        if not os.path.exists(
            RECOVERY_META_FILE
        ):

            messagebox.showwarning(
                "Recovery Setup Required",
                (
                    "Unlock SecureVault once with "
                    "your current master password first.\n\n"
                    "This creates the encrypted recovery "
                    "information needed for a future reset."
                )
            )

            return


        window = tk.Toplevel(
            self.root
        )

        window.title(
            "Reset Master Password"
        )

        window.geometry(
            "600x590"
        )

        window.configure(
            bg=self.PANEL
        )

        window.transient(
            self.root
        )

        window.grab_set()


        tk.Label(
            window,
            text="🔐 Reset Master Password",
            bg=self.PANEL,
            fg=self.TEXT,
            font=(
                "Segoe UI",
                22,
                "bold"
            )
        ).pack(
            pady=(25, 8)
        )


        tk.Label(
            window,
            text=(
                "Verify your email in the browser, "
                "copy the reset token, then enter it below."
            ),
            bg=self.PANEL,
            fg=self.MUTED,
            justify="center",
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            pady=(0, 18)
        )


        def field_label(text):

            tk.Label(
                window,
                text=text,
                bg=self.PANEL,
                fg="#91a0b5",
                font=(
                    "Segoe UI",
                    9,
                    "bold"
                )
            ).pack(
                anchor="w",
                padx=35,
                pady=(8, 5)
            )


        # ----------------------------------------------------
        # TOKEN
        # ----------------------------------------------------

        field_label(
            "WEB AUTHORIZATION TOKEN"
        )

        token_entry = ttk.Entry(
            window
        )

        token_entry.pack(
            fill="x",
            padx=35
        )


        # ----------------------------------------------------
        # RECOVERY KEY
        # ----------------------------------------------------

        field_label(
            "RECOVERY KEY"
        )

        recovery_entry = ttk.Entry(
            window,
            show="•"
        )

        recovery_entry.pack(
            fill="x",
            padx=35
        )


        # ----------------------------------------------------
        # NEW PASSWORD
        # ----------------------------------------------------

        field_label(
            "NEW MASTER PASSWORD"
        )

        new_entry = ttk.Entry(
            window,
            show="•"
        )

        new_entry.pack(
            fill="x",
            padx=35
        )


        # ----------------------------------------------------
        # CONFIRM PASSWORD
        # ----------------------------------------------------

        field_label(
            "CONFIRM NEW MASTER PASSWORD"
        )

        confirm_entry = ttk.Entry(
            window,
            show="•"
        )

        confirm_entry.pack(
            fill="x",
            padx=35
        )


        # ----------------------------------------------------
        # RESET
        # ----------------------------------------------------

        def reset_now():

            token = (
                token_entry
                .get()
                .strip()
            )

            recovery_key = (
                recovery_entry
                .get()
                .strip()
            )

            new_password = (
                new_entry
                .get()
            )

            confirm_password = (
                confirm_entry
                .get()
            )


            if not token:

                messagebox.showwarning(
                    "Missing Token",
                    (
                        "Paste the authorization token "
                        "from the recovery website."
                    ),
                    parent=window
                )

                return


            if not recovery_key:

                messagebox.showwarning(
                    "Missing Recovery Key",
                    "Enter your SecureVault recovery key.",
                    parent=window
                )

                return


            if len(new_password) < 10:

                messagebox.showwarning(
                    "Password Too Short",
                    "Use at least 10 characters.",
                    parent=window
                )

                return


            if new_password != confirm_password:

                messagebox.showerror(
                    "Mismatch",
                    "The new passwords do not match.",
                    parent=window
                )

                return


            try:

                # ------------------------------------------------
                # VALIDATE ONLINE RESET TOKEN
                # ------------------------------------------------

                request = Request(
                    BACKEND_URL
                    +
                    "/validate-reset-token",

                    data=json.dumps({
                        "reset_token": token
                    }).encode("utf-8"),

                    headers={
                        "Content-Type":
                            "application/json"
                    },

                    method="POST"
                )


                with urlopen(
                    request,
                    timeout=15
                ) as response:

                    result = json.loads(
                        response
                        .read()
                        .decode("utf-8")
                    )


                if not result.get(
                    "success"
                ):

                    raise ValueError(
                        result.get(
                            "message",
                            "Invalid reset token."
                        )
                    )


                # ------------------------------------------------
                # CHECK VERIFIED EMAIL
                # ------------------------------------------------

                verified_email = str(
                    result.get(
                        "email",
                        ""
                    )
                ).strip().lower()


                local_email = (
                    get_recovery_email()
                )


                if (
                    not local_email
                    or
                    verified_email != local_email
                ):

                    raise ValueError(
                        (
                            "The verified email does not "
                            "match this SecureVault vault."
                        )
                    )


                # ------------------------------------------------
                # RECOVER OLD MASTER PASSWORD
                # ------------------------------------------------

                old_password = (
                    recover_master_password(
                        recovery_key
                    )
                )


                # ------------------------------------------------
                # READ EXISTING VAULT
                # ------------------------------------------------

                with open(
                    VAULT_FILE,
                    "r",
                    encoding="utf-8"
                ) as file:

                    encrypted = json.load(
                        file
                    )


                # ------------------------------------------------
                # DECRYPT USING OLD PASSWORD
                # ------------------------------------------------

                vault_data = decrypt_data(
                    encrypted,
                    old_password
                )


                # ------------------------------------------------
                # ENCRYPT USING NEW PASSWORD
                # ------------------------------------------------

                new_encrypted = encrypt_data(
                    vault_data,
                    new_password
                )


                temporary = (
                    VAULT_FILE
                    +
                    ".tmp"
                )


                with open(
                    temporary,
                    "w",
                    encoding="utf-8"
                ) as file:

                    json.dump(
                        new_encrypted,
                        file
                    )


                os.replace(
                    temporary,
                    VAULT_FILE
                )


                # ------------------------------------------------
                # UPDATE RECOVERY METADATA
                # ------------------------------------------------

                update_recovery_metadata(
                    local_email,
                    new_password,
                    recovery_key
                )


                # ------------------------------------------------
                # UPDATE CURRENT SESSION
                # ------------------------------------------------

                self.master_password = (
                    new_password
                )

                self.vault = (
                    vault_data
                )

                self.last_activity = (
                    time.time()
                )


                window.destroy()


                messagebox.showinfo(
                    "Password Reset",
                    (
                        "Your SecureVault master password "
                        "has been reset successfully."
                    )
                )


                self.dashboard()


            except (
                HTTPError,
                URLError
            ) as error:

                messagebox.showerror(
                    "Recovery Server Error",
                    (
                        "Could not contact the online "
                        "recovery server.\n\n"
                        +
                        str(error)
                    ),
                    parent=window
                )


            except Exception as error:

                messagebox.showerror(
                    "Reset Failed",
                    str(error),
                    parent=window
                )


        ttk.Button(
            window,
            text="🔐 Reset Master Password",
            style="Accent.TButton",
            command=reset_now
        ).pack(
            fill="x",
            padx=35,
            pady=25
        )


        tk.Label(
            window,
            text=(
                "Never share your recovery key or reset token."
            ),
            bg=self.PANEL,
            fg="#5e6d83",
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            pady=(0, 15)
        )


    # ========================================================
    # CLIPBOARD
    # ========================================================

    def clear_clipboard(self):

        try:

            self.root.clipboard_clear()

            self.root.update()

        except Exception:
            pass


    # ========================================================
    # LOCK
    # ========================================================

    def lock(self):

        self.clear_clipboard()

        self.master_password = None

        self.vault = {
            "accounts": [],
            "email": ""
        }

        self.login_screen()


    # ========================================================
    # CLOSE
    # ========================================================

    def close(self):

        self.clear_clipboard()

        self.master_password = None

        self.vault = {
            "accounts": [],
            "email": ""
        }

        self.root.destroy()


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    root = tk.Tk()

    app = SecureVault(
        root
    )

    root.mainloop()
```
