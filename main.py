import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import secrets
import string
import time
import webbrowser

from crypto import encrypt_data, decrypt_data


VAULT_FILE = "vault.json"
AUTO_LOCK_TIME = 300


class SecureVault:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureVault")
        self.root.geometry("950x650")
        self.root.minsize(800, 550)

        self.master_password = None

        self.vault = {
            "accounts": [],
            "email": ""
        }

        self.recovery_key = None
        self.last_activity = time.time()

        self.setup_style()

        self.root.bind_all("<Key>", self.reset_timer)
        self.root.bind_all("<Button>", self.reset_timer)

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close
        )

        self.check_lock()
        self.login_screen()

    # =========================
    # STYLE
    # =========================

    def setup_style(self):
        style = ttk.Style()

        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "TButton",
            font=("Segoe UI", 10, "bold"),
            padding=9
        )

        style.configure(
            "TEntry",
            padding=8,
            font=("Segoe UI", 11)
        )

        style.configure(
            "Treeview",
            font=("Segoe UI", 10),
            rowheight=36
        )

        style.configure(
            "Treeview.Heading",
            font=("Segoe UI", 10, "bold")
        )

    def reset_timer(self, event=None):
        self.last_activity = time.time()

    def check_lock(self):
        if (
            self.master_password is not None
            and time.time() - self.last_activity >= AUTO_LOCK_TIME
        ):
            self.lock()

        self.root.after(
            5000,
            self.check_lock
        )

    # =========================
    # HELPERS
    # =========================

    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def password_toggle(self, entry, button):
        if entry.cget("show") == "":
            entry.config(show="•")
            button.config(text="Show")
        else:
            entry.config(show="")
            button.config(text="Hide")

    # =========================
    # LOGIN SCREEN
    # =========================

    def login_screen(self):
        self.clear()
        self.root.configure(bg="#0b1020")

        box = tk.Frame(
            self.root,
            bg="#111a2e"
        )

        box.place(
            relx=0.5,
            rely=0.5,
            anchor="center"
        )

        tk.Label(
            box,
            text="🔐",
            font=("Segoe UI Emoji", 45),
            bg="#111a2e",
            fg="white"
        ).pack(
            pady=(30, 0)
        )

        tk.Label(
            box,
            text="SecureVault",
            font=("Segoe UI", 30, "bold"),
            bg="#111a2e",
            fg="#61dafb"
        ).pack()

        tk.Label(
            box,
            text="Secure password management",
            font=("Segoe UI", 11),
            bg="#111a2e",
            fg="#aeb8ca"
        ).pack(
            pady=(0, 25)
        )

        if os.path.exists(VAULT_FILE):
            self.existing_login(box)
        else:
            self.new_vault_login(box)

    def existing_login(self, box):
        tk.Label(
            box,
            text="Master Password",
            bg="#111a2e",
            fg="white",
            font=("Segoe UI", 11, "bold")
        ).pack(
            anchor="w",
            padx=40
        )

        row = tk.Frame(
            box,
            bg="#111a2e"
        )

        row.pack(
            fill="x",
            padx=40,
            pady=8
        )

        self.password_entry = ttk.Entry(
            row,
            show="•"
        )

        self.password_entry.pack(
            side="left",
            fill="x",
            expand=True
        )

        show = ttk.Button(
            row,
            text="Show",
            command=lambda: self.password_toggle(
                self.password_entry,
                show
            )
        )

        show.pack(
            side="right",
            padx=(6, 0)
        )

        ttk.Button(
            box,
            text="🔓 Unlock Vault",
            command=self.unlock
        ).pack(
            fill="x",
            padx=40,
            pady=8
        )

        tk.Button(
            box,
            text="Forgot Password?",
            command=self.forgot_password,
            bg="#111a2e",
            fg="#61dafb",
            activebackground="#111a2e",
            activeforeground="white",
            bd=0,
            cursor="hand2",
            font=("Segoe UI", 10, "underline")
        ).pack(
            pady=5
        )

        tk.Label(
            box,
            text="Automatically locks after 5 minutes",
            bg="#111a2e",
            fg="#68748a",
            font=("Segoe UI", 9)
        ).pack(
            pady=(5, 30)
        )

        self.password_entry.focus()

    def new_vault_login(self, box):
        tk.Label(
            box,
            text="Create a Master Password",
            bg="#111a2e",
            fg="white",
            font=("Segoe UI", 11, "bold")
        ).pack(
            anchor="w",
            padx=40
        )

        self.password_entry = ttk.Entry(
            box,
            show="•"
        )

        self.password_entry.pack(
            fill="x",
            padx=40,
            pady=10
        )

        ttk.Button(
            box,
            text="🔐 Create Vault",
            command=self.create_vault
        ).pack(
            fill="x",
            padx=40,
            pady=8
        )

        tk.Label(
            box,
            text="Use at least 10 characters.",
            bg="#111a2e",
            fg="#68748a",
            font=("Segoe UI", 9)
        ).pack(
            pady=(5, 30)
        )

    # =========================
    # CREATE VAULT
    # =========================

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
                "Mismatch",
                "The passwords do not match."
            )
            return

        self.master_password = password
        self.recovery_key = self.generate_recovery_key()

        self.vault = {
            "accounts": [],
            "email": "",
            "recovery_key": self.recovery_key
        }

        self.save()

        self.recovery_screen()

    def confirm_password(self):
        window = tk.Toplevel(self.root)
        window.title("Confirm Password")
        window.geometry("400x220")
        window.configure(bg="#111a2e")
        window.transient(self.root)
        window.grab_set()

        result = [None]

        tk.Label(
            window,
            text="Confirm Master Password",
            bg="#111a2e",
            fg="white",
            font=("Segoe UI", 15, "bold")
        ).pack(
            pady=20
        )

        entry = ttk.Entry(
            window,
            show="•"
        )

        entry.pack(
            padx=30,
            fill="x"
        )

        def done():
            result[0] = entry.get()
            window.destroy()

        ttk.Button(
            window,
            text="Confirm",
            command=done
        ).pack(
            pady=20
        )

        entry.focus()

        self.root.wait_window(window)

        return result[0]

    # =========================
    # RECOVERY KEY
    # =========================

    def generate_recovery_key(self):
        chars = string.ascii_uppercase + string.digits

        parts = []

        for _ in range(4):
            parts.append(
                "".join(
                    secrets.choice(chars)
                    for _ in range(6)
                )
            )

        return "-".join(parts)

    def recovery_screen(self):
        self.clear()
        self.root.configure(bg="#0b1020")

        box = tk.Frame(
            self.root,
            bg="#111a2e"
        )

        box.place(
            relx=0.5,
            rely=0.5,
            anchor="center"
        )

        tk.Label(
            box,
            text="🔑 Recovery Key",
            bg="#111a2e",
            fg="#61dafb",
            font=("Segoe UI", 25, "bold")
        ).pack(
            pady=(30, 10)
        )

        tk.Label(
            box,
            text=(
                "Save this key somewhere safe.\n"
                "It is required for account recovery."
            ),
            bg="#111a2e",
            fg="white",
            justify="center",
            font=("Segoe UI", 11)
        ).pack(
            pady=10
        )

        key = tk.Entry(
            box,
            width=32,
            justify="center",
            font=("Consolas", 14, "bold"),
            bg="#18243a",
            fg="#61dafb",
            readonlybackground="#18243a"
        )

        key.insert(
            0,
            self.recovery_key
        )

        key.config(
            state="readonly"
        )

        key.pack(
            padx=40,
            pady=15
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
                "The clipboard will clear in 15 seconds."
            )

            self.root.after(
                15000,
                self.clear_clipboard
            )

        ttk.Button(
            box,
            text="📋 Copy Recovery Key",
            command=copy
        ).pack(
            fill="x",
            padx=40,
            pady=5
        )

        ttk.Button(
            box,
            text="Continue to SecureVault",
            command=self.dashboard
        ).pack(
            fill="x",
            padx=40,
            pady=(5, 30)
        )

    # =========================
    # ENCRYPTION
    # =========================

    def save(self):
        encrypted = encrypt_data(
            self.vault,
            self.master_password
        )

        temporary = VAULT_FILE + ".tmp"

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

            self.vault = decrypt_data(
                encrypted,
                password
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

    # =========================
    # DASHBOARD
    # =========================

    def dashboard(self):
        self.clear()
        self.root.configure(bg="#0b1020")

        header = tk.Frame(
            self.root,
            bg="#111a2e"
        )

        header.pack(
            fill="x"
        )

        tk.Label(
            header,
            text="🔐 SecureVault",
            bg="#111a2e",
            fg="#61dafb",
            font=("Segoe UI", 23, "bold")
        ).pack(
            side="left",
            padx=25,
            pady=20
        )

        ttk.Button(
            header,
            text="🔒 Lock",
            command=self.lock
        ).pack(
            side="right",
            padx=25
        )

        search = tk.Frame(
            self.root,
            bg="#0b1020"
        )

        search.pack(
            fill="x",
            padx=25,
            pady=20
        )

        tk.Label(
            search,
            text="🔎",
            bg="#0b1020",
            fg="white",
            font=("Segoe UI", 15)
        ).pack(
            side="left"
        )

        self.search_entry = ttk.Entry(
            search
        )

        self.search_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=10
        )

        self.search_entry.bind(
            "<KeyRelease>",
            lambda event: self.refresh()
        )

        ttk.Button(
            search,
            text="＋ Add Account",
            command=self.account_window
        ).pack(
            side="right"
        )

        table = tk.Frame(
            self.root,
            bg="#0b1020"
        )

        table.pack(
            fill="both",
            expand=True,
            padx=25
        )

        self.tree = ttk.Treeview(
            table,
            columns=("site", "username"),
            show="headings"
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
            width=350
        )

        self.tree.column(
            "username",
            width=450
        )

        scrollbar = ttk.Scrollbar(
            table,
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
            lambda event: self.view_account()
        )

        bottom = tk.Frame(
            self.root,
            bg="#0b1020"
        )

        bottom.pack(
            fill="x",
            padx=25,
            pady=20
        )

        ttk.Button(
            bottom,
            text="View",
            command=self.view_account
        ).pack(
            side="left",
            padx=4
        )

        ttk.Button(
            bottom,
            text="Edit",
            command=self.edit_account
        ).pack(
            side="left",
            padx=4
        )

        ttk.Button(
            bottom,
            text="Delete",
            command=self.delete_account
        ).pack(
            side="left",
            padx=4
        )

        ttk.Button(
            bottom,
            text="🎲 Password Generator",
            command=self.password_generator
        ).pack(
            side="right",
            padx=4
        )

        self.refresh()

    # =========================
    # REFRESH
    # =========================

    def refresh(self):
        if not hasattr(self, "tree"):
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        search = self.search_entry.get().lower()

        for index, account in enumerate(
            self.vault.get("accounts", [])
        ):
            site = account.get(
                "website",
                ""
            )

            username = account.get(
                "username",
                ""
            )

            if (
                search in site.lower()
                or search in username.lower()
            ):
                self.tree.insert(
                    "",
                    "end",
                    iid=str(index),
                    values=(
                        site,
                        username
                    )
                )

    # =========================
    # ACCOUNT WINDOW
    # =========================

    def account_window(self, index=None):
        editing = index is not None

        window = tk.Toplevel(self.root)

        window.title(
            "Edit Account"
            if editing
            else "Add Account"
        )

        window.geometry("520x450")
        window.configure(bg="#111a2e")
        window.transient(self.root)
        window.grab_set()

        frame = tk.Frame(
            window,
            bg="#111a2e"
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=35,
            pady=30
        )

        def field_label(text):
            tk.Label(
                frame,
                text=text,
                bg="#111a2e",
                fg="white",
                font=("Segoe UI", 10, "bold")
            ).pack(
                anchor="w"
            )

        field_label("Website / App")

        website = ttk.Entry(frame)

        website.pack(
            fill="x",
            pady=(5, 15)
        )

        field_label("Username / Email")

        username = ttk.Entry(frame)

        username.pack(
            fill="x",
            pady=(5, 15)
        )

        field_label("Password")

        password_row = tk.Frame(
            frame,
            bg="#111a2e"
        )

        password_row.pack(
            fill="x",
            pady=(5, 15)
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

        show = ttk.Button(
            password_row,
            text="Show",
            command=lambda: self.password_toggle(
                password,
                show
            )
        )

        show.pack(
            side="right",
            padx=(6, 0)
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
            pady=(0, 20)
        )

        if editing:
            account = self.vault["accounts"][index]

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
            site = website.get().strip()
            user = username.get().strip()
            pwd = password.get()

            if not site or not user or not pwd:
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
                self.vault["accounts"][index] = data
            else:
                self.vault["accounts"].append(data)

            self.save()
            self.refresh()

            window.destroy()

        ttk.Button(
            frame,
            text="💾 Save Securely",
            command=save_account
        ).pack(
            fill="x"
        )

    # =========================
    # VIEW
    # =========================

    def view_account(self):
        selection = self.tree.selection()

        if not selection:
            messagebox.showinfo(
                "Select Account",
                "Select an account first."
            )
            return

        index = int(selection[0])

        account = self.vault["accounts"][index]

        window = tk.Toplevel(self.root)

        window.title(
            "Credential"
        )

        window.geometry(
            "450x350"
        )

        window.configure(
            bg="#111a2e"
        )

        window.transient(
            self.root
        )

        window.grab_set()

        frame = tk.Frame(
            window,
            bg="#111a2e"
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=30,
            pady=25
        )

        for title, value in [
            (
                "Website / App",
                account["website"]
            ),
            (
                "Username / Email",
                account["username"]
            )
        ]:
            tk.Label(
                frame,
                text=title,
                bg="#111a2e",
                fg="#61dafb",
                font=("Segoe UI", 9, "bold")
            ).pack(
                anchor="w"
            )

            tk.Label(
                frame,
                text=value,
                bg="#111a2e",
                fg="white",
                font=("Segoe UI", 12)
            ).pack(
                anchor="w",
                pady=(2, 15)
            )

        tk.Label(
            frame,
            text="Password",
            bg="#111a2e",
            fg="#61dafb",
            font=("Segoe UI", 9, "bold")
        ).pack(
            anchor="w"
        )

        password_text = tk.StringVar(
            value="•" * len(
                account["password"]
            )
        )

        tk.Label(
            frame,
            textvariable=password_text,
            bg="#111a2e",
            fg="white",
            font=("Consolas", 12)
        ).pack(
            anchor="w",
            pady=(2, 15)
        )

        visible = [False]

        def toggle():
            visible[0] = not visible[0]

            if visible[0]:
                password_text.set(
                    account["password"]
                )

                toggle_button.config(
                    text="Hide Password"
                )

            else:
                password_text.set(
                    "•" * len(
                        account["password"]
                    )
                )

                toggle_button.config(
                    text="Show Password"
                )

        toggle_button = ttk.Button(
            frame,
            text="Show Password",
            command=toggle
        )

        toggle_button.pack(
            fill="x",
            pady=4
        )

        def copy():
            self.root.clipboard_clear()

            self.root.clipboard_append(
                account["password"]
            )

            self.root.update()

            messagebox.showinfo(
                "Copied",
                "Password copied.\n"
                "Clipboard clears in 15 seconds.",
                parent=window
            )

            self.root.after(
                15000,
                self.clear_clipboard
            )

        ttk.Button(
            frame,
            text="📋 Copy Password",
            command=copy
        ).pack(
            fill="x",
            pady=4
        )

    # =========================
    # EDIT
    # =========================

    def edit_account(self):
        selection = self.tree.selection()

        if not selection:
            return

        self.account_window(
            int(selection[0])
        )

    # =========================
    # DELETE
    # =========================

    def delete_account(self):
        selection = self.tree.selection()

        if not selection:
            return

        index = int(selection[0])

        account = self.vault["accounts"][index]

        if messagebox.askyesno(
            "Delete Account",
            "Delete "
            + account["website"]
            + "?"
        ):
            del self.vault["accounts"][index]

            self.save()
            self.refresh()

    # =========================
    # PASSWORD GENERATOR
    # =========================

    def generate_strong_password(self):
        characters = (
            string.ascii_letters
            + string.digits
            + "!@#$%^&*()-_=+"
        )

        while True:
            password = "".join(
                secrets.choice(characters)
                for _ in range(24)
            )

            if (
                any(
                    c.islower()
                    for c in password
                )
                and any(
                    c.isupper()
                    for c in password
                )
                and any(
                    c.isdigit()
                    for c in password
                )
                and any(
                    c in "!@#$%^&*()-_=+"
                    for c in password
                )
            ):
                return password

    def password_generator(self):
        password = self.generate_strong_password()

        self.root.clipboard_clear()

        self.root.clipboard_append(
            password
        )

        self.root.update()

        messagebox.showinfo(
            "Password Generated",
            "Strong password copied to clipboard.\n\n"
            "Clipboard clears in 15 seconds."
        )

        self.root.after(
            15000,
            self.clear_clipboard
        )

    # =========================
    # FORGOT PASSWORD
    # =========================

    def forgot_password(self):
        webbrowser.open(
            "https://securevaultreal.vercel.app/forgot-password.html"
        )

    # =========================
    # CLIPBOARD
    # =========================

    def clear_clipboard(self):
        try:
            self.root.clipboard_clear()
            self.root.update()
        except Exception:
            pass

    # =========================
    # LOCK
    # =========================

    def lock(self):
        self.clear_clipboard()

        self.master_password = None

        self.vault = {
            "accounts": [],
            "email": ""
        }

        self.login_screen()

    # =========================
    # CLOSE
    # =========================

    def close(self):
        self.clear_clipboard()

        self.master_password = None

        self.vault = {
            "accounts": [],
            "email": ""
        }

        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()

    app = SecureVault(root)

    root.mainloop()