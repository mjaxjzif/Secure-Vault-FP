import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import secrets
import string
import time
import webbrowser
import base64
import sys
import threading
import tempfile
import subprocess
import hashlib

from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from crypto import encrypt_data, decrypt_data


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "SecureVault"
APP_VERSION = "1.1.1"

VAULT_FILE = "vault.json"
RECOVERY_META_FILE = "recovery_meta.json"

AUTO_LOCK_TIME = 300

BACKEND_URL = "https://securevaultreal.vercel.app"

FORGOT_PASSWORD_URL = (
    "https://securevaultreal.vercel.app/forgot-password.html"
)

PBKDF2_ITERATIONS = 390000

# GitHub repository used for updates
GITHUB_REPO = "mjaxjzif/Secure-Vault-FP"

GITHUB_API_URL = (
    f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
)

GITHUB_DOWNLOAD_URL = (
    f"https://github.com/{GITHUB_REPO}/releases/latest/download/SecureVault.exe"
)


# ============================================================
# SECUREVAULT
# ============================================================

class SecureVault:

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

    # ========================================================
    # INITIALIZATION
    # ========================================================

    def __init__(self, root):

        self.root = root

        self.root.title(
            f"{APP_NAME} V{APP_VERSION}"
        )

        self.root.geometry("1180x720")
        self.root.minsize(950, 620)

        self.root.configure(
            bg=self.BG
        )

        self.master_password = None
        self.recovery_key = None

        self.vault = {
            "accounts": [],
            "email": ""
        }

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

        # Check for updates shortly after startup.
        # It only runs in the compiled EXE.
        self.root.after(
            1500,
            self.check_for_updates
        )

    # ========================================================
    # STYLES
    # ========================================================

    def setup_styles(self):

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "TButton",
            font=("Segoe UI", 10, "bold"),
            padding=10,
            background=self.PANEL_3,
            foreground=self.TEXT,
            borderwidth=0
        )

        style.map(
            "TButton",
            background=[
                ("active", "#20314d")
            ]
        )

        style.configure(
            "Accent.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=11,
            background=self.CYAN,
            foreground="#061018",
            borderwidth=0
        )

        style.map(
            "Accent.TButton",
            background=[
                ("active", "#8be8ff")
            ]
        )

        style.configure(
            "Danger.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=10,
            background="#321827",
            foreground="#ff9aaa",
            borderwidth=0
        )

        style.configure(
            "TEntry",
            padding=9,
            font=("Segoe UI", 11),
            fieldbackground="#101a2b",
            foreground=self.TEXT
        )

        style.configure(
            "Treeview",
            background=self.PANEL,
            fieldbackground=self.PANEL,
            foreground=self.TEXT,
            font=("Segoe UI", 10),
            rowheight=42,
            borderwidth=0
        )

        style.configure(
            "Treeview.Heading",
            background="#141f33",
            foreground="#9fb0c8",
            font=("Segoe UI", 10, "bold"),
            padding=10,
            borderwidth=0
        )

        style.map(
            "Treeview",
            background=[
                ("selected", "#183652")
            ],
            foreground=[
                ("selected", "white")
            ]
        )

    # ========================================================
    # AUTO LOCK
    # ========================================================

    def reset_timer(self, event=None):

        if self.master_password is not None:
            self.last_activity = time.time()

    def check_lock(self):

        if (
            self.master_password is not None
            and
            time.time() - self.last_activity
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

    def clear_screen(self):

        for widget in self.root.winfo_children():
            widget.destroy()

    def clear_clipboard(self):

        try:
            self.root.clipboard_clear()
            self.root.update()
        except Exception:
            pass

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
    # VERSION / UPDATE HELPERS
    # ========================================================

    def parse_version(
        self,
        version
    ):

        version = str(
            version
        ).strip().lower()

        if version.startswith("v"):
            version = version[1:]

        parts = version.split(".")

        numbers = []

        for part in parts[:3]:

            number = ""

            for char in part:

                if char.isdigit():
                    number += char
                else:
                    break

            numbers.append(
                int(number)
                if number
                else 0
            )

        while len(numbers) < 3:
            numbers.append(0)

        return tuple(numbers[:3])

    def check_for_updates(self):

        # Do not attempt self-update while running as
        # normal Python source.
        if not getattr(
            sys,
            "frozen",
            False
        ):
            return

        threading.Thread(
            target=self.update_check_worker,
            daemon=True
        ).start()

    def update_check_worker(self):

        try:

            request = Request(
                GITHUB_API_URL,
                headers={
                    "Accept":
                        "application/vnd.github+json",

                    "User-Agent":
                        "SecureVault",

                    "X-GitHub-Api-Version":
                        "2022-11-28"
                }
            )

            with urlopen(
                request,
                timeout=15
            ) as response:

                data = json.loads(
                    response
                    .read()
                    .decode("utf-8")
                )

            latest_version = str(
                data.get(
                    "tag_name",
                    ""
                )
            ).strip()

            if not latest_version:
                return

            if (
                self.parse_version(
                    latest_version
                )
                <=
                self.parse_version(
                    APP_VERSION
                )
            ):
                return

            download_url = (
                GITHUB_DOWNLOAD_URL
            )

            digest = ""

            for asset in data.get(
                "assets",
                []
            ):

                if asset.get(
                    "name"
                ) == "SecureVault.exe":

                    download_url = (
                        asset.get(
                            "browser_download_url",
                            GITHUB_DOWNLOAD_URL
                        )
                    )

                    digest = str(
                        asset.get(
                            "digest",
                            ""
                        )
                    )

                    break

            self.root.after(
                0,
                lambda:
                    self.show_update_window(
                        latest_version,
                        download_url,
                        digest
                    )
            )

        except Exception as error:

            print(
                "Update check failed:",
                error
            )

    def show_update_window(
        self,
        latest_version,
        download_url,
        digest
    ):

        window = tk.Toplevel(
            self.root
        )

        window.title(
            "SecureVault Update"
        )

        window.geometry(
            "540x360"
        )

        window.configure(
            bg=self.PANEL
        )

        window.resizable(
            False,
            False
        )

        window.transient(
            self.root
        )

        window.grab_set()

        tk.Label(
            window,
            text="🚀 Update Available",
            bg=self.PANEL,
            fg=self.TEXT,
            font=(
                "Segoe UI",
                23,
                "bold"
            )
        ).pack(
            pady=(28, 8)
        )

        tk.Label(
            window,
            text=(
                f"Current version: V{APP_VERSION}\n"
                f"Latest version: {latest_version}"
            ),
            bg=self.PANEL,
            fg=self.MUTED,
            justify="center",
            font=(
                "Segoe UI",
                10
            )
        ).pack(
            pady=8
        )

        tk.Label(
            window,
            text=(
                "A newer version of SecureVault is available.\n"
                "The update will be downloaded and installed automatically."
            ),
            bg=self.PANEL,
            fg="#aab6c8",
            justify="center",
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            pady=10
        )

        status = tk.Label(
            window,
            text="Ready to update.",
            bg=self.PANEL,
            fg=self.MUTED,
            font=(
                "Segoe UI",
                9
            )
        )

        status.pack(
            pady=8
        )

        buttons = tk.Frame(
            window,
            bg=self.PANEL
        )

        buttons.pack(
            pady=15
        )

        update_button = tk.Button(
            buttons,
            text="Update Now",
            bg="#2563eb",
            fg="white",
            activebackground="#1d4ed8",
            activeforeground="white",
            bd=0,
            padx=30,
            pady=11,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        update_button.pack(
            side="left",
            padx=6
        )

        later_button = tk.Button(
            buttons,
            text="Later",
            bg=self.PANEL_3,
            fg=self.TEXT,
            activebackground="#24344c",
            activeforeground="white",
            bd=0,
            padx=30,
            pady=11,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            command=window.destroy
        )

        later_button.pack(
            side="left",
            padx=6
        )

        def start():

            update_button.config(
                state="disabled"
            )

            later_button.config(
                state="disabled"
            )

            status.config(
                text="Downloading update..."
            )

            threading.Thread(
                target=self.download_update_worker,
                args=(
                    download_url,
                    digest,
                    window,
                    status
                ),
                daemon=True
            ).start()

        update_button.config(
            command=start
        )

    def download_update_worker(
        self,
        download_url,
        digest,
        window,
        status
    ):

        new_file = None

        try:

            temp_directory = tempfile.gettempdir()

            new_file = os.path.join(
                temp_directory,
                (
                    "SecureVault_update_"
                    +
                    secrets.token_hex(8)
                    +
                    ".exe"
                )
            )

            request = Request(
                download_url,
                headers={
                    "User-Agent":
                        "SecureVault-Updater"
                }
            )

            with urlopen(
                request,
                timeout=120
            ) as response:

                with open(
                    new_file,
                    "wb"
                ) as output:

                    while True:

                        chunk = response.read(
                            1024 * 1024
                        )

                        if not chunk:
                            break

                        output.write(
                            chunk
                        )

            # ------------------------------------------------
            # VERIFY SHA-256 WHEN AVAILABLE
            # ------------------------------------------------

            if digest.startswith(
                "sha256:"
            ):

                expected = (
                    digest
                    .split(
                        ":",
                        1
                    )[1]
                    .strip()
                    .lower()
                )

                hasher = hashlib.sha256()

                with open(
                    new_file,
                    "rb"
                ) as source:

                    while True:

                        chunk = source.read(
                            1024 * 1024
                        )

                        if not chunk:
                            break

                        hasher.update(
                            chunk
                        )

                actual = (
                    hasher
                    .hexdigest()
                    .lower()
                )

                if actual != expected:

                    raise ValueError(
                        "The downloaded update failed SHA-256 verification."
                    )

            app_path = os.path.abspath(
                sys.executable
            )

            app_directory = os.path.dirname(
                app_path
            )

            # Check that the EXE directory is writable.
            test_file = os.path.join(
                app_directory,
                (
                    ".securevault_write_test_"
                    +
                    secrets.token_hex(6)
                )
            )

            try:

                with open(
                    test_file,
                    "w",
                    encoding="utf-8"
                ) as file:

                    file.write("test")

                os.remove(
                    test_file
                )

            except Exception:

                raise PermissionError(
                    "SecureVault cannot update itself in this folder. "
                    "Move the EXE to a folder you can write to, such as "
                    "your Downloads folder."
                )

            updater_script = os.path.join(
                temp_directory,
                (
                    "SecureVault_updater_"
                    +
                    secrets.token_hex(8)
                    +
                    ".cmd"
                )
            )

            pid = os.getpid()

            script = f"""@echo off
setlocal

set "APP_PATH={app_path}"
set "NEW_PATH={new_file}"
set "APP_PID={pid}"

:WAIT_FOR_APP
tasklist /FI "PID eq %APP_PID%" | find "%APP_PID%" >nul

if not errorlevel 1 (
    timeout /t 1 /nobreak >nul
    goto WAIT_FOR_APP
)

timeout /t 1 /nobreak >nul

copy /Y "%NEW_PATH%" "%APP_PATH%" >nul

if errorlevel 1 (
    del "%NEW_PATH%" >nul 2>&1
    del "%~f0" >nul 2>&1
    exit /b 1
)

del "%NEW_PATH%" >nul 2>&1

start "" "%APP_PATH%"

del "%~f0" >nul 2>&1

endlocal
exit /b 0
"""

            with open(
                updater_script,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(
                    script
                )

            creation_flags = (
                subprocess.CREATE_NEW_PROCESS_GROUP
                |
                subprocess.DETACHED_PROCESS
                |
                subprocess.CREATE_NO_WINDOW
            )

            subprocess.Popen(
                [
                    "cmd.exe",
                    "/c",
                    updater_script
                ],
                creationflags=creation_flags,
                close_fds=True
            )

            self.root.after(
                0,
                lambda:
                    status.config(
                        text="Update downloaded. Restarting..."
                    )
            )

            self.root.after(
                1000,
                window.destroy
            )

            self.root.after(
                1100,
                self.close
            )

            self.root.after(
                1300,
                lambda:
                    os._exit(0)
            )

        except Exception as error:

            if (
                new_file
                and
                os.path.exists(new_file)
            ):

                try:
                    os.remove(
                        new_file
                    )
                except Exception:
                    pass

            self.root.after(
                0,
                lambda:
                    self.update_failed(
                        window,
                        status,
                        str(error)
                    )
            )

    def update_failed(
        self,
        window,
        status,
        error
    ):

        status.config(
            text="Update failed."
        )

        messagebox.showerror(
            "Update Failed",
            (
                "SecureVault could not update automatically.\n\n"
                +
                error
            ),
            parent=window
        )

    # ========================================================
    # RECOVERY CRYPTO
    # ========================================================

    def derive_recovery_key(
        self,
        recovery_key,
        salt
    ):

        if not recovery_key:

            raise ValueError(
                "Recovery key is empty."
            )

        if not salt:

            raise ValueError(
                "Recovery salt is missing."
            )

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS
        )

        derived = kdf.derive(
            recovery_key.encode("utf-8")
        )

        return Fernet(
            base64.urlsafe_b64encode(
                derived
            )
        )

    def create_recovery_metadata(
        self,
        email,
        master_password,
        recovery_key
    ):

        salt = secrets.token_bytes(16)

        fernet = self.derive_recovery_key(
            recovery_key,
            salt
        )

        encrypted_password = (
            fernet
            .encrypt(
                master_password.encode("utf-8")
            )
            .decode("utf-8")
        )

        metadata = {
            "version": 1,
            "email": email,
            "salt": base64.b64encode(
                salt
            ).decode("ascii"),
            "encrypted_master_password":
                encrypted_password
        }

        temporary = (
            RECOVERY_META_FILE +
            ".tmp"
        )

        with open(
            temporary,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                metadata,
                file,
                indent=2
            )

        os.replace(
            temporary,
            RECOVERY_META_FILE
        )

    def update_recovery_metadata(
        self,
        email,
        master_password,
        recovery_key
    ):

        if not os.path.exists(
            RECOVERY_META_FILE
        ):

            self.create_recovery_metadata(
                email,
                master_password,
                recovery_key
            )

            return

        with open(
            RECOVERY_META_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            metadata = json.load(
                file
            )

        salt = base64.b64decode(
            metadata["salt"]
        )

        fernet = self.derive_recovery_key(
            recovery_key,
            salt
        )

        encrypted_password = (
            fernet
            .encrypt(
                master_password.encode("utf-8")
            )
            .decode("utf-8")
        )

        metadata["email"] = email

        metadata[
            "encrypted_master_password"
        ] = encrypted_password

        temporary = (
            RECOVERY_META_FILE +
            ".tmp"
        )

        with open(
            temporary,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                metadata,
                file,
                indent=2
            )

        os.replace(
            temporary,
            RECOVERY_META_FILE
        )

    def recover_master_password(
        self,
        recovery_key
    ):

        if not os.path.exists(
            RECOVERY_META_FILE
        ):

            raise ValueError(
                "Recovery is not set up for this vault."
            )

        with open(
            RECOVERY_META_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            metadata = json.load(
                file
            )

        salt = base64.b64decode(
            metadata["salt"]
        )

        encrypted_password = (
            metadata[
                "encrypted_master_password"
            ]
        )

        fernet = self.derive_recovery_key(
            recovery_key,
            salt
        )

        try:

            password = fernet.decrypt(
                encrypted_password.encode("utf-8")
            ).decode("utf-8")

            return password

        except InvalidToken:

            raise ValueError(
                "Incorrect recovery key."
            )

    def get_recovery_email(self):

        if not os.path.exists(
            RECOVERY_META_FILE
        ):

            return ""

        try:

            with open(
                RECOVERY_META_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                metadata = json.load(
                    file
                )

            return str(
                metadata.get(
                    "email",
                    ""
                )
            ).strip().lower()

        except Exception:

            return ""

    # ========================================================
    # LOGIN SCREEN
    # ========================================================

    def login_screen(self):

        self.clear_screen()

        outer = tk.Frame(
            self.root,
            bg=self.BG
        )

        outer.pack(
            fill="both",
            expand=True
        )

        # ----------------------------------------------------
        # LEFT SIDE
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

        branding = tk.Frame(
            left,
            bg=self.BG
        )

        branding.place(
            relx=0.5,
            rely=0.5,
            anchor="center"
        )

        tk.Label(
            branding,
            text="🔐",
            bg=self.BG,
            fg=self.CYAN,
            font=(
                "Segoe UI Emoji",
                62
            )
        ).pack(
            pady=(0, 15)
        )

        tk.Label(
            branding,
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
            branding,
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

        for item in [
            "🔒  Encrypted local vault",
            "🎲  Strong password generator",
            "⏱  Automatic locking",
            "🔑  Email recovery"
        ]:

            tk.Label(
                branding,
                text=item,
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

        tk.Label(
            branding,
            text=f"V{APP_VERSION}",
            bg=self.BG,
            fg="#58667a",
            font=(
                "Segoe UI",
                9,
                "bold"
            )
        ).pack(
            pady=(25, 0)
        )

        # ----------------------------------------------------
        # RIGHT SIDE
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

        has_vault = os.path.exists(
            VAULT_FILE
        )

        tk.Label(
            card,
            text=(
                "Welcome back"
                if has_vault
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
                "Unlock your password vault."
                if has_vault
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
            width=34
        )

        self.password_entry.pack(
            side="left",
            fill="x",
            expand=True
        )

        show_button = tk.Button(
            row,
            text="Show",
            command=lambda:
                self.password_toggle(
                    self.password_entry,
                    show_button
                ),
            bg=self.PANEL_2,
            fg=self.CYAN,
            activebackground=self.PANEL_2,
            activeforeground="white",
            bd=0,
            padx=12,
            cursor="hand2"
        )

        show_button.pack(
            side="right",
            padx=(8, 0)
        )

        if has_vault:

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
                pady=(16, 5)
            )

            tk.Label(
                card,
                text="Auto-lock after 5 minutes",
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
                text="At least 10 characters recommended.",
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
                "Mismatch",
                "The passwords do not match."
            )

            return

        email = self.ask_recovery_email()

        if not email:
            return

        self.master_password = password

        self.recovery_key = (
            self.generate_recovery_key()
        )

        self.vault = {
            "accounts": [],
            "email": email,
            "recovery_key": self.recovery_key,
            "recovery_key_confirmed": False
        }

        self.last_activity = time.time()

        self.save()

        try:

            self.create_recovery_metadata(
                email,
                password,
                self.recovery_key
            )

        except Exception as error:

            messagebox.showerror(
                "Recovery Setup Error",
                str(error),
                parent=self.root
            )

            self.master_password = None

            return

        self.recovery_screen()

    # ========================================================
    # CONFIRM PASSWORD
    # ========================================================

    def confirm_password(self):

        window = tk.Toplevel(
            self.root
        )

        window.title(
            "Confirm Password"
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
            text="Confirm Master Password",
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
            fill="x",
            padx=35
        )

        def finish():

            result[0] = entry.get()

            window.destroy()

        ttk.Button(
            window,
            text="Confirm",
            style="Accent.TButton",
            command=finish
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
            "500x300"
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
                "Enter the email you will use\n"
                "for password recovery."
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

            email = (
                entry.get()
                .strip()
                .lower()
            )

            if (
                "@" not in email
                or "." not in email
            ):

                messagebox.showwarning(
                    "Invalid Email",
                    "Enter a valid email address.",
                    parent=window
                )

                return

            result[0] = email

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

        characters = (
            string.ascii_uppercase
            +
            string.digits
        )

        return "-".join(
            "".join(
                secrets.choice(
                    characters
                )
                for _ in range(6)
            )
            for _ in range(4)
        )

    def ensure_recovery_setup(self):

        if self.master_password is None:

            raise ValueError(
                "Unlock your vault first."
            )

        recovery_key = str(
            self.vault.get(
                "recovery_key",
                ""
            )
        ).strip()

        email = str(
            self.vault.get(
                "email",
                ""
            )
        ).strip().lower()

        created_new_key = False

        if not recovery_key:

            recovery_key = (
                self.generate_recovery_key()
            )

            self.vault[
                "recovery_key"
            ] = recovery_key

            self.recovery_key = recovery_key

            created_new_key = True

        else:

            self.recovery_key = recovery_key

        if not email:

            email = self.ask_recovery_email()

            if not email:
                return None

            self.vault[
                "email"
            ] = email

        self.save()

        self.create_recovery_metadata(
            email,
            self.master_password,
            recovery_key
        )

        if created_new_key:

            messagebox.showinfo(
                "Recovery Enabled",
                (
                    "Recovery has been enabled.\n\n"
                    "Your Recovery Key will now be shown."
                ),
                parent=self.root
            )

        return recovery_key

    def show_recovery_key(self):

        if self.master_password is None:

            messagebox.showwarning(
                "Vault Locked",
                "Unlock your vault first.",
                parent=self.root
            )

            return

        try:

            recovery_key = (
                self.ensure_recovery_setup()
            )

            if not recovery_key:
                return

            self.show_recovery_key_window(
                recovery_key
            )

        except Exception as error:

            messagebox.showerror(
                "Recovery Error",
                str(error),
                parent=self.root
            )

    def show_recovery_key_window(
        self,
        recovery_key
    ):

        window = tk.Toplevel(
            self.root
        )

        window.title(
            "SecureVault Recovery Key"
        )

        window.geometry(
            "650x330"
        )

        window.configure(
            bg=self.BG
        )

        window.resizable(
            False,
            False
        )

        window.transient(
            self.root
        )

        window.grab_set()

        tk.Label(
            window,
            text="🔑",
            bg=self.BG,
            fg=self.CYAN,
            font=(
                "Segoe UI Emoji",
                45
            )
        ).pack(
            pady=(20, 2)
        )

        tk.Label(
            window,
            text="Your Recovery Key",
            bg=self.BG,
            fg=self.TEXT,
            font=(
                "Segoe UI",
                23,
                "bold"
            )
        ).pack()

        tk.Label(
            window,
            text=(
                "Save this key somewhere private.\n"
                "You will need it to recover your vault."
            ),
            bg=self.BG,
            fg=self.MUTED,
            justify="center",
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            pady=(7, 15)
        )

        key_box = tk.Entry(
            window,
            width=48,
            justify="center",
            font=(
                "Consolas",
                13,
                "bold"
            ),
            bg=self.PANEL_2,
            fg=self.CYAN,
            readonlybackground=self.PANEL_2,
            insertbackground="white",
            bd=0
        )

        key_box.insert(
            0,
            recovery_key
        )

        key_box.config(
            state="readonly"
        )

        key_box.pack(
            padx=30,
            ipady=10
        )

        buttons = tk.Frame(
            window,
            bg=self.BG
        )

        buttons.pack(
            pady=20
        )

        def copy_key():

            try:

                self.root.clipboard_clear()

                self.root.clipboard_append(
                    recovery_key
                )

                self.root.update()

                copy_button.config(
                    text="Copied ✓"
                )

                window.after(
                    1500,
                    lambda:
                        copy_button.config(
                            text="Copy Recovery Key"
                        )
                )

                self.root.after(
                    15000,
                    self.clear_clipboard
                )

            except Exception as error:

                messagebox.showerror(
                    "Copy Error",
                    str(error),
                    parent=window
                )

        copy_button = tk.Button(
            buttons,
            text="Copy Recovery Key",
            command=copy_key,
            bg="#2563eb",
            fg="white",
            activebackground="#1d4ed8",
            activeforeground="white",
            bd=0,
            padx=22,
            pady=10,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        copy_button.pack(
            side="left",
            padx=5
        )

        close_button = tk.Button(
            buttons,
            text="Close",
            command=window.destroy,
            bg=self.PANEL_3,
            fg=self.TEXT,
            activebackground="#24344c",
            activeforeground="white",
            bd=0,
            padx=22,
            pady=10,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        close_button.pack(
            side="left",
            padx=5
        )

        key_box.bind(
            "<Control-c>",
            lambda event:
                copy_key()
        )

        tk.Label(
            window,
            text="Never share this key with anyone.",
            bg=self.BG,
            fg="#68758a",
            font=(
                "Segoe UI",
                8
            )
        ).pack()

    def recovery_screen(self):

        self.clear_screen()

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
                "Your Recovery Key is required if you lose\n"
                "your master password.\n\n"
                "If you lose both the master password and\n"
                "Recovery Key, SecureVault cannot recover\n"
                "your vault."
            ),
            bg=self.PANEL,
            fg=self.MUTED,
            justify="center",
            font=(
                "Segoe UI",
                10
            )
        ).pack(
            pady=(10, 15)
        )

        key_box = tk.Entry(
            card,
            width=38,
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
            pady=12,
            ipady=9
        )

        def copy():

            try:

                self.root.clipboard_clear()

                self.root.clipboard_append(
                    self.recovery_key
                )

                self.root.update()

                copy_button.config(
                    text="Copied ✓"
                )

                self.root.after(
                    1500,
                    lambda:
                        copy_button.config(
                            text="📋 Copy Recovery Key"
                        )
                )

                self.root.after(
                    15000,
                    self.clear_clipboard
                )

            except Exception as error:

                messagebox.showerror(
                    "Copy Error",
                    str(error),
                    parent=card
                )

        copy_button = tk.Button(
            card,
            text="📋 Copy Recovery Key",
            command=copy,
            bg="#2563eb",
            fg="white",
            activebackground="#1d4ed8",
            activeforeground="white",
            bd=0,
            padx=22,
            pady=10,
            cursor="hand2",
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        )

        copy_button.pack(
            fill="x",
            padx=35,
            pady=5
        )

        saved_var = tk.BooleanVar(
            value=False
        )

        def update_continue():

            if saved_var.get():

                continue_button.config(
                    state="normal"
                )

            else:

                continue_button.config(
                    state="disabled"
                )

        checkbox = tk.Checkbutton(
            card,
            text=(
                "I have securely saved my Recovery Key."
            ),
            variable=saved_var,
            command=update_continue,
            bg=self.PANEL,
            fg=self.TEXT,
            activebackground=self.PANEL,
            activeforeground=self.TEXT,
            selectcolor=self.PANEL_2,
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            cursor="hand2"
        )

        checkbox.pack(
            pady=(15, 5)
        )

        tk.Label(
            card,
            text=(
                "You cannot continue until you confirm this."
            ),
            bg=self.PANEL,
            fg="#d69e2e",
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            pady=(0, 10)
        )

        def continue_to_vault():

            if not saved_var.get():
                return

            self.vault[
                "recovery_key_confirmed"
            ] = True

            self.save()

            self.dashboard()

        continue_button = ttk.Button(
            card,
            text="Continue to SecureVault →",
            style="Accent.TButton",
            command=continue_to_vault,
            state="disabled"
        )

        continue_button.pack(
            fill="x",
            padx=35,
            pady=(5, 28)
        )

    # ========================================================
    # SAVE VAULT
    # ========================================================

    def save(self):

        if self.master_password is None:

            raise ValueError(
                "Vault cannot be saved while locked."
            )

        encrypted = encrypt_data(
            self.vault,
            self.master_password
        )

        temporary = (
            VAULT_FILE +
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

    # ========================================================
    # UNLOCK
    # ========================================================

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

                encrypted = json.load(
                    file
                )

            vault_data = decrypt_data(
                encrypted,
                password
            )

            self.master_password = password

            self.vault = vault_data

            self.last_activity = time.time()

            recovery_key = str(
                self.vault.get(
                    "recovery_key",
                    ""
                )
            ).strip()

            email = str(
                self.vault.get(
                    "email",
                    ""
                )
            ).strip().lower()

            # ------------------------------------------------
            # NO RECOVERY KEY
            # ------------------------------------------------

            if not recovery_key:

                recovery_key = (
                    self.generate_recovery_key()
                )

                self.recovery_key = recovery_key

                if not email:

                    email = (
                        self.ask_recovery_email()
                    )

                    if not email:

                        self.master_password = None
                        self.recovery_key = None

                        return

                self.vault[
                    "email"
                ] = email

                self.vault[
                    "recovery_key"
                ] = recovery_key

                self.vault[
                    "recovery_key_confirmed"
                ] = False

                self.save()

                self.create_recovery_metadata(
                    email,
                    password,
                    recovery_key
                )

                self.recovery_screen()

                return

            # ------------------------------------------------
            # RECOVERY METADATA MISSING
            # ------------------------------------------------

            if not os.path.exists(
                RECOVERY_META_FILE
            ):

                if not email:

                    email = (
                        self.ask_recovery_email()
                    )

                    if not email:

                        self.master_password = None
                        self.recovery_key = None

                        return

                    self.vault[
                        "email"
                    ] = email

                    self.save()

                self.create_recovery_metadata(
                    email,
                    password,
                    recovery_key
                )

            self.recovery_key = recovery_key

            # ------------------------------------------------
            # FORCE RECOVERY KEY CONFIRMATION
            # ------------------------------------------------

            confirmed = bool(
                self.vault.get(
                    "recovery_key_confirmed",
                    False
                )
            )

            if not confirmed:

                self.recovery_screen()

                return

            self.dashboard()

        except Exception:

            self.master_password = None
            self.recovery_key = None

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

        self.clear_screen()

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
            pady=(25, 5)
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
            text=f"V{APP_VERSION}",
            bg=self.PANEL,
            fg="#64728a",
            font=(
                "Segoe UI",
                8,
                "bold"
            )
        ).pack(
            pady=(2, 5)
        )

        tk.Label(
            sidebar,
            text="PASSWORD MANAGER",
            bg=self.PANEL,
            fg="#536177",
            font=(
                "Segoe UI",
                7,
                "bold"
            )
        ).pack(
            pady=(0, 25)
        )

        self.sidebar_button(
            sidebar,
            "▣   My Vault",
            self.dashboard,
            True
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

        self.sidebar_button(
            sidebar,
            "🔑   Recovery Key",
            self.show_recovery_key
        )

        spacer = tk.Frame(
            sidebar,
            bg=self.PANEL
        )

        spacer.pack(
            fill="both",
            expand=True
        )

        tk.Button(
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
        ).pack(
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

        tk.Label(
            header,
            text=f"V{APP_VERSION}",
            bg=self.BG,
            fg="#5d6d83",
            font=(
                "Segoe UI",
                9,
                "bold"
            )
        ).pack(
            side="right",
            padx=(0, 15),
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

        account_count = len(
            self.vault.get(
                "accounts",
                []
            )
        )

        values = [
            (
                "🔐",
                "Saved Accounts",
                str(account_count)
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

        for icon, title, value in values:

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

            text_frame = tk.Frame(
                card,
                bg=self.PANEL
            )

            text_frame.pack(
                side="left"
            )

            tk.Label(
                text_frame,
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
                text_frame,
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
        # TREE
        # ----------------------------------------------------

        table = tk.Frame(
            main,
            bg=self.PANEL
        )

        table.pack(
            fill="both",
            expand=True,
            padx=30,
            pady=(0, 15)
        )

        self.tree = ttk.Treeview(
            table,
            columns=(
                "site",
                "username"
            ),
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
            lambda event:
                self.view_account()
        )

        # ----------------------------------------------------
        # BOTTOM
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

    # ========================================================
    # SIDEBAR
    # ========================================================

    def sidebar_button(
        self,
        parent,
        text,
        command,
        active=False
    ):

        background = (
            "#18364a"
            if active
            else self.PANEL
        )

        foreground = (
            self.CYAN
            if active
            else "#8998ad"
        )

        tk.Button(
            parent,
            text=text,
            command=command,
            anchor="w",
            bg=background,
            fg=foreground,
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
        ).pack(
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
                .strip()
                .lower()
            )

        for index, account in enumerate(
            self.vault.get(
                "accounts",
                []
            )
        ):

            website = str(
                account.get(
                    "website",
                    ""
                )
            )

            username = str(
                account.get(
                    "username",
                    ""
                )
            )

            if search:

                if (
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

        tk.Label(
            window,
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
            anchor="w",
            padx=35,
            pady=(28, 5)
        )

        tk.Label(
            window,
            text=(
                "Update your credentials."
                if editing
                else
                "Save a credential securely."
            ),
            bg=self.PANEL,
            fg=self.MUTED,
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            anchor="w",
            padx=35,
            pady=(0, 20)
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

        def field_label(text):

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

        field_label(
            "WEBSITE / APP"
        )

        website = ttk.Entry(
            frame
        )

        website.pack(
            fill="x"
        )

        field_label(
            "USERNAME / EMAIL"
        )

        username = ttk.Entry(
            frame
        )

        username.pack(
            fill="x"
        )

        field_label(
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
            pady=(5, 6)
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

                toggle_button.config(
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

                toggle_button.config(
                    text="Show Password"
                )

        toggle_button = ttk.Button(
            content,
            text="Show Password",
            command=toggle
        )

        toggle_button.pack(
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

        answer = messagebox.askyesno(
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

        if not answer:
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

        password = (
            self.generate_strong_password()
        )

        self.root.clipboard_clear()

        self.root.clipboard_append(
            password
        )

        self.root.update()

        messagebox.showinfo(
            "Password Generated",
            (
                "A strong password was generated "
                "and copied to your clipboard.\n\n"
                "Clipboard clears in 15 seconds."
            )
        )

        self.root.after(
            15000,
            self.clear_clipboard
        )

    # ========================================================
    # FORGOT PASSWORD
    # ========================================================

    def forgot_password(self):

        if not os.path.exists(
            RECOVERY_META_FILE
        ):

            messagebox.showwarning(
                "Recovery Not Set Up",
                (
                    "Recovery is not set up for this vault.\n\n"
                    "Unlock the vault first so SecureVault "
                    "can create the recovery information."
                )
            )

            return

        try:

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
                str(error)
            )

    # ========================================================
    # RESET PASSWORD
    # ========================================================

    def reset_password_dialog(self):

        if not os.path.exists(
            RECOVERY_META_FILE
        ):

            return

        window = tk.Toplevel(
            self.root
        )

        window.title(
            "Reset Master Password"
        )

        window.geometry(
            "590x610"
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
            pady=(25, 7)
        )

        tk.Label(
            window,
            text=(
                "Verify your email in the browser.\n"
                "Then paste the reset token here."
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

        def label(text):

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

        label(
            "RESET TOKEN"
        )

        token_entry = ttk.Entry(
            window
        )

        token_entry.pack(
            fill="x",
            padx=35
        )

        label(
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

        label(
            "NEW MASTER PASSWORD"
        )

        new_password_entry = ttk.Entry(
            window,
            show="•"
        )

        new_password_entry.pack(
            fill="x",
            padx=35
        )

        label(
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

        status = tk.Label(
            window,
            text="",
            bg=self.PANEL,
            fg=self.MUTED,
            font=(
                "Segoe UI",
                9
            ),
            wraplength=500
        )

        status.pack(
            pady=(12, 0)
        )

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
                new_password_entry
                .get()
            )

            confirm_password = (
                confirm_entry
                .get()
            )

            if not token:

                messagebox.showwarning(
                    "Missing Token",
                    "Paste the reset token from the website.",
                    parent=window
                )

                return

            if not recovery_key:

                messagebox.showwarning(
                    "Missing Recovery Key",
                    "Enter your recovery key.",
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

            status.config(
                text="Checking recovery token..."
            )

            window.update_idletasks()

            try:

                request = Request(
                    BACKEND_URL +
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
                    "success",
                    False
                ):

                    raise ValueError(
                        result.get(
                            "message",
                            result.get(
                                "error",
                                "Invalid reset token."
                            )
                        )
                    )

                verified_email = str(
                    result.get(
                        "email",
                        ""
                    )
                ).strip().lower()

                local_email = (
                    self.get_recovery_email()
                )

                if not local_email:

                    raise ValueError(
                        "This vault has no recovery email."
                    )

                if (
                    verified_email
                    !=
                    local_email
                ):

                    raise ValueError(
                        "The verified email does not match this vault."
                    )

                status.config(
                    text="Token verified. Recovering vault..."
                )

                window.update_idletasks()

                old_password = (
                    self.recover_master_password(
                        recovery_key
                    )
                )

                with open(
                    VAULT_FILE,
                    "r",
                    encoding="utf-8"
                ) as file:

                    encrypted_vault = json.load(
                        file
                    )

                vault_data = decrypt_data(
                    encrypted_vault,
                    old_password
                )

                # Keep recovery information intact.
                vault_data[
                    "recovery_key"
                ] = recovery_key

                vault_data[
                    "recovery_key_confirmed"
                ] = True

                new_encrypted = encrypt_data(
                    vault_data,
                    new_password
                )

                temporary = (
                    VAULT_FILE +
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

                self.update_recovery_metadata(
                    local_email,
                    new_password,
                    recovery_key
                )

                self.master_password = (
                    new_password
                )

                self.vault = (
                    vault_data
                )

                self.recovery_key = (
                    recovery_key
                )

                self.last_activity = (
                    time.time()
                )

                window.destroy()

                messagebox.showinfo(
                    "Password Reset Complete",
                    (
                        "Your SecureVault master password "
                        "has been reset successfully."
                    )
                )

                self.dashboard()

            except HTTPError as error:

                messagebox.showerror(
                    "Recovery Server Error",
                    (
                        f"Server returned HTTP {error.code}.\n\n"
                        "Make sure the Vercel recovery server "
                        "is online."
                    ),
                    parent=window
                )

                status.config(
                    text="Recovery server error."
                )

            except URLError as error:

                messagebox.showerror(
                    "Connection Error",
                    (
                        "Could not connect to the recovery server.\n\n"
                        +
                        str(error.reason)
                    ),
                    parent=window
                )

                status.config(
                    text="Could not contact recovery server."
                )

            except Exception as error:

                messagebox.showerror(
                    "Reset Failed",
                    str(error),
                    parent=window
                )

                status.config(
                    text="Reset failed."
                )

        ttk.Button(
            window,
            text="🔐 Reset Master Password",
            style="Accent.TButton",
            command=reset_now
        ).pack(
            fill="x",
            padx=35,
            pady=22
        )

        tk.Label(
            window,
            text=(
                "Never share your Recovery Key or Reset Token."
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

        token_entry.focus()

    # ========================================================
    # LOCK
    # ========================================================

    def lock(self):

        self.clear_clipboard()

        self.master_password = None

        self.recovery_key = None

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
        self.recovery_key = None

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
