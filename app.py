import os
import sys
import json
import base64
import hashlib
import secrets
import string
import time
import webbrowser
import threading
import tempfile
import subprocess
import shutil
import urllib.request
import urllib.error
import tkinter as tk
from tkinter import ttk, messagebox

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ============================================================
# SECUREVAULT CONFIG
# ============================================================

APP_NAME = "SecureVault"
APP_VERSION = "1.1.3"

GITHUB_REPO = "mjaxjzif/Secure-Vault-FP"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

BACKEND_URL = "https://securevaultreal.vercel.app"
FORGOT_PASSWORD_URL = f"{BACKEND_URL}/forgot-password.html"

AUTO_LOCK_TIME = 300
PBKDF2_ITERATIONS = 390000


# ============================================================
# DATA LOCATION
# ============================================================

# Keep vault.json beside the EXE so existing installations
# continue using their current files.

if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

VAULT_FILE = os.path.join(BASE_DIR, "vault.json")
RECOVERY_META_FILE = os.path.join(BASE_DIR, "recovery_meta.json")

BACKUP_DIR = os.path.join(
    BASE_DIR,
    "SecureVault_Backups"
)


# ============================================================
# GLOBAL STATE
# ============================================================

root = None

vault_data = None
master_password = None
recovery_key = None

current_account_id = None

last_activity = time.time()
auto_lock_job = None


# ============================================================
# CRYPTO
# ============================================================

def derive_key(password: str, salt: bytes) -> bytes:

    if not isinstance(password, str):
        raise TypeError("Password must be text.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )

    derived = kdf.derive(
        password.encode("utf-8")
    )

    return base64.urlsafe_b64encode(
        derived
    )


def encrypt_data(data, password: str) -> str:

    salt = os.urandom(16)

    key = derive_key(
        password,
        salt
    )

    plaintext = json.dumps(
        data,
        ensure_ascii=False
    ).encode("utf-8")

    token = Fernet(
        key
    ).encrypt(
        plaintext
    )

    return (
        "SV1."
        + base64.urlsafe_b64encode(salt).decode("ascii")
        + "."
        + token.decode("ascii")
    )


def decrypt_data(encrypted: str, password: str):

    if not isinstance(encrypted, str):
        raise ValueError(
            "Invalid vault data."
        )

    if not encrypted.startswith("SV1."):

        raise ValueError(
            "Unsupported SecureVault format."
        )

    parts = encrypted.split(
        ".",
        2
    )

    if len(parts) != 3:

        raise ValueError(
            "Corrupted vault format."
        )

    try:

        salt = base64.urlsafe_b64decode(
            parts[1].encode("ascii")
        )

    except Exception as exc:

        raise ValueError(
            "Invalid vault salt."
        ) from exc

    token = parts[2].encode(
        "ascii"
    )

    key = derive_key(
        password,
        salt
    )

    try:

        decrypted = Fernet(
            key
        ).decrypt(
            token
        )

    except InvalidToken as exc:

        raise ValueError(
            "Incorrect master password."
        ) from exc

    try:

        return json.loads(
            decrypted.decode("utf-8")
        )

    except Exception as exc:

        raise ValueError(
            "Vault data is corrupted."
        ) from exc


# ============================================================
# FILE FUNCTIONS
# ============================================================

def atomic_write_text(
    path: str,
    text: str
):

    directory = (
        os.path.dirname(path)
        or "."
    )

    os.makedirs(
        directory,
        exist_ok=True
    )

    fd, temp_path = tempfile.mkstemp(
        prefix=".securevault_",
        suffix=".tmp",
        dir=directory,
        text=True
    )

    try:

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(text)

            file.flush()

            os.fsync(
                file.fileno()
            )

        os.replace(
            temp_path,
            path
        )

    except Exception:

        try:
            os.unlink(
                temp_path
            )
        except OSError:
            pass

        raise


def save_vault(
    data,
    password: str
):

    encrypted = encrypt_data(
        data,
        password
    )

    atomic_write_text(
        VAULT_FILE,
        encrypted
    )


def load_vault(
    password: str
):

    if not os.path.isfile(
        VAULT_FILE
    ):

        raise ValueError(
            "No SecureVault exists."
        )

    with open(
        VAULT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        encrypted = file.read()

    return decrypt_data(
        encrypted,
        password
    )


def save_json_file(
    path: str,
    data
):

    atomic_write_text(
        path,
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False
        )
    )


def load_json_file(
    path: str
):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(
            file
        )


def vault_exists():

    return os.path.isfile(
        VAULT_FILE
    )


def recovery_meta_exists():

    return os.path.isfile(
        RECOVERY_META_FILE
    )


# ============================================================
# BACKUP SYSTEM
# ============================================================

def make_backup():

    os.makedirs(
        BACKUP_DIR,
        exist_ok=True
    )

    timestamp = time.strftime(
        "%Y%m%d_%H%M%S"
    )

    backup_path = os.path.join(
        BACKUP_DIR,
        f"Backup_{timestamp}"
    )

    os.makedirs(
        backup_path,
        exist_ok=True
    )

    copied_files = []

    for path in (
        VAULT_FILE,
        RECOVERY_META_FILE
    ):

        if os.path.isfile(path):

            destination = os.path.join(
                backup_path,
                os.path.basename(path)
            )

            shutil.copy2(
                path,
                destination
            )

            copied_files.append(
                destination
            )

    if not copied_files:

        return None

    return backup_path


def prepare_for_new_vault():

    if not vault_exists():

        return True

    answer = messagebox.askyesno(
        "Existing SecureVault",
        (
            "A SecureVault already exists on this PC.\n\n"

            "Creating a new SecureVault will first back up "
            "your existing vault so it is not silently overwritten.\n\n"

            "Do you want to create a NEW vault?"
        ),
        parent=root
    )

    if not answer:

        return False

    try:

        backup_path = make_backup()

        if not backup_path:

            messagebox.showerror(
                "Backup Failed",
                "The existing vault could not be backed up.",
                parent=root
            )

            return False

        old_active_folder = os.path.join(
            backup_path,
            "OldActiveFiles"
        )

        os.makedirs(
            old_active_folder,
            exist_ok=True
        )

        for path in (
            VAULT_FILE,
            RECOVERY_META_FILE
        ):

            if os.path.isfile(path):

                shutil.move(
                    path,
                    os.path.join(
                        old_active_folder,
                        os.path.basename(path)
                    )
                )

        messagebox.showinfo(
            "Backup Created",
            (
                "Your previous SecureVault was backed up successfully.\n\n"
                f"Backup location:\n{backup_path}\n\n"
                "You can now create a new SecureVault."
            ),
            parent=root
        )

        return True

    except Exception as exc:

        messagebox.showerror(
            "Could Not Create New Vault",
            (
                "SecureVault could not safely prepare the new vault.\n\n"
                f"{exc}"
            ),
            parent=root
        )

        return False


# ============================================================
# RECOVERY KEY
# ============================================================

def generate_recovery_key():

    alphabet = (
        string.ascii_uppercase
        + string.digits
    )

    groups = []

    for _ in range(4):

        group = "".join(
            secrets.choice(
                alphabet
            )
            for _ in range(6)
        )

        groups.append(
            group
        )

    return "-".join(
        groups
    )


def encrypt_master_for_recovery(
    master: str,
    recovery_key_text: str
):

    salt = os.urandom(
        16
    )

    key = derive_key(
        recovery_key_text,
        salt
    )

    encrypted = Fernet(
        key
    ).encrypt(
        master.encode("utf-8")
    )

    return (
        "RV1."
        + base64.urlsafe_b64encode(
            salt
        ).decode("ascii")
        + "."
        + encrypted.decode("ascii")
    )


def decrypt_master_from_recovery(
    encrypted: str,
    recovery_key_text: str
):

    if not encrypted.startswith(
        "RV1."
    ):

        raise ValueError(
            "Unsupported recovery metadata format."
        )

    parts = encrypted.split(
        ".",
        2
    )

    if len(parts) != 3:

        raise ValueError(
            "Corrupted recovery metadata."
        )

    salt = base64.urlsafe_b64decode(
        parts[1].encode("ascii")
    )

    token = parts[2].encode(
        "ascii"
    )

    key = derive_key(
        recovery_key_text,
        salt
    )

    try:

        return Fernet(
            key
        ).decrypt(
            token
        ).decode("utf-8")

    except InvalidToken as exc:

        raise ValueError(
            "Incorrect Recovery Key."
        ) from exc


def create_recovery_metadata(
    email: str,
    recovery_key_text: str,
    master: str
):

    metadata = {

        "version":
            APP_VERSION,

        "email":
            email.strip().lower(),

        "encrypted_master_password":
            encrypt_master_for_recovery(
                master,
                recovery_key_text
            )
    }

    save_json_file(
        RECOVERY_META_FILE,
        metadata
    )


def get_recovery_email():

    if not recovery_meta_exists():

        return ""

    try:

        metadata = load_json_file(
            RECOVERY_META_FILE
        )

        return str(
            metadata.get(
                "email",
                ""
            )
        ).strip().lower()

    except Exception:

        return ""


def recover_master_password(
    recovery_key_text: str
):

    if not recovery_meta_exists():

        raise ValueError(
            "Recovery metadata does not exist."
        )

    metadata = load_json_file(
        RECOVERY_META_FILE
    )

    encrypted = str(
        metadata.get(
            "encrypted_master_password",
            ""
        )
    )

    if not encrypted:

        raise ValueError(
            "Recovery metadata is incomplete."
        )

    return decrypt_master_from_recovery(
        encrypted,
        recovery_key_text.strip().upper()
    )


# ============================================================
# CLIPBOARD
# ============================================================

def copy_to_clipboard(
    text: str,
    clear_after_ms=15000
):

    if not text:

        return

    try:

        root.clipboard_clear()

        root.clipboard_append(
            text
        )

        root.update()

    except Exception:

        return

    def clear_clipboard():

        try:

            if root.clipboard_get() == text:

                root.clipboard_clear()

        except Exception:

            pass

    root.after(
        clear_after_ms,
        clear_clipboard
    )


# ============================================================
# UI UTILITIES
# ============================================================

def clear_root():

    for widget in root.winfo_children():

        widget.destroy()


def set_window_title(
    extra=""
):

    title = (
        f"{APP_NAME} V{APP_VERSION}"
    )

    if extra:

        title += (
            f" — {extra}"
        )

    root.title(
        title
    )


def center_window(
    width,
    height
):

    root.update_idletasks()

    screen_width = (
        root.winfo_screenwidth()
    )

    screen_height = (
        root.winfo_screenheight()
    )

    x = max(
        0,
        (screen_width - width) // 2
    )

    y = max(
        0,
        (screen_height - height) // 2
    )

    root.geometry(
        f"{width}x{height}+{x}+{y}"
    )


def style_app():

    style = ttk.Style()

    try:

        style.theme_use(
            "clam"
        )

    except tk.TclError:

        pass

    style.configure(
        "Title.TLabel",
        font=(
            "Segoe UI",
            26,
            "bold"
        )
    )

    style.configure(
        "Subtitle.TLabel",
        font=(
            "Segoe UI",
            11
        )
    )

    style.configure(
        "Primary.TButton",
        font=(
            "Segoe UI",
            10,
            "bold"
        ),
        padding=(
            15,
            10
        )
    )


# ============================================================
# ACTIVITY / AUTO LOCK
# ============================================================

def activity_event(
    _event=None
):

    global last_activity

    last_activity = time.time()


def bind_activity(
    widget
):

    widget.bind_all(
        "<KeyPress>",
        activity_event,
        add="+"
    )

    widget.bind_all(
        "<ButtonPress>",
        activity_event,
        add="+"
    )


def start_auto_lock_timer():

    global auto_lock_job

    if auto_lock_job:

        try:

            root.after_cancel(
                auto_lock_job
            )

        except Exception:

            pass

    def check_lock():

        global auto_lock_job

        if master_password is not None:

            elapsed = (
                time.time()
                - last_activity
            )

            if elapsed >= AUTO_LOCK_TIME:

                lock_vault(
                    silent=False
                )

                return

        auto_lock_job = root.after(
            5000,
            check_lock
        )

    auto_lock_job = root.after(
        5000,
        check_lock
    )


# ============================================================
# CREATE SECUREVAULT SCREEN
# ============================================================

def create_vault():

    # IMPORTANT:
    # This is called even when vault.json already exists.
    # The existing vault is backed up first.

    if not prepare_for_new_vault():

        return

    clear_root()

    set_window_title(
        "Create SecureVault"
    )

    center_window(
        560,
        570
    )

    frame = ttk.Frame(
        root,
        padding=36
    )

    frame.pack(
        fill="both",
        expand=True
    )

    ttk.Label(
        frame,
        text="Create SecureVault",
        style="Title.TLabel"
    ).pack(
        pady=(15, 7)
    )

    ttk.Label(
        frame,
        text=(
            "Create your master password.\n"
            "Your vault is encrypted locally."
        ),
        style="Subtitle.TLabel",
        justify="center"
    ).pack(
        pady=(0, 25)
    )

    ttk.Label(
        frame,
        text="Master Password"
    ).pack(
        anchor="w"
    )

    master_var = tk.StringVar()

    master_entry = ttk.Entry(
        frame,
        textvariable=master_var,
        show="•"
    )

    master_entry.pack(
        fill="x",
        pady=(6, 16),
        ipady=8
    )

    ttk.Label(
        frame,
        text="Confirm Master Password"
    ).pack(
        anchor="w"
    )

    confirm_var = tk.StringVar()

    confirm_entry = ttk.Entry(
        frame,
        textvariable=confirm_var,
        show="•"
    )

    confirm_entry.pack(
        fill="x",
        pady=(6, 16),
        ipady=8
    )

    ttk.Label(
        frame,
        text="Recovery Email"
    ).pack(
        anchor="w"
    )

    email_var = tk.StringVar()

    email_entry = ttk.Entry(
        frame,
        textvariable=email_var
    )

    email_entry.pack(
        fill="x",
        pady=(6, 8),
        ipady=8
    )

    ttk.Label(
        frame,
        text=(
            "Use an email you can access for recovery verification."
        ),
        justify="left"
    ).pack(
        anchor="w",
        pady=(0, 17)
    )

    status_var = tk.StringVar()

    ttk.Label(
        frame,
        textvariable=status_var,
        wraplength=470,
        justify="center"
    ).pack(
        pady=8
    )

    def submit():

        password = master_var.get()
        confirm = confirm_var.get()
        email = (
            email_var.get()
            .strip()
            .lower()
        )

        if len(password) < 10:

            status_var.set(
                "Master password must be at least 10 characters."
            )

            return

        if password != confirm:

            status_var.set(
                "The master passwords do not match."
            )

            return

        if (
            not email
            or "@"
            not in email
            or "."
            not in email.split("@")[-1]
        ):

            status_var.set(
                "Enter a valid recovery email address."
            )

            return

        try:

            global vault_data
            global master_password
            global recovery_key

            recovery_key = generate_recovery_key()

            vault_data = {

                "version":
                    APP_VERSION,

                "email":
                    email,

                "recovery_key":
                    recovery_key,

                "recovery_key_confirmed":
                    False,

                "accounts":
                    []
            }

            master_password = password

            save_vault(
                vault_data,
                master_password
            )

            create_recovery_metadata(
                email,
                recovery_key,
                master_password
            )

            recovery_screen()

        except Exception as exc:

            messagebox.showerror(
                "Could Not Create Vault",
                str(exc),
                parent=root
            )

    ttk.Button(
        frame,
        text="Create SecureVault",
        style="Primary.TButton",
        command=submit
    ).pack(
        fill="x",
        pady=(10, 10)
    )

    ttk.Button(
        frame,
        text="Back to Login",
        command=login_screen
    ).pack(
        fill="x"
    )

    master_entry.focus_set()

    bind_activity(
        root
    )


# ============================================================
# RECOVERY KEY CONFIRMATION
# ============================================================

def recovery_screen():

    clear_root()

    set_window_title(
        "Recovery Setup"
    )

    center_window(
        620,
        545
    )

    frame = ttk.Frame(
        root,
        padding=36
    )

    frame.pack(
        fill="both",
        expand=True
    )

    ttk.Label(
        frame,
        text="Save Your Recovery Key",
        style="Title.TLabel"
    ).pack(
        pady=(15, 8)
    )

    ttk.Label(
        frame,
        text=(
            "This key is required if you forget your master password.\n"
            "Save it somewhere private and safe."
        ),
        justify="center"
    ).pack(
        pady=(0, 18)
    )

    key_var = tk.StringVar(
        value=recovery_key or ""
    )

    key_entry = ttk.Entry(
        frame,
        textvariable=key_var,
        justify="center",
        font=(
            "Consolas",
            15,
            "bold"
        ),
        state="readonly"
    )

    key_entry.pack(
        fill="x",
        ipady=10,
        pady=8
    )

    ttk.Button(
        frame,
        text="Copy Recovery Key",
        command=lambda:
            copy_to_clipboard(
                key_var.get()
            )
    ).pack(
        pady=8
    )

    ttk.Label(
        frame,
        text=(
            "IMPORTANT\n\n"
            "If both your master password and Recovery Key "
            "are lost, SecureVault cannot recover the encrypted vault."
        ),
        justify="center"
    ).pack(
        pady=18
    )

    confirmed_var = tk.BooleanVar(
        value=False
    )

    continue_button = None

    def checkbox_changed():

        continue_button.config(
            state=(
                "normal"
                if confirmed_var.get()
                else "disabled"
            )
        )

    ttk.Checkbutton(
        frame,
        text="I have securely saved my Recovery Key.",
        variable=confirmed_var,
        command=checkbox_changed
    ).pack(
        pady=8
    )

    def continue_to_dashboard():

        vault_data[
            "recovery_key_confirmed"
        ] = True

        save_vault(
            vault_data,
            master_password
        )

        dashboard()

    continue_button = ttk.Button(
        frame,
        text="Continue to SecureVault",
        style="Primary.TButton",
        command=continue_to_dashboard,
        state="disabled"
    )

    continue_button.pack(
        fill="x",
        pady=(14, 8)
    )

    ttk.Button(
        frame,
        text="Lock and Exit",
        command=close_app
    ).pack(
        fill="x"
    )


# ============================================================
# LOGIN SCREEN
# ============================================================

def login_screen():

    clear_root()

    set_window_title(
        "Login"
    )

    center_window(
        560,
        550
    )

    frame = ttk.Frame(
        root,
        padding=36
    )

    frame.pack(
        fill="both",
        expand=True
    )

    ttk.Label(
        frame,
        text="SecureVault",
        style="Title.TLabel"
    ).pack(
        pady=(25, 4)
    )

    ttk.Label(
        frame,
        text=f"V{APP_VERSION}",
        style="Subtitle.TLabel"
    ).pack(
        pady=(0, 17)
    )

    if vault_exists():

        ttk.Label(
            frame,
            text=(
                "An encrypted SecureVault already exists on this PC."
            ),
            justify="center"
        ).pack(
            pady=(0, 20)
        )

    else:

        ttk.Label(
            frame,
            text=(
                "No SecureVault exists yet. Create one below."
            ),
            justify="center"
        ).pack(
            pady=(0, 20)
        )

    ttk.Label(
        frame,
        text="Master Password"
    ).pack(
        anchor="w"
    )

    password_var = tk.StringVar()

    password_entry = ttk.Entry(
        frame,
        textvariable=password_var,
        show="•"
    )

    password_entry.pack(
        fill="x",
        pady=(6, 18),
        ipady=8
    )

    status_var = tk.StringVar()

    ttk.Label(
        frame,
        textvariable=status_var,
        wraplength=480,
        justify="center"
    ).pack(
        pady=7
    )

    def unlock():

        password = password_var.get()

        if not vault_exists():

            status_var.set(
                "No vault exists. Click Create SecureVault."
            )

            return

        if not password:

            status_var.set(
                "Enter your master password."
            )

            return

        try:

            global vault_data
            global master_password
            global recovery_key
            global last_activity

            data = load_vault(
                password
            )

            changed = False

            if (
                "accounts"
                not in data
                or not isinstance(
                    data["accounts"],
                    list
                )
            ):

                data["accounts"] = []

                changed = True

            if (
                "recovery_key"
                not in data
                or not data.get(
                    "recovery_key"
                )
            ):

                data[
                    "recovery_key"
                ] = generate_recovery_key()

                changed = True

            if "email" not in data:

                data["email"] = (
                    get_recovery_email()
                )

            vault_data = data

            master_password = password

            recovery_key = str(
                data[
                    "recovery_key"
                ]
            ).upper()

            last_activity = time.time()

            if changed:

                save_vault(
                    vault_data,
                    master_password
                )

            email = str(
                vault_data.get(
                    "email",
                    ""
                )
            ).strip().lower()

            if (
                not recovery_meta_exists()
                and email
            ):

                create_recovery_metadata(
                    email,
                    recovery_key,
                    master_password
                )

            elif (
                recovery_meta_exists()
                and email
                and get_recovery_email()
                != email
            ):

                create_recovery_metadata(
                    email,
                    recovery_key,
                    master_password
                )

            # Old vaults will come through this screen
            # once after migration.
            if not bool(
                vault_data.get(
                    "recovery_key_confirmed",
                    False
                )
            ):

                recovery_screen()

            else:

                dashboard()

        except ValueError as exc:

            status_var.set(
                str(exc)
            )

        except Exception as exc:

            status_var.set(
                f"Could not unlock vault: {exc}"
            )

    ttk.Button(
        frame,
        text="Unlock SecureVault",
        style="Primary.TButton",
        command=unlock
    ).pack(
        fill="x",
        pady=(10, 8)
    )

    # ========================================================
    # THIS IS THE IMPORTANT FIX
    #
    # The create button ALWAYS exists.
    # ========================================================

    if vault_exists():

        create_text = (
            "Create New SecureVault"
        )

    else:

        create_text = (
            "Create SecureVault"
        )

    ttk.Button(
        frame,
        text=create_text,
        command=create_vault
    ).pack(
        fill="x",
        pady=5
    )

    ttk.Button(
        frame,
        text="Forgot Password",
        command=forgot_password
    ).pack(
        fill="x",
        pady=5
    )

    ttk.Button(
        frame,
        text="Exit",
        command=close_app
    ).pack(
        fill="x",
        pady=5
    )

    password_entry.bind(
        "<Return>",
        lambda _event:
            unlock()
    )

    password_entry.focus_set()

    bind_activity(
        root
    )


# ============================================================
# FORGOT PASSWORD INFORMATION
# ============================================================

def forgot_password():

    if not vault_exists():

        messagebox.showinfo(
            "No SecureVault",
            (
                "There is no SecureVault to recover.\n\n"
                "Click Create SecureVault to create one."
            ),
            parent=root
        )

        return

    if not recovery_meta_exists():

        messagebox.showerror(
            "Recovery Unavailable",
            (
                "This vault does not have recovery metadata.\n\n"
                "The existing vault cannot be recovered through "
                "the current recovery system."
            ),
            parent=root
        )

        return

    window = tk.Toplevel(
        root
    )

    window.title(
        "SecureVault Recovery"
    )

    window.geometry(
        "620x500"
    )

    window.resizable(
        False,
        False
    )

    window.transient(
        root
    )

    window.grab_set()

    frame = ttk.Frame(
        window,
        padding=30
    )

    frame.pack(
        fill="both",
        expand=True
    )

    ttk.Label(
        frame,
        text="Recover SecureVault",
        style="Title.TLabel"
    ).pack(
        pady=(5, 12)
    )

    ttk.Label(
        frame,
        text=(
            "SecureVault recovery uses two separate things:\n\n"
            "1. Reset Token — obtained from the recovery website\n"
            "2. Recovery Key — created when this vault was set up"
        ),
        justify="center"
    ).pack(
        pady=(0, 18)
    )

    email = get_recovery_email()

    ttk.Label(
        frame,
        text="Recovery email:"
    ).pack(
        anchor="w"
    )

    ttk.Label(
        frame,
        text=(
            email
            if email
            else "Unknown"
        ),
        font=(
            "Segoe UI",
            10,
            "bold"
        )
    ).pack(
        anchor="w",
        pady=(5, 14)
    )

    ttk.Label(
        frame,
        text=(
            "IMPORTANT\n\n"
            "If the vault is locked and the Recovery Key was "
            "never saved, the encrypted vault cannot be recovered."
        ),
        justify="center",
        wraplength=540
    ).pack(
        pady=12
    )

    def open_website():

        try:

            webbrowser.open(
                FORGOT_PASSWORD_URL
            )

        except Exception as exc:

            messagebox.showerror(
                "Could Not Open Website",
                str(exc),
                parent=window
            )

    ttk.Button(
        frame,
        text="Open Recovery Website",
        style="Primary.TButton",
        command=open_website
    ).pack(
        fill="x",
        pady=6
    )

    def continue_recovery():

        window.destroy()

        reset_password_dialog()

    ttk.Button(
        frame,
        text="I Have My Recovery Key",
        command=continue_recovery
    ).pack(
        fill="x",
        pady=6
    )

    ttk.Button(
        frame,
        text="Close",
        command=window.destroy
    ).pack(
        fill="x",
        pady=6
    )


# ============================================================
# HTTP JSON REQUEST
# ============================================================

def post_json(
    url,
    payload,
    timeout=20
):

    data = json.dumps(
        payload
    ).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type":
                "application/json",

            "Accept":
                "application/json"
        },
        method="POST"
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=timeout
        ) as response:

            raw = response.read().decode(
                "utf-8"
            )

            result = json.loads(
                raw
            )

            return (
                response.status,
                result
            )

    except urllib.error.HTTPError as exc:

        body = exc.read().decode(
            "utf-8",
            errors="replace"
        )

        try:

            result = json.loads(
                body
            )

        except Exception:

            result = {
                "error":
                    body
                    or str(exc)
            }

        return (
            exc.code,
            result
        )

    except urllib.error.URLError as exc:

        raise RuntimeError(
            "Could not connect to the SecureVault recovery server."
        ) from exc


# ============================================================
# RESET MASTER PASSWORD
# ============================================================

def reset_password_dialog():

    if not vault_exists():

        messagebox.showinfo(
            "No Vault",
            "No SecureVault exists on this PC.",
            parent=root
        )

        return

    if not recovery_meta_exists():

        messagebox.showerror(
            "Recovery Unavailable",
            (
                "Recovery metadata is missing.\n\n"
                "The existing vault cannot be recovered using "
                "the current recovery system."
            ),
            parent=root
        )

        return

    window = tk.Toplevel(
        root
    )

    window.title(
        "Reset Master Password"
    )

    window.geometry(
        "700x710"
    )

    window.resizable(
        False,
        False
    )

    window.transient(
        root
    )

    window.grab_set()

    frame = ttk.Frame(
        window,
        padding=30
    )

    frame.pack(
        fill="both",
        expand=True
    )

    ttk.Label(
        frame,
        text="Reset Master Password",
        style="Title.TLabel"
    ).pack(
        pady=(5, 10)
    )

    ttk.Label(
        frame,
        text=(
            "Complete email verification on the recovery website.\n"
            "Then paste the Reset Token and enter your Recovery Key."
        ),
        justify="center"
    ).pack(
        pady=(0, 20)
    )

    ttk.Label(
        frame,
        text="Reset Token"
    ).pack(
        anchor="w"
    )

    token_var = tk.StringVar()

    token_entry = ttk.Entry(
        frame,
        textvariable=token_var
    )

    token_entry.pack(
        fill="x",
        pady=(6, 16),
        ipady=8
    )

    ttk.Label(
        frame,
        text="Recovery Key"
    ).pack(
        anchor="w"
    )

    recovery_var = tk.StringVar()

    recovery_entry = ttk.Entry(
        frame,
        textvariable=recovery_var,
        show="•"
    )

    recovery_entry.pack(
        fill="x",
        pady=(6, 16),
        ipady=8
    )

    ttk.Label(
        frame,
        text="New Master Password"
    ).pack(
        anchor="w"
    )

    new_password_var = tk.StringVar()

    new_password_entry = ttk.Entry(
        frame,
        textvariable=new_password_var,
        show="•"
    )

    new_password_entry.pack(
        fill="x",
        pady=(6, 16),
        ipady=8
    )

    ttk.Label(
        frame,
        text="Confirm New Master Password"
    ).pack(
        anchor="w"
    )

    confirm_password_var = tk.StringVar()

    confirm_password_entry = ttk.Entry(
        frame,
        textvariable=confirm_password_var,
        show="•"
    )

    confirm_password_entry.pack(
        fill="x",
        pady=(6, 16),
        ipady=8
    )

    status_var = tk.StringVar()

    ttk.Label(
        frame,
        textvariable=status_var,
        wraplength=620,
        justify="center"
    ).pack(
        pady=14
    )

    def reset_password():

        token = (
            token_var.get()
            .strip()
        )

        entered_recovery_key = (
            recovery_var.get()
            .strip()
            .upper()
        )

        new_password = (
            new_password_var.get()
        )

        confirm_password = (
            confirm_password_var.get()
        )

        if not token:

            status_var.set(
                "Paste the Reset Token from the recovery website."
            )

            return

        if not entered_recovery_key:

            status_var.set(
                "Enter the Recovery Key."
            )

            return

        if len(new_password) < 10:

            status_var.set(
                "New master password must be at least 10 characters."
            )

            return

        if (
            new_password
            != confirm_password
        ):

            status_var.set(
                "The new master passwords do not match."
            )

            return

        try:

            status_var.set(
                "Checking Reset Token..."
            )

            window.update_idletasks()

            status, result = post_json(
                f"{BACKEND_URL}/validate-reset-token",
                {
                    "reset_token":
                        token
                }
            )

            if (
                status != 200
                or not result.get(
                    "success"
                )
            ):

                raise ValueError(
                    result.get(
                        "error",
                        "The Reset Token is invalid or expired."
                    )
                )

            server_email = str(
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
                or server_email
                != local_email
            ):

                raise ValueError(
                    "The Reset Token does not belong to this vault."
                )

            status_var.set(
                "Checking Recovery Key..."
            )

            window.update_idletasks()

            old_master_password = (
                recover_master_password(
                    entered_recovery_key
                )
            )

            status_var.set(
                "Decrypting your vault..."
            )

            window.update_idletasks()

            old_vault = load_vault(
                old_master_password
            )

            # Make a backup before changing the active vault.

            backup_path = make_backup()

            if not backup_path:

                raise ValueError(
                    "SecureVault could not create a backup before resetting the password."
                )

            old_vault["version"] = (
                APP_VERSION
            )

            old_vault[
                "email"
            ] = local_email

            old_vault[
                "recovery_key"
            ] = entered_recovery_key

            old_vault[
                "recovery_key_confirmed"
            ] = True

            global vault_data
            global master_password
            global recovery_key
            global last_activity

            vault_data = old_vault

            master_password = (
                new_password
            )

            recovery_key = (
                entered_recovery_key
            )

            save_vault(
                vault_data,
                master_password
            )

            create_recovery_metadata(
                local_email,
                recovery_key,
                master_password
            )

            last_activity = time.time()

            window.destroy()

            messagebox.showinfo(
                "Password Reset Complete",
                (
                    "Your SecureVault master password has been changed.\n\n"
                    "Your Recovery Key remains the same.\n\n"
                    f"A backup was created here:\n{backup_path}"
                ),
                parent=root
            )

            dashboard()

        except Exception as exc:

            status_var.set(
                str(exc)
            )

    ttk.Button(
        frame,
        text="Reset Master Password",
        style="Primary.TButton",
        command=reset_password
    ).pack(
        fill="x",
        pady=(10, 8)
    )

    ttk.Button(
        frame,
        text="Open Recovery Website",
        command=lambda:
            webbrowser.open(
                FORGOT_PASSWORD_URL
            )
    ).pack(
        fill="x",
        pady=5
    )

    ttk.Button(
        frame,
        text="Close",
        command=window.destroy
    ).pack(
        fill="x",
        pady=5
    )


# ============================================================
# DASHBOARD
# ============================================================

def dashboard():

    clear_root()

    set_window_title(
        "Dashboard"
    )

    root.geometry(
        "1000x650"
    )

    root.minsize(
        900,
        600
    )

    header = ttk.Frame(
        root,
        padding=(
            20,
            15
        )
    )

    header.pack(
        fill="x"
    )

    ttk.Label(
        header,
        text=(
            f"SecureVault V{APP_VERSION}"
        ),
        font=(
            "Segoe UI",
            20,
            "bold"
        )
    ).pack(
        side="left"
    )

    ttk.Button(
        header,
        text="🔑 Recovery Key",
        command=show_recovery_key_window
    ).pack(
        side="right",
        padx=4
    )

    ttk.Button(
        header,
        text="Check for Updates",
        command=check_for_updates_ui
    ).pack(
        side="right",
        padx=4
    )

    ttk.Button(
        header,
        text="Lock",
        command=lambda:
            lock_vault(
                silent=False
            )
    ).pack(
        side="right",
        padx=4
    )

    body = ttk.Frame(
        root,
        padding=20
    )

    body.pack(
        fill="both",
        expand=True
    )

    left = ttk.LabelFrame(
        body,
        text="Accounts",
        padding=12
    )

    left.pack(
        side="left",
        fill="both",
        expand=True,
        padx=(0, 10)
    )

    right = ttk.LabelFrame(
        body,
        text="Account Details",
        padding=16
    )

    right.pack(
        side="right",
        fill="both",
        expand=True,
        padx=(10, 0)
    )

    # ========================================================
    # TREE
    # ========================================================

    tree = ttk.Treeview(
        left,
        columns=(
            "site",
            "username"
        ),
        show="headings",
        height=22
    )

    tree.heading(
        "site",
        text="Website / Service"
    )

    tree.heading(
        "username",
        text="Username"
    )

    tree.column(
        "site",
        width=230
    )

    tree.column(
        "username",
        width=210
    )

    tree.pack(
        fill="both",
        expand=True
    )

    scrollbar = ttk.Scrollbar(
        left,
        orient="vertical",
        command=tree.yview
    )

    scrollbar.pack(
        side="right",
        fill="y"
    )

    tree.configure(
        yscrollcommand=scrollbar.set
    )

    # ========================================================
    # VARIABLES
    # ========================================================

    site_var = tk.StringVar()
    username_var = tk.StringVar()
    password_var = tk.StringVar()
    notes_var = tk.StringVar()

    # ========================================================
    # SITE
    # ========================================================

    ttk.Label(
        right,
        text="Website / Service"
    ).pack(
        anchor="w"
    )

    ttk.Entry(
        right,
        textvariable=site_var
    ).pack(
        fill="x",
        pady=(5, 14),
        ipady=7
    )

    # ========================================================
    # USERNAME
    # ========================================================

    ttk.Label(
        right,
        text="Username / Email"
    ).pack(
        anchor="w"
    )

    ttk.Entry(
        right,
        textvariable=username_var
    ).pack(
        fill="x",
        pady=(5, 14),
        ipady=7
    )

    # ========================================================
    # PASSWORD
    # ========================================================

    ttk.Label(
        right,
        text="Password"
    ).pack(
        anchor="w"
    )

    password_row = ttk.Frame(
        right
    )

    password_row.pack(
        fill="x",
        pady=(5, 14)
    )

    password_entry = ttk.Entry(
        password_row,
        textvariable=password_var,
        show="•"
    )

    password_entry.pack(
        side="left",
        fill="x",
        expand=True,
        ipady=7
    )

    show_password_var = tk.BooleanVar(
        value=False
    )

    def toggle_password():

        password_entry.config(
            show=(
                ""
                if show_password_var.get()
                else "•"
            )
        )

    ttk.Checkbutton(
        password_row,
        text="Show",
        variable=show_password_var,
        command=toggle_password
    ).pack(
        side="right",
        padx=(8, 0)
    )

    # ========================================================
    # NOTES
    # ========================================================

    ttk.Label(
        right,
        text="Notes"
    ).pack(
        anchor="w"
    )

    ttk.Entry(
        right,
        textvariable=notes_var
    ).pack(
        fill="x",
        pady=(5, 14),
        ipady=7
    )

    # ========================================================
    # ACCOUNT FUNCTIONS
    # ========================================================

    def get_selected_account():

        selection = tree.selection()

        if not selection:

            return None

        selected_id = str(
            selection[0]
        )

        for account in (
            vault_data.get(
                "accounts",
                []
            )
        ):

            if str(
                account.get(
                    "id"
                )
            ) == selected_id:

                return account

        return None

    def refresh_tree():

        for item in tree.get_children():

            tree.delete(
                item
            )

        for account in (
            vault_data.get(
                "accounts",
                []
            )
        ):

            tree.insert(
                "",
                "end",
                iid=str(
                    account[
                        "id"
                    ]
                ),
                values=(
                    account.get(
                        "site",
                        ""
                    ),
                    account.get(
                        "username",
                        ""
                    )
                )
            )

    def clear_details():

        global current_account_id

        current_account_id = None

        site_var.set("")
        username_var.set("")
        password_var.set("")
        notes_var.set("")

        show_password_var.set(
            False
        )

        password_entry.config(
            show="•"
        )

        for item in tree.selection():

            tree.selection_remove(
                item
            )

    def load_selected(
        _event=None
    ):

        global current_account_id

        account = (
            get_selected_account()
        )

        if not account:

            return

        current_account_id = str(
            account["id"]
        )

        site_var.set(
            account.get(
                "site",
                ""
            )
        )

        username_var.set(
            account.get(
                "username",
                ""
            )
        )

        password_var.set(
            account.get(
                "password",
                ""
            )
        )

        notes_var.set(
            account.get(
                "notes",
                ""
            )
        )

    def save_account():

        global current_account_id

        site = (
            site_var.get()
            .strip()
        )

        username = (
            username_var.get()
            .strip()
        )

        password = (
            password_var.get()
        )

        notes = (
            notes_var.get()
            .strip()
        )

        if not site:

            messagebox.showwarning(
                "Missing Website",
                "Enter the website or service.",
                parent=root
            )

            return

        if not password:

            messagebox.showwarning(
                "Missing Password",
                "Enter the password.",
                parent=root
            )

            return

        if current_account_id is None:

            account = {

                "id":
                    secrets.token_hex(
                        8
                    ),

                "site":
                    site,

                "username":
                    username,

                "password":
                    password,

                "notes":
                    notes
            }

            vault_data[
                "accounts"
            ].append(
                account
            )

            current_account_id = str(
                account["id"]
            )

        else:

            account = (
                get_selected_account()
            )

            if not account:

                return

            account["site"] = site
            account["username"] = username
            account["password"] = password
            account["notes"] = notes

        save_vault(
            vault_data,
            master_password
        )

        refresh_tree()

        try:

            tree.selection_set(
                current_account_id
            )

            tree.focus(
                current_account_id
            )

        except tk.TclError:

            pass

        messagebox.showinfo(
            "Saved",
            "Account saved securely.",
            parent=root
        )

    def delete_account():

        account = (
            get_selected_account()
        )

        if not account:

            messagebox.showwarning(
                "No Selection",
                "Select an account first.",
                parent=root
            )

            return

        answer = messagebox.askyesno(
            "Delete Account",
            (
                f"Delete '{account.get('site', '')}' "
                "from SecureVault?"
            ),
            parent=root
        )

        if not answer:

            return

        vault_data[
            "accounts"
        ] = [

            account_item

            for account_item
            in vault_data[
                "accounts"
            ]

            if str(
                account_item.get(
                    "id"
                )
            )
            != str(
                account.get(
                    "id"
                )
            )
        ]

        save_vault(
            vault_data,
            master_password
        )

        clear_details()

        refresh_tree()

    def copy_selected_password():

        account = (
            get_selected_account()
        )

        if not account:

            messagebox.showwarning(
                "No Selection",
                "Select an account first.",
                parent=root
            )

            return

        copy_to_clipboard(
            account.get(
                "password",
                ""
            )
        )

    tree.bind(
        "<<TreeviewSelect>>",
        load_selected
    )

    # ========================================================
    # BUTTONS
    # ========================================================

    button_frame = ttk.Frame(
        right
    )

    button_frame.pack(
        fill="x",
        pady=(18, 0)
    )

    ttk.Button(
        button_frame,
        text="New",
        command=clear_details
    ).grid(
        row=0,
        column=0,
        padx=4,
        pady=4,
        sticky="ew"
    )

    ttk.Button(
        button_frame,
        text="Save",
        style="Primary.TButton",
        command=save_account
    ).grid(
        row=0,
        column=1,
        padx=4,
        pady=4,
        sticky="ew"
    )

    ttk.Button(
        button_frame,
        text="Delete",
        command=delete_account
    ).grid(
        row=1,
        column=0,
        padx=4,
        pady=4,
        sticky="ew"
    )

    ttk.Button(
        button_frame,
        text="Copy Password",
        command=copy_selected_password
    ).grid(
        row=1,
        column=1,
        padx=4,
        pady=4,
        sticky="ew"
    )

    button_frame.columnconfigure(
        0,
        weight=1
    )

    button_frame.columnconfigure(
        1,
        weight=1
    )

    # ========================================================
    # PASSWORD GENERATOR
    # ========================================================

    generator = ttk.LabelFrame(
        right,
        text="Password Generator",
        padding=10
    )

    generator.pack(
        fill="x",
        pady=(25, 0)
    )

    length_var = tk.IntVar(
        value=20
    )

    generated_var = tk.StringVar()

    ttk.Label(
        generator,
        text="Length"
    ).grid(
        row=0,
        column=0,
        sticky="w"
    )

    ttk.Spinbox(
        generator,
        from_=8,
        to=64,
        textvariable=length_var,
        width=6
    ).grid(
        row=0,
        column=1,
        padx=8
    )

    ttk.Entry(
        generator,
        textvariable=generated_var,
        state="readonly"
    ).grid(
        row=1,
        column=0,
        columnspan=2,
        sticky="ew",
        pady=(10, 8)
    )

    def generate_password():

        try:

            length = int(
                length_var.get()
            )

        except (
            TypeError,
            ValueError
        ):

            length = 20

        length = max(
            8,
            min(
                64,
                length
            )
        )

        alphabet = (
            string.ascii_letters
            + string.digits
            + "!@#$%^&*()-_=+[]{}"
        )

        generated = "".join(
            secrets.choice(
                alphabet
            )
            for _ in range(length)
        )

        generated_var.set(
            generated
        )

        password_var.set(
            generated
        )

        show_password_var.set(
            False
        )

        password_entry.config(
            show="•"
        )

    generator_buttons = ttk.Frame(
        generator
    )

    generator_buttons.grid(
        row=2,
        column=0,
        columnspan=2,
        sticky="ew"
    )

    ttk.Button(
        generator_buttons,
        text="Generate",
        command=generate_password
    ).pack(
        side="left",
        fill="x",
        expand=True,
        padx=2
    )

    ttk.Button(
        generator_buttons,
        text="Copy",
        command=lambda:
            copy_to_clipboard(
                generated_var.get()
            )
    ).pack(
        side="left",
        fill="x",
        expand=True,
        padx=2
    )

    generator.columnconfigure(
        1,
        weight=1
    )

    refresh_tree()

    start_auto_lock_timer()

    bind_activity(
        root
    )


# ============================================================
# RECOVERY KEY WINDOW
# ============================================================

def show_recovery_key_window(
    parent=None
):

    parent = parent or root

    window = tk.Toplevel(
        parent
    )

    window.title(
        "SecureVault Recovery Key"
    )

    window.geometry(
        "620x340"
    )

    window.resizable(
        False,
        False
    )

    window.transient(
        parent
    )

    window.grab_set()

    frame = ttk.Frame(
        window,
        padding=30
    )

    frame.pack(
        fill="both",
        expand=True
    )

    ttk.Label(
        frame,
        text="YOUR RECOVERY KEY",
        font=(
            "Segoe UI",
            18,
            "bold"
        )
    ).pack(
        pady=(10, 8)
    )

    ttk.Label(
        frame,
        text=(
            "Save this key somewhere safe.\n"
            "SecureVault cannot display it while locked."
        ),
        justify="center"
    ).pack(
        pady=(0, 18)
    )

    key = (
        recovery_key
        or (
            vault_data.get(
                "recovery_key",
                ""
            )
            if vault_data
            else ""
        )
    )

    key_var = tk.StringVar(
        value=key
    )

    ttk.Entry(
        frame,
        textvariable=key_var,
        justify="center",
        font=(
            "Consolas",
            15,
            "bold"
        ),
        state="readonly"
    ).pack(
        fill="x",
        ipady=10,
        pady=8
    )

    ttk.Button(
        frame,
        text="Copy Recovery Key",
        command=lambda:
            copy_to_clipboard(
                key_var.get()
            )
    ).pack(
        pady=10
    )

    ttk.Button(
        frame,
        text="Close",
        command=window.destroy
    ).pack(
        pady=5
    )


# ============================================================
# LOCK
# ============================================================

def lock_vault(
    silent=False
):

    global vault_data
    global master_password
    global recovery_key
    global current_account_id

    vault_data = None
    master_password = None
    recovery_key = None
    current_account_id = None

    if not silent:

        login_screen()


def close_app():

    global vault_data
    global master_password
    global recovery_key

    vault_data = None
    master_password = None
    recovery_key = None

    try:

        root.destroy()

    except Exception:

        pass


# ============================================================
# GITHUB UPDATE SYSTEM
# ============================================================

def parse_version(
    version_text
):

    cleaned = (
        str(version_text)
        .strip()
        .lower()
    )

    if cleaned.startswith("v"):

        cleaned = cleaned[1:]

    parts = cleaned.split(
        "."
    )

    values = []

    for part in parts[:3]:

        digits = "".join(
            character
            for character
            in part
            if character.isdigit()
        )

        values.append(
            int(
                digits
                or 0
            )
        )

    while len(values) < 3:

        values.append(0)

    return tuple(
        values[:3]
    )


def is_newer_version(
    remote,
    local
):

    return (
        parse_version(remote)
        >
        parse_version(local)
    )


def sha256_file(
    path
):

    digest = hashlib.sha256()

    with open(
        path,
        "rb"
    ) as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:

                break

            digest.update(
                chunk
            )

    return digest.hexdigest()


def get_latest_release():

    request = urllib.request.Request(

        GITHUB_API_URL,

        headers={
            "Accept":
                "application/vnd.github+json",

            "User-Agent":
                "SecureVault-Updater"
        }
    )

    with urllib.request.urlopen(
        request,
        timeout=15
    ) as response:

        return json.loads(
            response.read().decode(
                "utf-8"
            )
        )


def run_updater_replace(
    current_exe,
    downloaded_exe
):

    current_pid = os.getpid()

    updater_script = f"""@echo off
setlocal

set "CURRENT={current_exe}"
set "NEW={downloaded_exe}"
set "PID={current_pid}"

:WAIT

tasklist /FI "PID eq %PID%" | find "%PID%" >nul

if not errorlevel 1 (
    timeout /t 1 /nobreak >nul
    goto WAIT
)

copy /Y "%NEW%" "%CURRENT%" >nul

if errorlevel 1 (
    exit /b 1
)

start "" "%CURRENT%"

del "%NEW%" >nul 2>&1

del "%~f0" >nul 2>&1
"""

    fd, script_path = tempfile.mkstemp(
        prefix="SecureVault_Update_",
        suffix=".cmd"
    )

    os.close(
        fd
    )

    with open(
        script_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            updater_script
        )

    subprocess.Popen(
        [
            "cmd.exe",
            "/c",
            script_path
        ],
        creationflags=getattr(
            subprocess,
            "CREATE_NO_WINDOW",
            0
        )
    )


def update_from_release(
    release
):

    if not getattr(
        sys,
        "frozen",
        False
    ):

        messagebox.showinfo(
            "Updater",
            (
                "Auto-update works only inside "
                "the compiled SecureVault.exe."
            ),
            parent=root
        )

        return

    assets = release.get(
        "assets",
        []
    )

    target = None

    for asset in assets:

        if asset.get(
            "name"
        ) == "SecureVault.exe":

            target = asset

            break

    if not target:

        raise RuntimeError(
            "The GitHub release does not contain SecureVault.exe."
        )

    current_exe = os.path.abspath(
        sys.executable
    )

    current_directory = os.path.dirname(
        current_exe
    )

    if not os.access(
        current_directory,
        os.W_OK
    ):

        raise RuntimeError(
            (
                "SecureVault cannot update because its folder "
                "is not writable."
            )
        )

    digest = str(
        target.get(
            "digest",
            ""
        )
    )

    temporary_exe = os.path.join(

        tempfile.gettempdir(),

        (
            "SecureVault_"
            + str(
                release.get(
                    "tag_name",
                    "latest"
                )
            )
            + ".exe"
        )
    )

    request = urllib.request.Request(

        target[
            "browser_download_url"
        ],

        headers={
            "User-Agent":
                "SecureVault-Updater"
        }
    )

    with urllib.request.urlopen(
        request,
        timeout=60
    ) as response:

        with open(
            temporary_exe,
            "wb"
        ) as file:

            while True:

                chunk = response.read(
                    1024 * 1024
                )

                if not chunk:

                    break

                file.write(
                    chunk
                )

    if digest.startswith(
        "sha256:"
    ):

        expected = digest.split(
            ":",
            1
        )[1].strip().lower()

        actual = sha256_file(
            temporary_exe
        )

        if actual != expected:

            try:

                os.unlink(
                    temporary_exe
                )

            except OSError:

                pass

            raise RuntimeError(
                "The downloaded update failed SHA-256 verification."
            )

    run_updater_replace(
        current_exe,
        temporary_exe
    )

    root.destroy()


def check_for_updates(
    silent=False
):

    try:

        release = get_latest_release()

        remote_version = (
            release.get(
                "tag_name"
            )
            or
            release.get(
                "name"
            )
            or
            ""
        )

        if not remote_version:

            raise RuntimeError(
                "GitHub returned a release without a version."
            )

        if not is_newer_version(
            remote_version,
            APP_VERSION
        ):

            if not silent:

                messagebox.showinfo(
                    "SecureVault Updater",
                    (
                        f"You already have the latest version.\n\n"
                        f"Current: V{APP_VERSION}"
                    ),
                    parent=root
                )

            return

        answer = messagebox.askyesno(
            "Update Available",
            (
                "A newer SecureVault version is available.\n\n"
                f"Current version: V{APP_VERSION}\n"
                f"New version: {remote_version}\n\n"
                "Download and install it now?"
            ),
            parent=root
        )

        if not answer:

            return

        update_from_release(
            release
        )

    except Exception as exc:

        if not silent:

            messagebox.showerror(
                "Update Error",
                str(exc),
                parent=root
            )


def check_for_updates_ui():

    def worker():

        try:

            release = get_latest_release()

            def show_result():

                try:

                    remote_version = (
                        release.get(
                            "tag_name"
                        )
                        or
                        release.get(
                            "name"
                        )
                        or
                        ""
                    )

                    if not remote_version:

                        raise RuntimeError(
                            "GitHub returned an invalid release."
                        )

                    if not is_newer_version(
                        remote_version,
                        APP_VERSION
                    ):

                        messagebox.showinfo(
                            "SecureVault Updater",
                            (
                                "You are already using the latest version.\n\n"
                                f"Version: V{APP_VERSION}"
                            ),
                            parent=root
                        )

                        return

                    answer = messagebox.askyesno(
                        "Update Available",
                        (
                            f"Current version: V{APP_VERSION}\n"
                            f"New version: {remote_version}\n\n"
                            "Install the new version?"
                        ),
                        parent=root
                    )

                    if answer:

                        update_from_release(
                            release
                        )

                except Exception as exc:

                    messagebox.showerror(
                        "Update Error",
                        str(exc),
                        parent=root
                    )

            root.after(
                0,
                show_result
            )

        except Exception as exc:

            root.after(
                0,
                lambda:
                    messagebox.showerror(
                        "Update Error",
                        str(exc),
                        parent=root
                    )
            )

    threading.Thread(
        target=worker,
        daemon=True
    ).start()


# ============================================================
# STARTUP
# ============================================================

def main():

    global root

    root = tk.Tk()

    root.protocol(
        "WM_DELETE_WINDOW",
        close_app
    )

    style_app()

    bind_activity(
        root
    )

    login_screen()

    # Background GitHub update check
    # only for the compiled EXE.

    if getattr(
        sys,
        "frozen",
        False
    ):

        def background_update():

            try:

                release = get_latest_release()

                remote_version = (
                    release.get(
                        "tag_name"
                    )
                    or
                    release.get(
                        "name"
                    )
                    or
                    ""
                )

                if (
                    remote_version
                    and is_newer_version(
                        remote_version,
                        APP_VERSION
                    )
                ):

                    root.after(
                        0,
                        lambda:
                            check_for_updates(
                                silent=True
                            )
                    )

            except Exception:

                pass

        root.after(
            5000,
            lambda:
                threading.Thread(
                    target=background_update,
                    daemon=True
                ).start()
        )

    root.mainloop()


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()
