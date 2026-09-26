import os
import time
import secrets
import hmac
import hashlib
import base64
import json
import smtplib

from pathlib import Path
from email.message import EmailMessage

from flask import Flask, request, jsonify, send_file


BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)


GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS", "")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "")
RESET_SECRET = os.getenv("RESET_SECRET", "")


def create_challenge(email, code):
    payload = {
        "email": email,
        "code_hash": hashlib.sha256(
            code.encode("utf-8")
        ).hexdigest(),
        "expires": int(time.time()) + 600
    }

    raw = json.dumps(
        payload,
        separators=(",", ":")
    ).encode("utf-8")

    encoded = base64.urlsafe_b64encode(
        raw
    ).decode("utf-8")

    signature = hmac.new(
        RESET_SECRET.encode("utf-8"),
        encoded.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return encoded + "." + signature


def verify_challenge(token, email, code):
    try:
        encoded, signature = token.split(".", 1)

        expected_signature = hmac.new(
            RESET_SECRET.encode("utf-8"),
            encoded.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(
            signature,
            expected_signature
        ):
            return False

        raw = base64.urlsafe_b64decode(
            encoded.encode("utf-8")
        )

        payload = json.loads(
            raw.decode("utf-8")
        )

        if payload.get("email") != email:
            return False

        if int(time.time()) > int(
            payload.get("expires", 0)
        ):
            return False

        entered_hash = hashlib.sha256(
            code.encode("utf-8")
        ).hexdigest()

        return hmac.compare_digest(
            entered_hash,
            payload.get("code_hash", "")
        )

    except Exception:
        return False


def send_verification_email(recipient, code):
    if not GMAIL_ADDRESS:
        raise RuntimeError(
            "GMAIL_ADDRESS is not configured."
        )

    if not GMAIL_APP_PASSWORD:
        raise RuntimeError(
            "GMAIL_APP_PASSWORD is not configured."
        )

    message = EmailMessage()

    message["Subject"] = (
        "SecureVault Password Reset Code"
    )

    message["From"] = GMAIL_ADDRESS
    message["To"] = recipient

    message.set_content(
        "SecureVault Password Reset\n\n"
        "Your verification code is:\n\n"
        f"{code}\n\n"
        "This code expires in 10 minutes.\n\n"
        "If you did not request a password reset, "
        "you can ignore this email.\n\n"
        "— VaultSecure"
    )

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465,
        timeout=20
    ) as smtp:
        smtp.login(
            GMAIL_ADDRESS,
            GMAIL_APP_PASSWORD
        )

        smtp.send_message(message)


@app.route("/")
def home():
    return send_file(
        BASE_DIR / "index.html"
    )


@app.route("/forgot-password.html")
def forgot_password_page():
    return send_file(
        BASE_DIR / "forgot-password.html"
    )


@app.route("/health")
def health():
    return jsonify({
        "success": True,
        "message": "VaultSecure server is running."
    })


@app.route("/send-code", methods=["POST"])
def send_code():

    if not RESET_SECRET:
        return jsonify({
            "success": False,
            "message": "Recovery server is not configured."
        }), 500

    data = request.get_json(
        silent=True
    )

    if not data:
        return jsonify({
            "success": False,
            "message": "Invalid request."
        }), 400

    email = str(
        data.get("email", "")
    ).strip().lower()

    if not email:
        return jsonify({
            "success": False,
            "message": "Email is required."
        }), 400

    if "@" not in email:
        return jsonify({
            "success": False,
            "message": "Enter a valid email address."
        }), 400

    code = f"{secrets.randbelow(1000000):06d}"

    try:
        send_verification_email(
            email,
            code
        )

        challenge = create_challenge(
            email,
            code
        )

        return jsonify({
            "success": True,
            "message": "Verification code sent.",
            "challenge": challenge
        })

    except Exception as error:
        print("Email error:", repr(error))

        return jsonify({
            "success": False,
            "message": "Could not send verification email."
        }), 500


@app.route("/verify-code", methods=["POST"])
def verify_code():

    data = request.get_json(
        silent=True
    )

    if not data:
        return jsonify({
            "success": False,
            "message": "Invalid request."
        }), 400

    email = str(
        data.get("email", "")
    ).strip().lower()

    code = str(
        data.get("code", "")
    ).strip()

    challenge = str(
        data.get("challenge", "")
    ).strip()

    if not email or not code or not challenge:
        return jsonify({
            "success": False,
            "message": "Email, code and challenge are required."
        }), 400

    if len(code) != 6 or not code.isdigit():
        return jsonify({
            "success": False,
            "message": "The code must contain 6 digits."
        }), 400

    if verify_challenge(
        challenge,
        email,
        code
    ):
        return jsonify({
            "success": True,
            "message": "Verification successful."
        })

    return jsonify({
        "success": False,
        "message": "Invalid or expired verification code."
    }), 400


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
