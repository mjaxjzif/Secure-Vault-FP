import os
import secrets
import time
import smtplib
from email.message import EmailMessage

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

verification_codes = {}


def send_verification_email(recipient, code):
    message = EmailMessage()
    message["Subject"] = "SecureVault Password Reset Code"
    message["From"] = GMAIL_ADDRESS
    message["To"] = recipient

    message.set_content(
        "SecureVault Password Reset\n\n"
        "Your verification code is:\n\n"
        + code
        + "\n\n"
        "This code expires in 10 minutes.\n\n"
        "If you did not request a password reset, you can ignore this email.\n\n"
        "— VaultSecure"
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
        smtp.send_message(message)


@app.route("/")
def home():
    return jsonify({
        "success": True,
        "message": "SecureVault server is running."
    })


@app.route("/send-code", methods=["POST"])
def send_code():
    data = request.get_json()

    if not data or not data.get("email"):
        return jsonify({
            "success": False,
            "message": "Email is required"
        }), 400

    email = data["email"].strip().lower()

    code = f"{secrets.randbelow(1000000):06d}"

    verification_codes[email] = {
        "code": code,
        "expires": time.time() + 600
    }

    try:
        send_verification_email(email, code)

        return jsonify({
            "success": True,
            "message": "Verification code sent"
        })

    except Exception as e:
        print("Email error:", e)
        verification_codes.pop(email, None)

        return jsonify({
            "success": False,
            "message": "Could not send verification email"
        }), 500


@app.route("/verify-code", methods=["POST"])
def verify_code():
    data = request.get_json()

    if not data or not data.get("email") or not data.get("code"):
        return jsonify({
            "success": False,
            "message": "Email and verification code are required"
        }), 400

    email = data["email"].strip().lower()
    entered_code = data["code"].strip()

    saved = verification_codes.get(email)

    if not saved:
        return jsonify({
            "success": False,
            "message": "No verification code found"
        }), 400

    if time.time() > saved["expires"]:
        verification_codes.pop(email, None)

        return jsonify({
            "success": False,
            "message": "Verification code expired"
        }), 400

    if not secrets.compare_digest(entered_code, saved["code"]):
        return jsonify({
            "success": False,
            "message": "Invalid verification code"
        }), 400

    verification_codes.pop(email, None)

    return jsonify({
        "success": True,
        "message": "Verification successful"
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)