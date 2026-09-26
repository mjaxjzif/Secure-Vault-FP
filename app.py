import os
import ssl
import smtplib
import secrets
import hashlib
import hmac

from email.message import EmailMessage
from flask import Flask, request, jsonify
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

app = Flask(__name__)

# ============================================================
# ENVIRONMENT VARIABLES
# ============================================================

GMAIL_ADDRESS = os.environ.get("GMAIL_ADDRESS", "").strip()
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "").strip()
RESET_SECRET = os.environ.get("RESET_SECRET", "").strip()

# How long different tokens remain valid
CODE_VALID_SECONDS = 10 * 60       # 10 minutes
RESET_TOKEN_VALID_SECONDS = 15 * 60  # 15 minutes


# ============================================================
# TOKEN HELPERS
# ============================================================

def get_serializer():
    if not RESET_SECRET:
        return None

    return URLSafeTimedSerializer(
        RESET_SECRET,
        salt="securevault-recovery"
    )


def make_code_hash(email, code):
    """
    Uses RESET_SECRET as a secret key so the 6-digit code
    cannot simply be guessed from the challenge data.
    """
    message = f"{email.lower()}:{code}".encode("utf-8")

    return hmac.new(
        RESET_SECRET.encode("utf-8"),
        message,
        hashlib.sha256
    ).hexdigest()


# ============================================================
# EMAIL
# ============================================================

def send_recovery_email(destination, code):
    if not GMAIL_ADDRESS or not GMAIL_APP_PASSWORD:
        raise RuntimeError(
            "GMAIL_ADDRESS or GMAIL_APP_PASSWORD is not configured."
        )

    msg = EmailMessage()
    msg["Subject"] = "SecureVault Recovery Code"
    msg["From"] = GMAIL_ADDRESS
    msg["To"] = destination

    msg.set_content(
        f"""SecureVault Recovery

Your recovery verification code is:

{code}

This code expires in 10 minutes.

If you did not request SecureVault account recovery, you can ignore this email.
"""
    )

    context = ssl.create_default_context()

    # Gmail supports smtp.gmail.com on port 465 with SSL.
    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465,
        context=context,
        timeout=20
    ) as smtp:

        smtp.login(
            GMAIL_ADDRESS,
            GMAIL_APP_PASSWORD
        )

        smtp.send_message(msg)


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "server": "SecureVault Recovery Server",
        "gmail_configured": bool(GMAIL_ADDRESS and GMAIL_APP_PASSWORD),
        "reset_secret_configured": bool(RESET_SECRET)
    })


# ============================================================
# SEND RECOVERY CODE
# ============================================================

@app.route("/send-code", methods=["POST"])
def send_code():
    try:
        if not RESET_SECRET:
            return jsonify({
                "success": False,
                "error": "Recovery server is not configured."
            }), 500

        if not GMAIL_ADDRESS or not GMAIL_APP_PASSWORD:
            return jsonify({
                "success": False,
                "error": "Gmail recovery email is not configured."
            }), 500

        data = request.get_json(silent=True) or {}

        email = str(data.get("email", "")).strip().lower()

        if not email or "@" not in email:
            return jsonify({
                "success": False,
                "error": "Please enter a valid email address."
            }), 400

        # Generate a 6-digit code
        code = f"{secrets.randbelow(1000000):06d}"

        # Create a secret hash of the code
        code_hash = make_code_hash(email, code)

        serializer = get_serializer()

        challenge = serializer.dumps({
            "purpose": "email_verification",
            "email": email,
            "code_hash": code_hash
        })

        # Send the actual code
        send_recovery_email(email, code)

        return jsonify({
            "success": True,
            "message": "Recovery code sent.",
            "challenge": challenge
        })

    except smtplib.SMTPAuthenticationError:
        return jsonify({
            "success": False,
            "error": "Gmail authentication failed. Check your Gmail App Password."
        }), 500

    except smtplib.SMTPException as e:
        return jsonify({
            "success": False,
            "error": f"Gmail could not send the email: {str(e)}"
        }), 500

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ============================================================
# VERIFY RECOVERY CODE
# ============================================================

@app.route("/verify-code", methods=["POST"])
def verify_code():
    try:
        if not RESET_SECRET:
            return jsonify({
                "success": False,
                "error": "Recovery server is not configured."
            }), 500

        data = request.get_json(silent=True) or {}

        email = str(data.get("email", "")).strip().lower()
        code = str(data.get("code", "")).strip()
        challenge = str(data.get("challenge", "")).strip()

        if not email or not code or not challenge:
            return jsonify({
                "success": False,
                "error": "Missing email, code, or verification challenge."
            }), 400

        serializer = get_serializer()

        try:
            payload = serializer.loads(
                challenge,
                max_age=CODE_VALID_SECONDS
            )
        except SignatureExpired:
            return jsonify({
                "success": False,
                "error": "The verification code has expired. Request a new one."
            }), 400
        except BadSignature:
            return jsonify({
                "success": False,
                "error": "Invalid verification request."
            }), 400

        # Verify the challenge purpose
        if payload.get("purpose") != "email_verification":
            return jsonify({
                "success": False,
                "error": "Invalid verification request."
            }), 400

        # Verify email
        stored_email = str(payload.get("email", "")).lower()

        if not hmac.compare_digest(stored_email, email):
            return jsonify({
                "success": False,
                "error": "Email does not match the verification request."
            }), 400

        # Calculate what the hash should be
        expected_hash = make_code_hash(email, code)
        stored_hash = str(payload.get("code_hash", ""))

        if not hmac.compare_digest(expected_hash, stored_hash):
            return jsonify({
                "success": False,
                "error": "Incorrect recovery code."
            }), 400

        # Code verified.
        # Create a short-lived reset token.
        reset_token = serializer.dumps({
            "purpose": "password_reset",
            "email": email,
            "nonce": secrets.token_urlsafe(24)
        })

        return jsonify({
            "success": True,
            "message": "Recovery code verified.",
            "email": email,
            "reset_token": reset_token
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ============================================================
# VALIDATE RESET TOKEN
# ============================================================

@app.route("/validate-reset-token", methods=["POST"])
def validate_reset_token():
    try:
        if not RESET_SECRET:
            return jsonify({
                "success": False,
                "error": "Recovery server is not configured."
            }), 500

        data = request.get_json(silent=True) or {}

        reset_token = str(data.get("reset_token", "")).strip()

        if not reset_token:
            return jsonify({
                "success": False,
                "error": "Reset token is missing."
            }), 400

        serializer = get_serializer()

        try:
            payload = serializer.loads(
                reset_token,
                max_age=RESET_TOKEN_VALID_SECONDS
            )
        except SignatureExpired:
            return jsonify({
                "success": False,
                "error": "The reset token has expired. Start recovery again."
            }), 400
        except BadSignature:
            return jsonify({
                "success": False,
                "error": "Invalid reset token."
            }), 400

        if payload.get("purpose") != "password_reset":
            return jsonify({
                "success": False,
                "error": "Invalid reset token."
            }), 400

        email = str(payload.get("email", "")).strip().lower()

        if not email:
            return jsonify({
                "success": False,
                "error": "Reset token contains no email."
            }), 400

        return jsonify({
            "success": True,
            "email": email,
            "message": "Reset token is valid."
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ============================================================
# ROOT
# ============================================================

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "name": "SecureVault Recovery Server",
        "status": "online",
        "endpoints": [
            "/health",
            "/send-code",
            "/verify-code",
            "/validate-reset-token"
        ]
    })


# ============================================================
# VERCEL / LOCAL
# ============================================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
