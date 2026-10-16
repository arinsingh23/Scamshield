from flask import Flask, request, jsonify, send_from_directory
import re

app = Flask(__name__, static_folder=".")

SCAM_RULES = {
    "OTP or verification code": [
        "otp", "one time password", "verification code"
    ],
    "Account or KYC pressure": [
        "kyc expired", "update kyc", "verify account",
        "account suspended", "account blocked"
    ],
    "Suspicious link": [
        "click here", "tap here", "http://", "https://", "www."
    ],
    "Urgent or threatening language": [
        "urgent", "immediately", "within 24 hours",
        "act now", "final warning", "you will be blocked"
    ],
    "Payment request": [
        "upi", "payment", "transfer money", "send money",
        "refund fee", "pay now", "processing fee"
    ],
    "Prize or reward claim": [
        "prize", "winner", "lottery", "claim now",
        "won a reward", "free gift"
    ],
    "Sensitive account details": [
        "password", "bank account", "card number", "cvv", "pin"
    ]
}


@app.route("/")
def home():
    return send_from_directory(".", "index.html")

@app.route("/protect_fixed.html")
def protect():
    return send_from_directory(".", "protect_fixed.html")
@app.route("/dashboard.html")
def dashboard():
    return send_from_directory(".", "dashboard.html")

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip().lower()

    if not message:
        return jsonify({"error": "Please enter a message."}), 400

    score = 0
    reasons = []

    points = {
        "OTP or verification code": 25,
        "Account or KYC pressure": 25,
        "Suspicious link": 20,
        "Urgent or threatening language": 15,
        "Payment request": 20,
        "Prize or reward claim": 20,
        "Sensitive account details": 25
    }

    for reason, terms in SCAM_RULES.items():
        if any(term in message for term in terms):
            score += points[reason]
            reasons.append(reason)

    score = min(score, 100)
    level = "High" if score >= 60 else "Medium" if score >= 30 else "Low"

    return jsonify({
        "score": score,
        "level": level,
        "suspicious": score >= 30,
        "reasons": reasons or ["No known demo rule matched."]
    })


if __name__ == "__main__":
    app.run(debug=True)