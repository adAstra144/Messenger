import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# ====== Messenger config ======
PAGE_ACCESS_TOKEN = os.getenv("PAGE_ACCESS_TOKEN")  # From Meta Developer portal
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "my_verify_token")  # You choose this

# ====== Hugging Face config ======
HF_API_URL = os.getenv("HF_API_URL", "https://api-inference.huggingface.co/models/ealvaradob/bert-finetuned-phishing")
HF_TOKEN = os.getenv("HF_TOKEN")  # Your Hugging Face API key


# ====== Messenger Webhook ======
@app.route("/webhook", methods=["GET"])
def verify():
    """Webhook verification (for Messenger setup)"""
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        return challenge, 200
    return "Verification failed", 403


@app.route("/webhook", methods=["POST"])
def webhook():
    """Handle incoming Messenger messages"""
    data = request.get_json()
    app.logger.info(f"Incoming webhook: {data}")

    if "entry" in data:
        for entry in data["entry"]:
            for event in entry.get("messaging", []):
                if "message" in event and "text" in event["message"]:
                    sender_id = event["sender"]["id"]
                    user_message = event["message"]["text"]

                    app.logger.info(f"User({sender_id}) said: {user_message}")

                    # Run Hugging Face phishing scanner
                    result = run_scanner(user_message)
                    app.logger.info(f"Scanner result: {result}")

                    # Send reply to Messenger
                    send_message(sender_id, f"Scan Result: {result}")

    return "EVENT_RECEIVED", 200


# ====== Helper functions ======
def send_message(recipient_id, text):
    """Send a text message to Messenger user"""
    url = "https://graph.facebook.com/v20.0/me/messages"
    params = {"access_token": PAGE_ACCESS_TOKEN}
    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": text}
    }
    headers = {"Content-Type": "application/json"}
    requests.post(url, params=params, headers=headers, json=payload)


def run_scanner(message):
    """Send user message to Hugging Face phishing model"""
    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    payload = {"inputs": message}

    try:
        response = requests.post(HF_API_URL, headers=headers, json=payload)
        if response.status_code == 200:
            result = response.json()

            # Unwrap if nested (e.g. [[...]])
            while isinstance(result, list) and len(result) > 0 and isinstance(result[0], list):
                result = result[0]

            # Now result should be a list of dicts
            if isinstance(result, list) and len(result) > 0:
                top = max(result, key=lambda x: x.get("score", 0))
                label = top.get("label", "Unknown")
                confidence = round(top.get("score", 0) * 100, 2)
                return f"{label} ({confidence}%)"

            return f"Unexpected response: {result}"

        return f"Error: HF API returned {response.status_code} - {response.text}"

    except Exception as e:
        return f"Error calling scanner: {str(e)}"


# ====== Health Check ======
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "ok",
        "message": "Messenger phishing scanner is running"
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
