import os
import requests
from flask import Flask, request, jsonify
from threading import Thread

app = Flask(__name__)

# ====== Messenger config ======
PAGE_ACCESS_TOKEN = os.getenv("PAGE_ACCESS_TOKEN")
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "my_verify_token")

# ====== Hugging Face config ======
HF_API_URL = os.getenv(
    "HF_API_URL",
    "https://api-inference.huggingface.co/models/ealvaradob/bert-finetuned-phishing",
)
HF_TOKEN = os.getenv("HF_TOKEN")


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

    try:
        response = requests.post(url, params=params, headers=headers, json=payload)
        print("Send API response:", response.status_code, response.text)
        if response.status_code != 200:
            print("Error sending message:", response.text)
    except Exception as e:
        print("Exception sending message:", e)


def run_scanner(message):
    """Send user message to Hugging Face phishing model"""
    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    payload = {"inputs": message}

    try:
        response = requests.post(HF_API_URL, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            result = response.json()
            
            # Unwrap nested list if needed
            while isinstance(result, list) and len(result) > 0 and isinstance(result[0], list):
                result = result[0]

            if isinstance(result, list) and len(result) > 0:
                top = max(result, key=lambda x: x.get("score", 0))
                label = top.get("label", "Unknown")
                confidence = round(top.get("score", 0) * 100, 2)

                if label.lower() == "phishing":
                    return (
                        f"🚨 Phishing\nConfidence: {confidence}%\n\n"
                        "⚠️ This message looks suspicious. Do NOT reply or click links.\n"
                        "🛡️ Best action: ignore, delete, or report it."
                    )
                else:
                    return (
                        f"✅ Safe\nConfidence: {confidence}%\n\n"
                        "This message appears safe. Stay alert for anything unusual."
                    )

            return f"Unexpected response: {result}"
        else:
            return f"HF API error {response.status_code}: {response.text}"

    except Exception as e:
        return f"Error calling HF API: {e}"


def handle_message(sender_id, user_message):
    """Run HF scan and send reply in a thread"""
    result = run_scanner(user_message)
    send_message(sender_id, result)


# ====== Messenger Webhook ======
@app.route("/webhook", methods=["GET"])
def verify():
    """Webhook verification"""
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

                    # Run in a thread to avoid blocking FB webhook
                    Thread(target=handle_message, args=(sender_id, user_message)).start()

    # Always return 200 immediately
    return "EVENT_RECEIVED", 200


# ====== Health Check ======
@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "ok", "message": "Messenger phishing scanner is running"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
