import os
import requests
from flask import Flask, request

app = Flask(__name__)

# Environment variables from Render dashboard
PAGE_ACCESS_TOKEN = os.getenv("PAGE_ACCESS_TOKEN")
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "my_verify_token")

HF_API_URL = os.getenv("HF_API_URL")  # Hugging Face model API URL
HF_TOKEN = os.getenv("HF_TOKEN")      # Hugging Face API key


@app.route("/webhook", methods=["GET"])
def verify():
    """Verification for Facebook Webhook"""
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        print("Webhook verified ✅")
        return challenge, 200
    print("Webhook verification failed ❌")
    return "Verification failed", 403


@app.route("/webhook", methods=["POST"])
def webhook():
    """Handle incoming messages"""
    data = request.get_json()
    print("Incoming webhook:", data)

    if "entry" in data:
        for entry in data["entry"]:
            for event in entry.get("messaging", []):
                if "message" in event:
                    sender_id = event["sender"]["id"]
                    user_message = event["message"].get("text", "")

                    print(f"User({sender_id}) said: {user_message}")

                    # Call HF model for phishing scan
                    result = run_scanner(user_message)
                    print(f"Scanner result: {result}")

                    # Reply to Messenger
                    send_message(sender_id, f"Scan Result: {result}")

    return "EVENT_RECEIVED", 200


def send_message(recipient_id, text):
    """Send message back to Messenger"""
    url = "https://graph.facebook.com/v20.0/me/messages"
    params = {"access_token": PAGE_ACCESS_TOKEN}
    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": text}
    }
    try:
        response = requests.post(url, params=params, json=payload, timeout=10)
        if response.status_code != 200:
            print(f"Failed to send message: {response.status_code} {response.text}")
    except Exception as e:
        print(f"Error sending message: {e}")


def run_scanner(message):
    """Call Hugging Face API to scan message"""
    if not HF_API_URL or not HF_TOKEN:
        return "Scanner not configured. Missing HF_API_URL or HF_TOKEN."

    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    payload = {"inputs": message}

    try:
        response = requests.post(HF_API_URL, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            result = response.json()

            # Handle classification result
            if isinstance(result, list) and len(result) > 0:
                label = result[0].get("label", "unknown")
                score = result[0].get("score", 0)
                return f"{label.upper()} (confidence: {score:.2f})"

            return str(result)

        return f"Error: HF API returned {response.status_code} {response.text}"
    except Exception as e:
        return f"Error calling scanner: {str(e)}"


@app.route("/health", methods=["GET"])
def health():
    """Health check for Render"""
    return "OK", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)