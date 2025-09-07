import os
import requests
from flask import Flask, request

app = Flask(__name__)

PAGE_ACCESS_TOKEN = os.getenv("PAGE_ACCESS_TOKEN")
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "my_verify_token")

HF_API_URL = os.getenv("HF_API_URL")  # your Hugging Face model API URL
HF_TOKEN = os.getenv("HF_TOKEN")      # your HF API key

@app.route("/webhook", methods=["GET"])
def verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        return challenge, 200
    return "Verification failed", 403

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json()
    if "entry" in data:
        for entry in data["entry"]:
            for event in entry.get("messaging", []):
                if "message" in event:
                    sender_id = event["sender"]["id"]
                    user_message = event["message"].get("text", "")

                    # Call HF model for phishing scan
                    result = run_scanner(user_message)

                    # Reply to Messenger
                    send_message(sender_id, f"Scan Result: {result}")

    return "EVENT_RECEIVED", 200

def send_message(recipient_id, text):
    url = "https://graph.facebook.com/v20.0/me/messages"
    params = {"access_token": PAGE_ACCESS_TOKEN}
    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": text}
    }
    requests.post(url, params=params, json=payload)

def run_scanner(message):
    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    payload = {"inputs": message}
    try:
        response = requests.post(HF_API_URL, headers=headers, json=payload)
        if response.status_code == 200:
            return response.json()
        return "Error: Scanner unavailable."
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
