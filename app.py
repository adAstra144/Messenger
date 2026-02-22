import os
import requests
from flask import Flask, request, jsonify
from threading import Thread
from analyze import analyze_pipeline

app = Flask(__name__)

# ====== Messenger config ======
PAGE_ACCESS_TOKEN = os.getenv("PAGE_ACCESS_TOKEN")
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "my_verify_token")

# ====== Hugging Face config ======
HF_API_URL = os.getenv(
    "HF_API_URL",
    "https://router.huggingface.co/hf-inference/models/ealvaradob/bert-finetuned-phishing"
)
HF_TOKEN = os.getenv("HF_TOKEN")


# ====== Messenger Webhook ======
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
                if "message" in event and "text" in event["message"]:
                    sender_id = event["sender"]["id"]
                    user_message = event["message"]["text"]

                    # Run message handling in a separate thread
                    Thread(target=handle_message, args=(sender_id, user_message)).start()

    # Return 200 immediately so FB doesn't retry
    return "EVENT_RECEIVED", 200


# ====== Message Handling ======
def handle_message(sender_id, user_message):
    try:
        analysis = analyze_pipeline(user_message)
        if analysis.get("blacklist"):
            result = phishing_reply()
        elif analysis.get("whitelist"):
            result = safe_reply()
        else:
            result = run_scanner(user_message)
    except Exception as e:
        result = f"Error processing message: {str(e)}"

    send_message(sender_id, result)


# ====== Replies ======
def phishing_reply():
    return (
        f"🚨 Phishing\n"
        f"Confidence: 100.0%\n\n"
        f"⚠️ This message contains a phishing link.\n\n"
        f"👉 What to do: Do not reply, share personal details, or click any links/attachments.\n\n"
        f"🛡️ Best action: ignore, delete, or report it.\n\n"
        f"🔒 How to avoid phishing:\n"
        f"• Check the sender’s email/number carefully.\n"
        f"• Watch for spelling mistakes or odd grammar.\n"
        f"• Don’t trust urgent scare tactics like “act now”.\n"
        f"• Use official apps or websites instead of in-message links."
    )


def safe_reply():
    return (
        f"✅ Safe\n"
        f"Confidence: 100.0%\n\n"
        f"✅ This message appears safe.\n\n"
        f"👉 What to do: You can continue normally, but stay alert for anything unusual.\n\n"
        f"💡 Safety tips:\n"
        f"• Double-check the sender/source if unsure.\n"
        f"• Be careful with unexpected links or files.\n"
        f"• Keep your device and security tools updated.\n"
        f"• When in doubt, verify through official channels."
    )


# ====== Messenger Send API ======
def send_message(recipient_id, text):
    url = "https://graph.facebook.com/v20.0/me/messages"
    params = {"access_token": PAGE_ACCESS_TOKEN}
    payload = {"recipient": {"id": recipient_id}, "message": {"text": text}}
    headers = {"Content-Type": "application/json"}

    try:
        resp = requests.post(url, params=params, headers=headers, json=payload)
        print(f"Send API response: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"Error sending message: {str(e)}")


# ====== Hugging Face Fallback ======
def run_scanner(message):
    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    payload = {"inputs": message}

    try:
        response = requests.post(HF_API_URL, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            result = response.json()
            while isinstance(result, list) and len(result) > 0 and isinstance(result[0], list):
                result = result[0]

            if isinstance(result, list) and len(result) > 0:
                top = max(result, key=lambda x: x.get("score", 0))
                label = top.get("label", "Unknown")
                confidence = round(top.get("score", 0) * 100, 2)

                if label.lower() == "phishing":
                    return phishing_reply()
                else:
                    return safe_reply()
            return f"Unexpected HF response: {result}"
        else:
            return f"HF API error {response.status_code}: {response.text}"
    except Exception as e:
        return f"Error calling HF API: {str(e)}"


# ====== Health Check ======
@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "ok", "message": "Messenger phishing scanner is running"})


# ====== Run App (Render-friendly) ======
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)