import os
import requests
from flask import Flask, request

app = Flask(__name__)

PAGE_ACCESS_TOKEN = os.getenv("PAGE_ACCESS_TOKEN")
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "my_verify_token")

HF_API_URL = os.getenv("HF_API_URL")  # Hugging Face model API URL
HF_TOKEN = os.getenv("HF_TOKEN")      # Hugging Face API key


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
                    send_message(sender_id, result)

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
            result = response.json()

            # Handle HF returning list of predictions
            if isinstance(result, list) and len(result) > 0:
                top = max(result, key=lambda x: x.get("score", 0))
                label = top.get("label", "Unknown").lower()
                confidence = round(top.get("score", 0) * 100, 2)

                if "phish" in label:  # format phishing message
                    return (
                        f"🚨 Phishing\n"
                        f"Confidence: {confidence}%\n"
                        f"⚠️ This message looks suspicious and may be a phishing attempt.\n\n"
                        f"👉 What to do: Do not reply, share personal details, or click any links/attachments.\n\n"
                        f"🛡️ Best action: ignore, delete, or report it.\n\n"
                        f"🔒 How to avoid phishing:\n"
                        f"• Check the sender’s email/number carefully.\n"
                        f"• Watch for spelling mistakes or odd grammar.\n"
                        f"• Don’t trust urgent scare tactics like “act now”.\n"
                        f"• Use official apps or websites instead of in-message links."
                    )
                else:  # format safe message
                    return (
                        f"✅ Safe\n"
                        f"Confidence: {confidence}%\n"
                        f"✅ This message appears safe.\n\n"
                        f"👉 What to do: You can continue normally, but stay alert for anything unusual.\n\n"
                        f"💡 Safety tips:\n"
                        f"• Double-check the sender/source if unsure.\n"
                        f"• Be careful with unexpected links or files.\n"
                        f"• Keep your device and security tools updated.\n"
                        f"• When in doubt, verify through official channels."
                    )

            return str(result)

        return f"Error: HF API returned {response.status_code} - {response.text}"

    except Exception as e:
        return f"Error: {str(e)}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
