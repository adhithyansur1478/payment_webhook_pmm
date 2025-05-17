from flask import Flask, request, abort
import hmac
import hashlib
import json
import os

app = Flask(__name__)

# Razorpay webhook secret
RAZORPAY_WEBHOOK_SECRET = "your_webhook_secret"

@app.route('/webhook', methods=['POST'])
def webhook():
    try:
        webhook_body = request.data
        print("📩 Raw Webhook Body:", webhook_body)

        received_signature = request.headers.get('X-Razorpay-Signature')
        print("🔐 Received Signature:", received_signature)

        expected_signature = hmac.new(
            key=bytes(RAZORPAY_WEBHOOK_SECRET, 'utf-8'),
            msg=webhook_body,
            digestmod=hashlib.sha256
        ).hexdigest()
        print("✅ Expected Signature:", expected_signature)

        if not hmac.compare_digest(received_signature, expected_signature):
            print("❌ Signature mismatch")
            abort(400, "Invalid signature")

        data = json.loads(webhook_body)
        print("📦 Parsed Webhook Data:", data)

        event_type = data.get("event")
        print("🔔 Event Type:", event_type)

        if event_type == "payment.captured":
            payment_info = data["payload"]["payment"]["entity"]
            print("✅ Payment Captured:", json.dumps(payment_info, indent=2))
        else:
            print("ℹ️ Event not handled:", event_type)

        return "Webhook received", 200

    except Exception as e:
        print("🔥 Exception occurred:", str(e))
        abort(500, "Internal server error")

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
