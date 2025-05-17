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
    webhook_body = request.data
    print("📩 Raw webhook body:", webhook_body)  # See the full payload

    received_signature = request.headers.get('X-Razorpay-Signature')
    print("🔐 Received Signature:", received_signature)  # Log the signature

    try:
        expected_signature = hmac.new(
            key=bytes(RAZORPAY_WEBHOOK_SECRET, 'utf-8'),
            msg=webhook_body,
            digestmod=hashlib.sha256
        ).hexdigest()
        print("✅ Expected Signature:", expected_signature)

        if hmac.compare_digest(received_signature, expected_signature):
            data = json.loads(webhook_body)
            print("📦 Parsed JSON:", data)

            if data.get("event") == "payment.captured":
                payment_info = data["payload"]["payment"]["entity"]
                print("✅ Payment Captured:", payment_info)

            return "Webhook received", 200
        else:
            print("❌ Signature mismatch")
            abort(400, "Invalid signature")
    except Exception as e:
        print("🔥 Exception occurred:", str(e))
        abort(500, "Server error")

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
