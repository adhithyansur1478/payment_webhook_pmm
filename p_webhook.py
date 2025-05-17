from flask import Flask, request, abort
import hmac
import hashlib
import json

app = Flask(__name__)

# Razorpay webhook secret
RAZORPAY_WEBHOOK_SECRET = "your_webhook_secret"

@app.route('/webhook', methods=['POST'])
def webhook():
    webhook_body = request.data
    received_signature = request.headers.get('X-Razorpay-Signature')

    # Generate expected signature
    expected_signature = hmac.new(
        key=bytes(RAZORPAY_WEBHOOK_SECRET, 'utf-8'),
        msg=webhook_body,
        digestmod=hashlib.sha256
    ).hexdigest()

    # Compare signatures
    if hmac.compare_digest(received_signature, expected_signature):
        data = json.loads(webhook_body)

        if data.get("event") == "payment.captured":
            payment_info = data["payload"]["payment"]["entity"]
            print("✅ Payment Captured:", payment_info)
            # You can now log/store or trigger further actions

        return "Webhook received", 200
    else:
        abort(400, "Invalid signature")

if __name__ == '__main__':
    app.run(port=5000, debug=True)
