python


import os
from mailjet_rest import Client
# Environment variables (Render)
MJ_APIKEY_PUBLIC = os.getenv("6342f39dec0b4e73354e7cf37d05cde2")
MJ_APIKEY_PRIVATE = os.getenv("b2a83917402a2145d2fd470667f70f71")
SENDER_EMAIL = os.getenv("theopasisis1@gmail.com")
mailer = Client(auth=(MJ_APIKEY_PUBLIC, MJ_APIKEY_PRIVATE), version='v3.1')
def send_email(to, subject, text_message, html_message=None):
    if html_message is None:
        html_message = f"<pre>{text_message}</pre>"
    data = {
        "Messages": [
            {
                "From": {
                    "Email": SENDER_EMAIL,
                    "Name": "VulnScanner"
                },
                "To": [{"Email": to}],
                "Subject": subject,
                "TextPart": text_message,
                "HTMLPart": html_message,
                "CustomID": "VulnScannerEmail"
            }
        ]
    }
    try:
        result = mailer.send.create(data=data)
        print("Mailjet response:", result.json())
        return result.json()
    except Exception as e:
        print("❌ Mailjet error:", str(e))
        return {"Error": str(e)}
