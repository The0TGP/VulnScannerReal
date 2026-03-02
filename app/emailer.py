from mailjet_rest import Client

# Replace with your keys from https://app.mailjet.com/account/apikeys
MJ_APIKEY_PUBLIC = "6342f39dec0b4e73354e7cf37d05cde2"
MJ_APIKEY_PRIVATE = "b2a83917402a2145d2fd470667f70f71"
SENDER_EMAIL = "theopasisis1@gmail.com"

mailer = Client(auth=(MJ_APIKEY_PUBLIC, MJ_APIKEY_PRIVATE), version='v3.1')


def send_email(to, subject, message):
    data = {
        'Messages': [
            {
                "From": {
                    "Email": SENDER_EMAIL,
                    "Name": "VulnScanner"
                },
                "To": [
                    {
                        "Email": to
                    }
                ],
                "Subject": subject,
                "TextPart": message
            }
        ]
    }

    result = mailer.send.create(data=data)
    print("Mailjet response:", result.json())
