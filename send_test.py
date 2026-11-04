
import smtplib
import ssl
from email.message import EmailMessage

# SMTP Configuration
SMTP_HOST = "app.biztechroadshow.com"
SMTP_PORT = 465

SMTP_USERNAME = "freya@biztechroadshow.com"
SMTP_PASSWORD = "Bcareful69!@"

SENDER_NAME = "Freya"
SENDER_EMAIL = SMTP_USERNAME

# Recipient
RECIPIENT = "s.m.serazummunir@gmail.com"



def send_email(recipient, subject, body):

    msg = EmailMessage()

    msg["From"] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
    msg["To"] = recipient
    msg["Subject"] = subject

    msg.set_content(body)

    context = ssl._create_unverified_context()

    try:
        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=30
        ) as server:

            server.login(SMTP_USERNAME, SMTP_PASSWORD)

            server.send_message(msg)

        print(f"[SUCCESS] Email sent to {recipient}")
        return True

    except Exception as e:
        print(f"[ERROR] {e}")
        return False



if __name__ == "__main__":

    subject = "A quick test email"

    body = """Hi,

I'm just testing my email sending setup.

I wanted to make sure everything is working correctly and that
emails are being delivered as expected.

No action is needed. Just a quick test.

Best regards,
Serazum
"""

    send_email(RECIPIENT, subject, body)
