import smtplib
from email.mime.text import MIMEText

def send_email(subject, body, sender, receiver, password):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = receiver
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.sendmail(sender, receiver, msg.as_string())
        print("✅ Mail sent.")
        return True
    except Exception as e:
        print("❌ Mail could not be sent:", e)
        return False
