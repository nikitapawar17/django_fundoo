import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# import logging
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


def send_mail(receiver_email, message):
    try:
        server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)

        context = ssl.create_default_context()
        server.starttls(context=context)  # Secure the connection
        server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
        server.sendmail(settings.EMAIL_HOST_USER, receiver_email, message)
        server.quit()
        logger.info("Email sent to ", receiver_email)

    except Exception as e:
        print(e)


def send_html_email(to_email, subject, html_message):
    message = MIMEMultipart("alternative")
    message["From"] = settings.EMAIL_HOST_USER
    message["To"] = to_email
    message["Subject"] = subject

    h = MIMEText(html_message, "html")
    message.attach(h)

    send_mail(to_email, message.as_string())
