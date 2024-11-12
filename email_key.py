import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

smtp_port = 587                 # Standard secure SMTP port
smtp_server = "smtp.gmail.com"  # Google SMTP Server

email_from = "iitbombaycse90@gmail.com"
email_to = "anam.mitmpl@gmail.com"
pswd = "ytuxeebrngblxcqd"

# Path to the private key file
private_key_file = r"C:\Users\Anam\Desktop\New folder\PYTHON\MedLock\doctor_private_key.pem"

# Create the email message
subject = "Your Private Key for MedLock"
body = "Dear Doctor,\n\nPlease find attached your private key for the MedLock system.\n\nBest regards,\nMedLock Team"

# Setting up MIME
msg = MIMEMultipart()
msg['From'] = email_from
msg['To'] = email_to
msg['Subject'] = subject
msg.attach(MIMEText(body, 'plain'))

# Attach the private key file
try:
    with open(private_key_file, 'rb') as attachment:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename="{private_key_file.split('/')[-1]}"'
        )
        msg.attach(part)
except FileNotFoundError:
    print(f"Error: The file '{private_key_file}' was not found.")
    exit(1)

# Disable SSL verification
context = ssl._create_unverified_context()

try:
    print("Connecting to server...")
    TIE_server = smtplib.SMTP(smtp_server, smtp_port)
    TIE_server.ehlo()
    TIE_server.starttls(context=context)  # Use the unverified context
    TIE_server.login(email_from, pswd)
    print("Connected to server :-)")

    # Send the email with the attachment
    print(f"Sending email to - {email_to}")
    TIE_server.sendmail(email_from, email_to, msg.as_string())
    print(f"Email successfully sent to - {email_to}")

except smtplib.SMTPAuthenticationError:
    print("Failed to authenticate with the SMTP server. Check your email or app-specific password.")
except smtplib.SMTPConnectError:
    print("Failed to connect to the SMTP server. Ensure that your network allows SMTP connections.")
except smtplib.SMTPException as e:
    print(f"An SMTP error occurred: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")

finally:
    try:
        if TIE_server:
            TIE_server.quit()
    except smtplib.SMTPServerDisconnected:
        print("SMTP server already disconnected.")
