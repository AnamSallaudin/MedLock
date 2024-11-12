import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PyPDF2 import PdfReader, PdfWriter
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as symmetric_padding
import tempfile
from firebase_admin import credentials, firestore, storage
import firebase_admin

# Initialize Firebase
def initialize_firebase():
    cred = credentials.Certificate(r'C:\Users\Anam\Desktop\New folder\PYTHON\MedLock\medenc-d3b84-firebase-adminsdk-zs1n2-740e8714db.json')
    firebase_admin.initialize_app(cred, {'storageBucket': 'medenc-d3b84.appspot.com'})

initialize_firebase()

# Email function to notify patient
def send_email_notification(patient_email, patient_name):
    smtp_port = 587
    smtp_server = "smtp.gmail.com"
    email_from = os.environ.get("EMAIL_ADDRESS")
    password = os.environ.get("EMAIL_PASSWORD")

    subject = "Your Medical Records Have Been Added"
    body = f"Dear {patient_name},\n\nYour medical records have been securely added to our system. Please contact your doctor for more details.\n\nBest Regards,\nMedLock Team"
    message = f"Subject: {subject}\n\n{body}"

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls(context=context)
            server.login(email_from, password)
            server.sendmail(email_from, patient_email, message)
        print(f"Email notification sent to {patient_email}")
    except Exception as e:
        print(f"Error sending email: {e}")

# Firestore function to store patient data
def store_patient_data(patient_id, name, email, encrypted_pdf_url, blood_test_type, encrypted_key):
    db = firestore.client()
    patient_data = {
        'patient_id': patient_id,
        'name': name,
        'email': email,
        'encrypted_pdf_url': encrypted_pdf_url,
        'blood_test_type': blood_test_type,
        'encrypted_key': encrypted_key
    }
    db.collection('patients').add(patient_data)
    print("Patient data stored in Firestore.")

    # Send email notification to the patient
    send_email_notification(email, name)



# Main function
def main():
    print("Program started.")
    
    # Generate AES key, load public key, and encrypt AES key
    key = os.urandom(32)
    with open('doctor_public_key.pem', 'rb') as pub_key_file:
        public_key = serialization.load_pem_public_key(pub_key_file.read(), backend=default_backend())
    encrypted_key = public_key.encrypt(
        key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Input patient details
    patient_id = input("Enter patient ID: ")
    name = input("Enter patient name: ")
    email = input("Enter patient email: ")

    # Blood test options
    blood_test_options = {
        1: "Complete Blood Count (CBC)",
        2: "Basic Metabolic Panel (BMP)",
        3: "Liver Function Test (LFT)",
        4: "Lipid Panel",
        5: "Thyroid Panel"
    }

    print("\nSelect a blood test type:")
    for option, test_name in blood_test_options.items():
        print(f"{option}. {test_name}")
    
    while True:
        try:
            blood_test_choice = int(input("Enter the number corresponding to the blood test type: "))
            if blood_test_choice in blood_test_options:
                blood_test_type = blood_test_options[blood_test_choice]
                break
            else:
                print("Invalid choice. Please enter a valid number.")
        except ValueError:
            print("Please enter a number.")

    input_pdf_path = input("Enter path to PDF file: ")

    # Encrypt PDF
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_pdf_path, 'rb') as file:
        pdf_reader = PdfReader(file)
        pdf_writer = PdfWriter()
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            for page in pdf_reader.pages:
                pdf_writer.add_page(page)
            pdf_writer.write(temp_file)
            temp_file.flush()
            temp_file.seek(0)
            pdf_buffer = temp_file.read()


 # Pad and encrypt the PDF content
    padder = symmetric_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(pdf_buffer) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_pdf_content = iv + encrypted_data

    # Save encrypted PDF
    encrypted_pdf_path = input_pdf_path.replace('.pdf', '_encrypted.pdf')
    with open(encrypted_pdf_path, 'wb') as enc_file:
        enc_file.write(encrypted_pdf_content)

    # Upload encrypted PDF to Firebase Storage
    bucket = storage.bucket()
    blob = bucket.blob(f'encrypted_reports/{patient_id}_med_report_encrypted.pdf')
    blob.upload_from_filename(encrypted_pdf_path)
    encrypted_pdf_url = blob.public_url

    # Store patient data and send email
    store_patient_data(patient_id, name, email, encrypted_pdf_url, blood_test_type, encrypted_key)
smtp_port = 587                 # Standard secure SMTP port
smtp_server = "smtp.gmail.com"  # Google SMTP Server

email_from = "iitbombaycse90@gmail.com"
email_to = "anam.mitmpl@gmail.com"
pswd = "ytuxeebrngblxcqd"

# Path to the private key file
private_key_file = r"C:\Users\Anam\Desktop\New folder\PYTHON\MedLock\doctor_private_key.pem"

# Create the email message
subject = "Your Private Key for MedLock"
body = "Dear Patient,\n\nPlease note that your medical records have been updated on our server.\n\nBest regards,\nMedLock Team"

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

if __name__ == "__main__":
    main()