import base64
import binascii  # Import binascii module for error handling
import firebase_admin
from firebase_admin import credentials, firestore, storage
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as symmetric_padding

# Function to handle base64 decoding with padding fix
def safe_b64decode(b64_string):
    """Decode base64 with padding fix."""
    # Add padding to base64 string if missing
    missing_padding = len(b64_string) % 4
    if missing_padding:
        b64_string += '=' * (4 - missing_padding)
    
    try:
        return base64.b64decode(b64_string)
    except binascii.Error:
        # Silently ignore any errors here and return None
        return None

# Function to request and decrypt patient data
def request_patient_data(patient_id, private_key_path, doctor_id):
    # Initialize Firebase
    initialize_firebase()
    
    # Get Firestore client
    db = firestore.client()
    
    # Retrieve patient record from Firestore
    patient_ref = db.collection('patients').document(patient_id)
    patient_data = patient_ref.get().to_dict()
    
    if patient_data is None:
        print(f"Error: No data found for patient with ID {patient_id}")
        return
    
    # Check if the required fields exist
    if 'encrypted_key' not in patient_data or 'encrypted_pdf_url' not in patient_data:
        print(f"Error: Missing encrypted data for patient with ID {patient_id}")
        return
    
    # Get the encrypted AES key and handle padding
    encrypted_aes_key = patient_data['encrypted_key']
    
    # Attempt to decode the base64-encoded AES key using safe_b64decode
    encrypted_aes_key = safe_b64decode(encrypted_aes_key)
    if encrypted_aes_key is None:
        return
    
    # Load the private key for the doctor
    private_key = load_private_key(private_key_path)
    
    # Decrypt the AES key using the doctor's private RSA key
    aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
    
    # Download the encrypted PDF file
    encrypted_pdf_url = patient_data['encrypted_pdf_url']
    encrypted_pdf_data = download_encrypted_pdf(encrypted_pdf_url)
    
    # Decrypt the PDF content using the AES key
    decrypted_pdf_data = decrypt_pdf(encrypted_pdf_data, aes_key)
    
    # Save the decrypted PDF to a file
    decrypted_pdf_path = f"decrypted_{patient_id}_medical_report.pdf"
    try:
        with open(decrypted_pdf_path, 'wb') as pdf_file:
            pdf_file.write(decrypted_pdf_data)
        print(f"Decrypted PDF saved as: {decrypted_pdf_path}")
    except Exception as e:
        print(f"Error saving decrypted PDF: {e}")

# Firebase initialization
def initialize_firebase():
    cred = credentials.Certificate(r'C:\Users\Anam\Desktop\New folder\PYTHON\MedLock\medenc-d3b84-firebase-adminsdk-zs1n2-740e8714db.json')  # Update with your path
    firebase_admin.initialize_app(cred, {
        'storageBucket': 'your-storage-bucket-name.appspot.com'  # Update with your bucket name
    })
    print("Firebase initialized.")

# Get doctor's private key from a file
def load_private_key(private_key_path):
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    return private_key

# Function to decrypt AES key using RSA private key
def decrypt_aes_key(encrypted_aes_key, private_key):
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

# Function to decrypt the PDF file
def decrypt_pdf(encrypted_pdf_data, aes_key):
    iv = encrypted_pdf_data[:16]  # The first 16 bytes are the IV (Initialization Vector)
    encrypted_data = encrypted_pdf_data[16:]  # The rest is the actual encrypted data
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = symmetric_padding.PKCS7(algorithms.AES.block_size).unpadder()
    pdf_data = unpadder.update(padded_data) + unpadder.finalize()
    
    return pdf_data

# Function to download encrypted PDF from Firebase Storage
def download_encrypted_pdf(encrypted_pdf_url):
    bucket = storage.bucket()
    blob = bucket.blob(encrypted_pdf_url.replace("https://storage.googleapis.com/your-storage-bucket-name.appspot.com/", ""))
    encrypted_pdf_data = blob.download_as_bytes()
    return encrypted_pdf_data

# Request inputs from the doctor
patient_id = input("Enter the patient ID: ")
private_key_path = input("Enter the path to your private key file: ")
doctor_id = input("Enter your doctor ID: ")

# Request and decrypt patient data
request_patient_data(patient_id, private_key_path, doctor_id)
print(f"Fetching data from patient {patient_id}",)
print("decrypted file saved")