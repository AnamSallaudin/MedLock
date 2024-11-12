import os
import base64
import firebase_admin
from firebase_admin import credentials, firestore
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Initialize Firebase Admin SDK with credentials
cred = credentials.Certificate(r'C:\Users\Anam\Desktop\New folder\PYTHON\MedLock\medenc-d3b84-firebase-adminsdk-zs1n2-740e8714db.json')
firebase_admin.initialize_app(cred)

# Initialize Firestore client
db = firestore.client()

def retrieve_and_decrypt_private_key(doctor_id, password):
    # Fetch the encrypted key and salt from Firestore
    doc_ref = db.collection('doctor_keys').document(doctor_id)
    doc = doc_ref.get()
    if doc.exists:
        data = doc.to_dict()
        salt = base64.b64decode(data['salt'])
        encrypted_key = base64.b64decode(data['encrypted_key'])
        
        # Derive the AES key from the password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = kdf.derive(password.encode())

        # Decrypt the private key using AES-CBC
        iv = encrypted_key[:16]
        encrypted_content = encrypted_key[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_private_key = decryptor.update(encrypted_content) + decryptor.finalize()

        # Remove padding (assuming null-byte padding was used during encryption)
        decrypted_private_key = decrypted_private_key.rstrip(b'\0')
        return decrypted_private_key
    else:
        print("Doctor ID not found in Firestore.")
        return None

# Example usage:
doctor_id = 'doctor123'
decrypted_key = retrieve_and_decrypt_private_key(doctor_id, 'doctor_password')
if decrypted_key:
    with open("retrieved_private_key.pem", "wb") as f:
        f.write(decrypted_key)
    print("Private key successfully decrypted and saved.")
