import firebase_admin
from firebase_admin import credentials, firestore, storage
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
from flask import Flask, request, jsonify
from request_patient_record import request_patient_record
# Initialize Firebase Admin SDK (check if already initialized)
cred = credentials.Certificate(r'C:\Users\Anam\Desktop\New folder\PYTHON\MedLock\medenc-d3b84-firebase-adminsdk-zs1n2-740e8714db.json')

# Check if Firebase is already initialized
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred, {
        'storageBucket': 'medenc-d3b84.appspot.com'
    })
else:
    print("Firebase already initialized")

# Initialize Firestore client
db = firestore.client()

# Flask setup
app = Flask(__name__)

# Your existing functions (download_encrypted_pdf, request_patient_record)

@app.route('/requestRecord', methods=['POST'])
def request_record():
    # Get form data
    doctor_id = request.form.get('doctorId')
    patient_id = request.form.get('patientId')
    private_key = request.files.get('privateKey')

    # Check if the private key file exists
    if not private_key:
        return jsonify({'success': False, 'error': 'Private key file is missing'}), 400

    # Save the private key file temporarily
    private_key_path = os.path.join('uploads', private_key.filename)
    private_key.save(private_key_path)

    try:
        # Process the request using the private key and other details
        decrypted_pdf = request_patient_record(patient_id, private_key_path, doctor_id)

        if decrypted_pdf:
            return jsonify({'success': True, 'message': 'Record successfully requested'})
        else:
            return jsonify({'success': False, 'error': 'Failed to decrypt record'}), 500

    except Exception as e:
        # Return error details in JSON format
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
