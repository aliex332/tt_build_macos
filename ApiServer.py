from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__)

# File to store UDID data
UDID_FILE = 'udids.json'

# Unique password for verification
UNIQUE_PASSWORD = 'DsBFGjipgiOITESOj23r8238r3SEFNnfiyrpi@@oifse#'

# Shared encryption key (must be 32 bytes for AES-256)
ENCRYPTION_KEY = b"1l94u6ebs12p45h739w22p5v7la1s34b"

# Ensure the file exists
if not os.path.exists(UDID_FILE) or os.stat(UDID_FILE).st_size == 0:
    with open(UDID_FILE, 'w') as f:
        json.dump([], f)


def load_udids():
    """Load UDIDs from the file."""
    with open(UDID_FILE, 'r') as f:
        return json.load(f)


def save_udids(udids):
    """Save UDIDs to the file."""
    with open(UDID_FILE, 'w') as f:
        json.dump(udids, f, indent=4)


def encrypt_aes256(key, data):
    """Encrypt data using AES-256."""
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad data to match AES block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Return IV + encrypted data as base64
    return base64.b64encode(iv + encrypted_data).decode()

@app.route('/add', methods=['POST'])
def add_udid():
    try:
        # Extract data from the request
        data = request.get_json()
        if data is None:
            return jsonify({"error": "Request data must be JSON"}), 400

        # Check for the unique password
        password = data.get('password')
        if password != UNIQUE_PASSWORD:
            return '', 404

        udid = data.get('udid')
        days = data.get('days', 0)

        if not udid:
            return jsonify({"error": "UDID is required"}), 400

        if not isinstance(days, int) or days < 0:
            return jsonify({"error": "Days must be a non-negative integer"}), 400

        # Load existing UDIDs
        udid_storage = load_udids()
        for entry in udid_storage:
            if entry['udid'] == udid:
                # Check if future_date is in the past
                current_future_date = datetime.strptime(entry['future_date'], '%Y-%m-%d %H:%M:%S')
                current_time = datetime.now()

                if current_future_date < current_time:
                    # If expired, set future_date to now + days
                    updated_future_date = current_time + timedelta(days=days)
                else:
                    # Otherwise, extend existing future_date by days
                    updated_future_date = current_future_date + timedelta(days=days)

                # Update the future_date in the entry
                entry['future_date'] = updated_future_date.strftime('%Y-%m-%d %H:%M:%S')

                # Save the updated UDID list
                save_udids(udid_storage)
                return jsonify({"message": "UDID updated successfully", "data": entry}), 200

        # Record the UDID with the current date and time + days
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        future_date = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
        udid_entry = {
            "udid": udid,
            "timestamp": timestamp,
            "future_date": future_date
        }

        # Save the new UDID
        udid_storage.append(udid_entry)
        save_udids(udid_storage)

        return jsonify({"message": "UDID added successfully", "data": udid_entry}), 201

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/get', methods=['POST'])
def get_udid():
    try:
        # Extract data from the request
        data = request.get_json()
        if data is None:
            return jsonify({"error": "Request data must be JSON"}), 400

        udid = data.get('udid')
        if not udid:
            return jsonify({"error": "UDID is required"}), 400

        # Load existing UDIDs
        udid_storage = load_udids()

        # Check if UDID exists
        for entry in udid_storage:
            if entry['udid'] == udid:
                # Check future_date
                future_date_str = entry.get('future_date')
                if future_date_str:
                    future_date = datetime.strptime(future_date_str, '%Y-%m-%d %H:%M:%S')
                    current_date = datetime.now()

                    if future_date < current_date:
                        return jsonify({"error": "Date has expired"}), 405

                # Encrypt the response
                encrypted_message = encrypt_aes256(ENCRYPTION_KEY, udid)
                return jsonify({"message": encrypted_message}), 200

        return '', 404

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)