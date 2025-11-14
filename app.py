#!/usr/bin/env python3
import hashlib
import base64
import json
import time
from urllib.parse import parse_qs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from flask import Flask, request, Response

# --- Initialize the Flask App ---
app = Flask(__name__)

# --- AES Configuration (Must match the client) ---
KEY = b"KPBXFY9Q6WUJ8345"
IV = b"1FPR3J5MLDCWAVTE"

def compute_token(user_key: str, serial: str, game: str = "PUBGNR", suffix: str = "FractionLoader123") -> str:
    """Calculates the MD5 hash of a formatted string."""
    final_string = f"{game}-{user_key}-{serial}-{suffix}"
    return hashlib.md5(final_string.encode('utf-8')).hexdigest()

def generate_encrypted_string(request_string: str) -> tuple[bool, str]:
    """
    Parses the request data, creates the encrypted response, and returns a status and the final string.
    """
    # 1. Parse the request string to get user_key and serial
    try:
        parsed_data = parse_qs(request_string)
        if 'user_key' not in parsed_data or 'serial' not in parsed_data:
            raise KeyError("Missing user_key or serial")
        user_key = parsed_data['user_key'][0]
        serial = parsed_data['serial'][0]
    except (KeyError, IndexError):
        error_msg = "Error: Malformed request. Ensure 'user_key' and 'serial' are present."
        app.logger.error(f"{error_msg} - Input: {request_string}")
        return False, error_msg

    # 2. Generate the MD5 token
    new_token = compute_token(user_key, serial)

    # 3. Use the fixed expiration date: November 30, 2025
    exp_string = "2025-11-30 23:59:59"

    # 4. Get the current Unix timestamp for the RNG check
    current_timestamp = int(time.time())

    # 5. Construct the JSON data payload
    response_data = {
        "status": True,
        "data": {
            "modname": "MOD NAME",
            "mod_status": "MOD STATUS - SAFE",
            "credit": "FLOATING TEXT",
            "token": new_token,
            "device": "10000",
            "EXP": exp_string,
            "rng": current_timestamp
        }
    }
    json_string = json.dumps(response_data)

    # --- Encryption Process ---
    inner_base64 = base64.b64encode(json_string.encode('utf-8'))
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded_data = pad(inner_base64, AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_data)
    final_output = base64.b64encode(encrypted_bytes).decode('utf-8')
    
    app.logger.info(f"Successfully processed request for user_key: {user_key}")
    return True, final_output

# --- API Endpoint Definition ---

@app.route('/', methods=['POST'])
def handle_request():
    """
    Main endpoint that accepts a raw query string in the POST body
    and returns the raw encrypted string as the response.
    """
    # Get the entire request body as a single string
    request_data = request.get_data(as_text=True)

    if not request_data:
        return Response("Error: Request body is empty.", status=400, mimetype='text/plain')

    # Generate the encrypted response
    success, result = generate_encrypted_string(request_data)

    if success:
        # If successful, return the raw encrypted string with a 200 OK status
        return Response(result, status=200, mimetype='text/plain')
    else:
        # If there was an error (e.g., bad input), return the error message with a 400 Bad Request status
        return Response(result, status=400, mimetype='text/plain')

# --- Main execution block (for local testing) ---
if __name__ == "__main__":
    # To test locally, you would run this script and then use a tool like curl
    # Example: curl -X POST -H "Content-Type: text/plain" --data "game=PUBGNR&user_key=test&serial=123" http://127.0.0.1:5000
    app.run(host='0.0.0.0', port=5000, debug=True)
