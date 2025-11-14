import json
import os
from flask import Flask, request, jsonify
import secrets
from datetime import datetime, timedelta
from functools import wraps

# --- Configuration & Constants ---
# Admin password for creating keys (set via environment variable for security)
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')  # Change this!

# Initial valid keys
VALID_KEYS = {
    "ALL-TG-MOYE-MOYE": {
        "days": 30,
        "duration": "30 Days"
    },
    "KEY-USER-001": {
        "days": 365,
        "duration": "1 Year"
    },
    "MY-OWN-TEST-KEY": {
        "days": 7,
        "duration": "7 Days"
    },
    "vasanthtest": {
        "days": 365,
        "duration": "1 Year"
    }
}

# Dictionary to store key data
KEY_DATA = {}

# Blocked keys with reasons and timestamp
BLOCKED_KEYS = {}

# Statistics
STATS = {
    "total_active_users": 0,
    "total_expired_users": 0,
    "total_blocked_users": 0
}

# File paths for persistence on Render
DATA_FILE = '/tmp/key_data.json'
BLOCKED_FILE = '/tmp/blocked_keys.json'
VALID_KEYS_FILE = '/tmp/valid_keys.json'

# --------------------------------

app = Flask(__name__)

# --- Persistence Functions (for Render) ---
def load_data():
    """Load data from files if they exist"""
    global KEY_DATA, BLOCKED_KEYS, VALID_KEYS
    
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'r') as f:
                data = json.load(f)
                # Convert string dates back to datetime
                for key, val in data.items():
                    val['first_login'] = datetime.fromisoformat(val['first_login'])
                KEY_DATA = data
    except Exception as e:
        print(f"Error loading KEY_DATA: {e}")
    
    try:
        if os.path.exists(BLOCKED_FILE):
            with open(BLOCKED_FILE, 'r') as f:
                BLOCKED_KEYS = json.load(f)
    except Exception as e:
        print(f"Error loading BLOCKED_KEYS: {e}")
    
    try:
        if os.path.exists(VALID_KEYS_FILE):
            with open(VALID_KEYS_FILE, 'r') as f:
                VALID_KEYS = json.load(f)
    except Exception as e:
        print(f"Error loading VALID_KEYS: {e}")

def save_data():
    """Save data to files"""
    try:
        # Convert datetime to string for JSON serialization
        data_to_save = {}
        for key, val in KEY_DATA.items():
            data_to_save[key] = {
                'serial': val['serial'],
                'first_login': val['first_login'].isoformat(),
                'expire_timestamp': val['expire_timestamp']
            }
        
        with open(DATA_FILE, 'w') as f:
            json.dump(data_to_save, f)
        
        with open(BLOCKED_FILE, 'w') as f:
            json.dump(BLOCKED_KEYS, f)
        
        with open(VALID_KEYS_FILE, 'w') as f:
            json.dump(VALID_KEYS, f)
    except Exception as e:
        print(f"Error saving data: {e}")

# Load data on startup
load_data()

# --- Authentication Decorator ---
def require_admin_password(f):
    """Decorator to require admin password"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check password from header, query param, or form data
        password = (
            request.headers.get('X-Admin-Password') or 
            request.args.get('password') or 
            request.form.get('password') or
            (request.json.get('password') if request.is_json else None)
        )
        
        if password != ADMIN_PASSWORD:
            return jsonify({
                "status": 0,
                "message": "Unauthorized: Invalid admin password"
            }), 401
        
        return f(*args, **kwargs)
    return decorated

def update_statistics():
    """Update user statistics based on current data"""
    current_time = datetime.now()
    
    active = 0
    expired = 0
    
    for key, data in KEY_DATA.items():
        if key in BLOCKED_KEYS:
            continue
        
        expire_time = datetime.fromtimestamp(data['expire_timestamp'])
        if current_time < expire_time:
            active += 1
        else:
            expired += 1
    
    STATS['total_active_users'] = active
    STATS['total_expired_users'] = expired
    STATS['total_blocked_users'] = len(BLOCKED_KEYS)

@app.route('/')
def home():
    """Home page with API documentation"""
    return jsonify({
        "message": "Key Management API",
        "version": "2.0",
        "endpoints": {
            "authentication": "/api?user_key=KEY&serial=SERIAL",
            "admin": {
                "create_key": "/admin/create_key (POST with password)",
                "stats": "/admin/stats (GET with password)",
                "blocked": "/admin/blocked (GET with password)",
                "unblock": "/admin/unblock (POST with password)",
                "remove_key": "/admin/remove_key (POST with password)",
                "delete_key": "/admin/delete_key (POST with password)"
            }
        }
    })

@app.route('/api', methods=['GET', 'POST'])
def handle_api_request():
    
    # Get parameters from request
    game = request.args.get('game') or request.form.get('game')
    user_key = request.args.get('user_key') or request.form.get('user_key')
    serial = request.args.get('serial') or request.form.get('serial')
    
    # Check if all required parameters are present
    if not user_key:
        error_response = {
            "status": 0,
            "token": None,
            "expire": 0,
            "reason": "'user_key' parameter not found."
        }
        return jsonify(error_response), 400
    
    if not serial:
        error_response = {
            "status": 0,
            "token": None,
            "expire": 0,
            "reason": "'serial' parameter not found."
        }
        return jsonify(error_response), 400
    
    # Check if key is blocked
    if user_key in BLOCKED_KEYS:
        response_data = {
            "status": 0,
            "token": None,
            "expire": 0,
            "reason": f"Login failed: Key is blocked."
        }
        return jsonify(response_data), 403
    
    # Check if key is valid
    if user_key not in VALID_KEYS:
        response_data = {
            "status": 0,
            "token": None,
            "expire": 0,
            "reason": f"Login failed: Invalid key."
        }
        return jsonify(response_data), 401
    
    # Check serial number validation
    if user_key in KEY_DATA:
        # Key has been used before
        stored_data = KEY_DATA[user_key]
        stored_serial = stored_data['serial']
        
        if stored_serial != serial:
            # Different serial detected - BLOCK THE KEY
            BLOCKED_KEYS[user_key] = {
                "original_serial": stored_serial,
                "attempted_serial": serial,
                "blocked_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "reason": "Login attempt from different device"
            }
            
            # Save data
            save_data()
            
            # Update statistics
            update_statistics()
            
            response_data = {
                "status": 0,
                "token": None,
                "expire": 0,
                "reason": "Login failed: Key blocked due to suspicious activity."
            }
            return jsonify(response_data), 403
        else:
            # Check if key has expired
            current_time = datetime.now()
            expire_time = datetime.fromtimestamp(stored_data['expire_timestamp'])
            
            if current_time > expire_time:
                response_data = {
                    "status": 0,
                    "token": None,
                    "expire": stored_data['expire_timestamp'],
                    "reason": f"Login failed: Key has expired."
                }
                update_statistics()
                return jsonify(response_data), 403
    else:
        # First time login - register the key
        current_time = datetime.now()
        days_valid = VALID_KEYS[user_key]['days']
        expire_time = current_time + timedelta(days=days_valid)
        expire_timestamp = int(expire_time.timestamp())
        
        KEY_DATA[user_key] = {
            'serial': serial,
            'first_login': current_time,
            'expire_timestamp': expire_timestamp
        }
        
        # Save data
        save_data()
    
    # Login successful
    token = secrets.token_hex(16)
    exp_timestamp = KEY_DATA[user_key]['expire_timestamp']
    
    response_data = {
        "status": 1,
        "token": token,
        "expire": exp_timestamp,
        "reason": "Authentication successful"
    }
    
    # Update statistics
    update_statistics()
    
    return jsonify(response_data)

@app.route('/admin/create_key', methods=['POST'])
@require_admin_password
def create_key():
    """Create a new key with specified duration"""
    
    # Get parameters
    key_name = (
        request.args.get('key_name') or 
        request.form.get('key_name') or
        (request.json.get('key_name') if request.is_json else None)
    )
    
    days = (
        request.args.get('days') or 
        request.form.get('days') or
        (request.json.get('days') if request.is_json else None)
    )
    
    # Validate inputs
    if not key_name:
        return jsonify({ "status": 0,
            "message": "key_name parameter required"
        }), 400
    
    if not days:
        return jsonify({
            "status": 0,
            "message": "days parameter required"
        }), 400
    
    try:
        days = int(days)
        if days <= 0:
            raise ValueError("Days must be positive")
    except ValueError:
        return jsonify({
            "status": 0,
            "message": "days must be a positive integer"
        }), 400
    
    # Check if key already exists
    if key_name in VALID_KEYS:
        return jsonify({
            "status": 0,
            "message": f"Key '{key_name}' already exists"
        }), 409
    
    # Determine duration string
    if days == 1:
        duration = "1 Day"
    elif days == 7:
        duration = "7 Days"
    elif days == 30:
        duration = "30 Days"
    elif days == 365:
        duration = "1 Year"
    else:
        duration = f"{days} Days"
    
    # Create the key
    VALID_KEYS[key_name] = {
        "days": days,
        "duration": duration
    }
    
    # Save data
    save_data()
    
    return jsonify({
        "status": 1,
        "message": f"Key '{key_name}' created successfully",
        "key_details": {
            "key_name": key_name,
            "duration": duration,
            "days": days
        }
    })

@app.route('/admin/delete_key', methods=['POST'])
@require_admin_password
def delete_key():
    """Delete a key from VALID_KEYS (removes it from system entirely)"""
    
    key_name = (
        request.args.get('key_name') or 
        request.form.get('key_name') or
        (request.json.get('key_name') if request.is_json else None)
    )
    
    if not key_name:
        return jsonify({
            "status": 0,
            "message": "key_name parameter required"
        }), 400
    
    if key_name not in VALID_KEYS:
        return jsonify({
            "status": 0,
            "message": f"Key '{key_name}' not found in valid keys"
        }), 404
    
    # Remove from all dictionaries
    key_info = VALID_KEYS.pop(key_name)
    
    removed_from = ["valid_keys"]
    
    if key_name in KEY_DATA:
        KEY_DATA.pop(key_name)
        removed_from.append("active_data")
    
    if key_name in BLOCKED_KEYS:
        BLOCKED_KEYS.pop(key_name)
        removed_from.append("blocked_list")
    
    # Save data
    save_data()
    
    # Update statistics
    update_statistics()
    
    return jsonify({
        "status": 1,
        "message": f"Key '{key_name}' deleted successfully",
        "removed_from": removed_from,
        "key_info": key_info
    })

@app.route('/admin/stats', methods=['GET'])
@require_admin_password
def get_statistics():
    """Endpoint to view current statistics"""
    update_statistics()
    
    # Build detailed response
    active_keys = []
    expired_keys = []
    current_time = datetime.now()
    
    for key, data in KEY_DATA.items():
        if key in BLOCKED_KEYS:
            continue
        
        expire_time = datetime.fromtimestamp(data['expire_timestamp'])
        key_info = {
            "key": key,
            "serial": data['serial'],
            "first_login": data['first_login'].strftime('%Y-%m-%d %H:%M:%S'),
            "expires": expire_time.strftime('%Y-%m-%d %H:%M:%S'),
            "days_remaining": (expire_time - current_time).days if current_time < expire_time else 0
        }
        
        if current_time < expire_time:
            active_keys.append(key_info)
        else:
            expired_keys.append(key_info)
    
    blocked_list = []
    for key, block_info in BLOCKED_KEYS.items():
        blocked_list.append({
            "key": key,
            "original_serial": block_info['original_serial'],
            "attempted_serial": block_info['attempted_serial'],
            "blocked_time": block_info['blocked_time'],
            "reason": block_info['reason']
        })
    
    # List all valid keys
    valid_keys_list = []
    for key, info in VALID_KEYS.items():
        valid_keys_list.append({
            "key_name": key,
            "duration": info['duration'],
            "days": info['days']
        })
    
    return jsonify({
        "statistics": STATS,
        "total_valid_keys": len(VALID_KEYS),
        "valid_keys": valid_keys_list,
        "active_keys": active_keys,
        "expired_keys": expired_keys,
        "blocked_keys": blocked_list
    })

@app.route('/admin/blocked', methods=['GET'])
@require_admin_password
def get_blocked_keys():
    """Endpoint to view only blocked keys"""
    blocked_list = []
    for key, block_info in BLOCKED_KEYS.items():
        blocked_list.append({
            "key": key,
            "original_serial": block_info['original_serial'],
            "attempted_serial": block_info['attempted_serial'],
            "blocked_time": block_info['blocked_time'],
            "reason": block_info['reason']
        })
    
    return jsonify({
        "total_blocked": len(BLOCKED_KEYS),
        "blocked_keys": blocked_list
    })

@app.route('/admin/unblock', methods=['POST'])
@require_admin_password
def unblock_key():
    """Endpoint to unblock a key"""
    user_key = (
        request.args.get('user_key') or 
        request.form.get('user_key') or
        (request.json.get('user_key') if request.is_json else None)
    )
    
    if not user_key:
        return jsonify({
            "status": 0,
            "message": "user_key parameter required"
        }), 400
    
    if user_key not in BLOCKED_KEYS:
        return jsonify({
            "status": 0,
            "message": f"Key '{user_key}' is not blocked"
        }), 404
    
    # Remove from blocked list
    block_info = BLOCKED_KEYS.pop(user_key)
    
    # Save data
    save_data()
    
    # Update statistics
    update_statistics()
    
    return jsonify({
        "status": 1,
        "message": f"Key '{user_key}' has been unblocked successfully",
        "unblocked_info": block_info
    })

@app.route('/admin/remove_key', methods=['POST'])
@require_admin_password
def remove_key():
    """Endpoint to completely remove a key from active data and blocked list (but keeps in VALID_KEYS)"""
    user_key = (
        request.args.get('user_key') or 
        request.form.get('user_key') or
        (request.json.get('user_key') if request.is_json else None)
    )
    
    if not user_key:
        return jsonify({
            "status": 0,
            "message": "user_key parameter required"
        }), 400
    
    removed_from = []
    
    # Remove from KEY_DATA
    if user_key in KEY_DATA:
        KEY_DATA.pop(user_key)
        removed_from.append("active_data")
    
    # Remove from BLOCKED_KEYS
    if user_key in BLOCKED_KEYS:
        BLOCKED_KEYS.pop(user_key)
        removed_from.append("blocked_list")
    
    if not removed_from:
        return jsonify({
            "status": 0,
            "message": f"Key '{user_key}' not found in active data or blocked list"
        }), 404
    
    # Save data
    save_data()
    
    # Update statistics
    update_statistics()
    
    return jsonify({
        "status": 1,
        "message": f"Key '{user_key}' removed successfully (still exists in valid keys)",
        "removed_from": removed_from
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=False)


