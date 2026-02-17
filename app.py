from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import os
import json
import base64
import datetime
import sqlite3
import struct
import glob
import secrets
from werkzeug.utils import secure_filename
import time

from modules.Decryptor import Decryptor
from modules.pypush_gsa_icloud import icloud_login_mobileme, generate_anisette_headers
import requests

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = 'keys'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024  # 16KB max file size

def decode_tag(data):
    """Decode location data from encrypted payload"""
    latitude = struct.unpack(">i", data[0:4])[0] / 10000000.0
    longitude = struct.unpack(">i", data[4:8])[0] / 10000000.0
    confidence = int.from_bytes(data[8:9], 'big')
    status = int.from_bytes(data[9:10], 'big')
    return {'lat': latitude, 'lon': longitude, 'conf': confidence, 'status': status}

def init_db():
    """Initialize SQLite database"""
    db_path = os.path.join(app.config['UPLOAD_FOLDER'], 'reports.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS reports (
        id_short TEXT, timestamp INTEGER, datePublished INTEGER, payload TEXT, 
        id TEXT, statusCode INTEGER, lat TEXT, lon TEXT, conf INTEGER, 
        PRIMARY KEY(id_short, timestamp))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS device_names (
        device_id TEXT PRIMARY KEY,
        custom_name TEXT NOT NULL)''')
    conn.commit()
    conn.close()

def get_device_name(device_id):
    """Get custom name for a device, or return original name"""
    db_path = os.path.join(app.config['UPLOAD_FOLDER'], 'reports.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT custom_name FROM device_names WHERE device_id = ?', (device_id,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else device_id

def set_device_name(device_id, custom_name):
    """Set custom name for a device"""
    db_path = os.path.join(app.config['UPLOAD_FOLDER'], 'reports.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO device_names (device_id, custom_name) VALUES (?, ?)',
                   (device_id, custom_name))
    conn.commit()
    conn.close()

def get_auth_credentials():
    """Get authentication credentials from session or file"""
    auth_path = os.path.join(app.config['UPLOAD_FOLDER'], 'auth.json')
    
    if os.path.exists(auth_path):
        with open(auth_path, 'r') as f:
            auth_data = json.load(f)
            # Check if auth is still valid (less than 24 hours old)
            if 'timestamp' in auth_data:
                age = time.time() - auth_data['timestamp']
                if age < 86400:  # 24 hours
                    return (auth_data['dsid'], auth_data['searchPartyToken'])
    return None

def save_auth_credentials(dsid, token):
    """Save authentication credentials"""
    auth_path = os.path.join(app.config['UPLOAD_FOLDER'], 'auth.json')
    auth_data = {
        'dsid': dsid,
        'searchPartyToken': token,
        'timestamp': time.time()
    }
    with open(auth_path, 'w') as f:
        json.dump(auth_data, f)

def authenticate_icloud(username, password, second_factor='trusted_device'):
    """Authenticate with iCloud and save credentials"""
    try:
        mobileme = icloud_login_mobileme(username, password, second_factor)
        dsid = mobileme['dsid']
        token = mobileme['delegates']['com.apple.mobileme']['service-data']['tokens']['searchPartyToken']
        save_auth_credentials(dsid, token)
        return True, "Authentication successful"
    except Exception as e:
        return False, str(e)

def load_key_files():
    """Load all .keys files and return device info"""
    privkeys = {}
    names = {}
    
    for keyfile in glob.glob(os.path.join(app.config['UPLOAD_FOLDER'], '*.keys')):
        with open(keyfile) as f:
            hashed_adv = priv = ''
            name = os.path.basename(keyfile)[:-5]
            
            for line in f:
                key = line.rstrip('\n').split(': ')
                if key[0] == 'Private key':
                    priv = key[1]
                elif key[0] == 'Hashed adv key':
                    hashed_adv = key[1]
            
            if priv and hashed_adv:
                privkeys[hashed_adv] = priv
                names[hashed_adv] = name
    
    return privkeys, names

def fetch_location_reports(hours=24):
    """Fetch location reports from Apple's servers"""
    auth = get_auth_credentials()
    if not auth:
        return {'error': 'Not authenticated', 'status': 401}
    
    privkeys, names = load_key_files()
    
    if not names:
        return {'error': 'No key files found', 'status': 404}
    
    unix_epoch = int(datetime.datetime.now().timestamp())
    start_date = unix_epoch - (60 * 60 * hours)
    
    data = {
        "search": [{
            "startDate": start_date * 1000,
            "endDate": unix_epoch * 1000,
            "ids": list(names.keys())
        }]
    }
    
    try:
        r = requests.post(
            "https://gateway.icloud.com/acsnservice/fetch",
            auth=auth,
            headers=generate_anisette_headers(),
            json=data,
            timeout=10
        )
        
        if r.status_code == 401:
            return {'error': 'Authentication expired', 'status': 401}
        
        if r.status_code != 200:
            return {'error': f'Server returned {r.status_code}', 'status': r.status_code}
        
        results = json.loads(r.content.decode())['results']
        
        # Process and decrypt reports
        locations = []
        db_path = os.path.join(app.config['UPLOAD_FOLDER'], 'reports.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        for report in results:
            try:
                priv = int.from_bytes(base64.b64decode(privkeys[report['id']]), byteorder='big')
                payload = base64.b64decode(report['payload'])
                timestamp = int.from_bytes(payload[0:4], 'big') + 978307200
                
                if timestamp >= start_date:
                    decryptor = Decryptor(payload, priv)
                    decrypted = decryptor.Decrypt()
                    tag = decode_tag(decrypted)
                    
                    location = {
                        'key': get_device_name(names[report['id']]),
                        'original_key': names[report['id']],
                        'lat': tag['lat'],
                        'lon': tag['lon'],
                        'conf': tag['conf'],
                        'status': tag['status'],
                        'timestamp': timestamp,
                        'datetime': datetime.datetime.fromtimestamp(timestamp).isoformat(),
                        'google_maps': f"https://maps.google.com/maps?q={tag['lat']},{tag['lon']}"
                    }
                    locations.append(location)
                    
                    # Save to database
                    query = "INSERT OR REPLACE INTO reports VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                    params = (
                        names[report['id']], timestamp, report['datePublished'],
                        report['payload'], report['id'], report['statusCode'],
                        str(tag['lat']), str(tag['lon']), tag['conf']
                    )
                    cursor.execute(query, params)
            except Exception as e:
                print(f"Error processing report: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        # Sort by timestamp
        locations.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return {
            'status': 200,
            'count': len(locations),
            'locations': locations
        }
        
    except Exception as e:
        return {'error': str(e), 'status': 500}

# Routes
@app.route('/')
def index():
    """Main dashboard page"""
    auth = get_auth_credentials()
    if not auth:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'Missing credentials'}), 400
        
        success, message = authenticate_icloud(username, password, 'trusted_device')
        
        if success:
            session['authenticated'] = True
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 401
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Clear authentication"""
    auth_path = os.path.join(app.config['UPLOAD_FOLDER'], 'auth.json')
    if os.path.exists(auth_path):
        os.remove(auth_path)
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/upload_key', methods=['POST'])
def upload_key():
    """Upload a .keys file"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not file.filename.endswith('.keys'):
        return jsonify({'success': False, 'message': 'File must be a .keys file'}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    return jsonify({'success': True, 'message': f'Uploaded {filename}'})

@app.route('/api/devices')
def get_devices():
    """Get list of tracked devices"""
    _, names = load_key_files()
    devices = []
    for key_id, original_name in names.items():
        custom_name = get_device_name(original_name)
        devices.append({
            'name': custom_name,
            'original_name': original_name,
            'id': key_id
        })
    return jsonify({'devices': devices})

@app.route('/api/rename_device', methods=['POST'])
def rename_device():
    """Rename a device"""
    data = request.get_json()
    device_id = data.get('device_id')
    new_name = data.get('new_name')
    
    if not device_id or not new_name:
        return jsonify({'success': False, 'message': 'Missing device_id or new_name'}), 400
    
    set_device_name(device_id, new_name)
    return jsonify({'success': True, 'message': 'Device renamed successfully'})

@app.route('/api/delete_device', methods=['POST'])
def delete_device():
    """
    Delete a device: removes its .keys file from disk and clears any
    custom name stored in the database.  Historical report rows are left
    intact (they no longer decode without the key anyway).
    """
    data = request.get_json()
    device_id = data.get('device_id')   # this is the filename stem (original_name)

    if not device_id:
        return jsonify({'success': False, 'message': 'Missing device_id'}), 400

    # Sanitise: only allow the bare filename, no path traversal
    safe_name = secure_filename(device_id)
    if not safe_name:
        return jsonify({'success': False, 'message': 'Invalid device name'}), 400

    keys_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_name + '.keys')

    if not os.path.exists(keys_path):
        return jsonify({'success': False, 'message': 'Device key file not found'}), 404

    # 1. Delete the .keys file
    os.remove(keys_path)

    # 2. Remove any custom name entry from the DB
    db_path = os.path.join(app.config['UPLOAD_FOLDER'], 'reports.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM device_names WHERE device_id = ?', (device_id,))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': f'{device_id} deleted'})

@app.route('/api/locations')
def get_locations():
    """Get current locations of all devices"""
    hours = request.args.get('hours', 24, type=int)
    result = fetch_location_reports(hours)
    return jsonify(result)

@app.route('/api/check_auth')
def check_auth():
    """Check if authentication is still valid"""
    auth = get_auth_credentials()
    return jsonify({'authenticated': auth is not None})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8000)