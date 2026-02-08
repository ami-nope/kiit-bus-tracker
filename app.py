from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import json
import os
from werkzeug.security import generate_password_hash, check_password_hash
import base64
from fido2.utils import websafe_encode, websafe_decode
from fido2.webauthn import AttestedCredentialData

try:
    from fido2.server import Fido2Server
    from fido2.webauthn import PublicKeyCredentialRpEntity
    FIDO2_AVAILABLE = True
except Exception:
    FIDO2_AVAILABLE = False

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'dev-secret-change-this')

BUSES_FILE = 'buses_location.json'
LOCATIONS_FILE = 'locations.json'
CREDENTIALS_FILE = 'credentials.json'

# Ensure required files exist

if not os.path.exists(BUSES_FILE):
    with open(BUSES_FILE, 'w') as f:
        json.dump({}, f)

if not os.path.exists(LOCATIONS_FILE):
    with open(LOCATIONS_FILE, 'w') as f:
        json.dump({"hostels": [], "classes": [], "routes": []}, f)

if not os.path.exists(CREDENTIALS_FILE):
    with open(CREDENTIALS_FILE, 'w') as f:
        json.dump({}, f)


def load_credentials():
    try:
        with open(CREDENTIALS_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def save_credentials(data: dict):
    with open(CREDENTIALS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


if FIDO2_AVAILABLE:
    rp = PublicKeyCredentialRpEntity(
        id="localhost",
        name="Campus Transport"
    )

    fido2_server = Fido2Server(rp)


@app.route('/')
def student_view():
    creds = load_credentials()
    institute = creds.get('institute_name', 'INSTITUTE')
    return render_template('student.html', institute_name=institute)

@app.route('/driver')
def driver_view():
    creds = load_credentials()
    institute = creds.get('institute_name', 'INSTITUTE')
    return render_template('driver.html', institute_name=institute)



def login_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'admin' not in session:
            return redirect(url_for('admin_login'))
        return fn(*args, **kwargs)

    return wrapper


@app.route('/admin')
@login_required
def admin_view():
    creds = load_credentials()
    institute = creds.get('institute_name', 'INSTITUTE')
    user = session.get('admin')
    return render_template('admin.html', institute_name=institute, admin_user=user)


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    creds = load_credentials()
    if request.method == 'GET':
        return render_template('admin_login.html', credentials_exist=bool(creds), fido2_available=FIDO2_AVAILABLE, institute_name=creds.get('institute_name', 'INSTITUTE'))

    # POST: handle login or initial registration
    data = request.form
    institute = data.get('institute_name', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    pin = data.get('pin', '').strip()

    # If no credentials yet, treat as registration
    if not creds:
        if not username:
            return "Provide username", 400
        creds['institute_name'] = institute or 'INSTITUTE'
        creds['username'] = username
        if password:
            creds['password_hash'] = generate_password_hash(password)
        if pin:
            creds['pin_hash'] = generate_password_hash(pin)
        creds['webauthn'] = creds.get('webauthn', {})
        save_credentials(creds)
        session['admin'] = username
        return redirect(url_for('admin_view'))

    # Otherwise login flow
    if username != creds.get('username'):
        return "Invalid username", 403

    # check password then pin
    if password and creds.get('password_hash') and check_password_hash(creds['password_hash'], password):
        session['admin'] = username
        return redirect(url_for('admin_view'))
    if pin and creds.get('pin_hash') and check_password_hash(creds['pin_hash'], pin):
        session['admin'] = username
        return redirect(url_for('admin_view'))

    # For WebAuthn, browser will call specific endpoints; here we just show error
    return "Invalid credentials", 403


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))


@app.route('/webauthn/register_options', methods=['POST'])
def webauthn_register_options():
    if not FIDO2_AVAILABLE:
        return jsonify({'error': 'FIDO2 not available on server. Install fido2 and configure RP.'}), 501

    creds = load_credentials()
    username = creds.get('username')
    if not username:
        return jsonify({'error': 'No admin user configured yet'}), 400

    # Build user object (id should be bytes)
    user_id = username.encode('utf-8')
    user = {'id': user_id, 'name': username, 'displayName': username}

    # Existing credential descriptors to exclude
    existing = []
    for c in creds.get('webauthn', {}).values():
        try:
            existing.append({'id': websafe_decode(c['id']), 'type': 'public-key'})
        except Exception:
            continue

    options, state = fido2_server.register_begin(user, existing)

    # Store state in session for completion step
    session['webauthn_state'] = state

    def encode(obj):
        if isinstance(obj, bytes):
            return websafe_encode(obj).decode('utf-8')
        if isinstance(obj, dict):
            return {k: encode(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [encode(v) for v in obj]
        return obj

    return jsonify(encode(options))


@app.route('/webauthn/register_result', methods=['POST'])
def webauthn_register_result():
    if not FIDO2_AVAILABLE:
        return jsonify({'error': 'FIDO2 not available on server.'}), 501

    data = request.json
    if 'webauthn_state' not in session:
        return jsonify({'error': 'No registration in progress'}), 400

    state = session.pop('webauthn_state')

    client_data = base64.urlsafe_b64decode(data['clientDataJSON'] + '==')
    att_obj = base64.urlsafe_b64decode(data['attestationObject'] + '==')

    auth_data = fido2_server.register_complete(state, client_data, att_obj)

    # auth_data is AttestedCredentialData
    cred = auth_data.credential_data
    cred_id_b64 = websafe_encode(cred.credential_id).decode('utf-8')

    creds = load_credentials()
    web = creds.get('webauthn', {})
    web[cred_id_b64] = {
        'id': cred_id_b64,
        'public_key': base64.b64encode(cred.public_key).decode('utf-8'),
        'sign_count': auth_data.sign_count
    }
    creds['webauthn'] = web
    save_credentials(creds)

    return jsonify({'status': 'ok', 'credentialId': cred_id_b64})


@app.route('/webauthn/authenticate_options', methods=['POST'])
def webauthn_authenticate_options():
    if not FIDO2_AVAILABLE:
        return jsonify({'error': 'FIDO2 not available on server.'}), 501

    creds = load_credentials()
    registered = []
    for c in creds.get('webauthn', {}).values():
        try:
            # We can pass credential descriptors (id and type) to the server
            registered.append({'id': websafe_decode(c['id']), 'type': 'public-key'})
        except Exception:
            continue

    options, state = fido2_server.authenticate_begin(registered)
    session['webauthn_state'] = state

    def encode(obj):
        if isinstance(obj, bytes):
            return websafe_encode(obj).decode('utf-8')
        if isinstance(obj, dict):
            return {k: encode(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [encode(v) for v in obj]
        return obj

    return jsonify(encode(options))


@app.route('/webauthn/authenticate_result', methods=['POST'])
def webauthn_authenticate_result():
    if not FIDO2_AVAILABLE:
        return jsonify({'error': 'FIDO2 not available on server.'}), 501

    data = request.json
    if 'webauthn_state' not in session:
        return jsonify({'error': 'No authentication in progress'}), 400
    state = session.pop('webauthn_state')

    # clientDataJSON and authenticatorData and signature are base64url
    client_data = base64.urlsafe_b64decode(data['clientDataJSON'] + '==')
    auth_data = base64.urlsafe_b64decode(data['authenticatorData'] + '==')
    signature = base64.urlsafe_b64decode(data['signature'] + '==')
    credential_id = websafe_decode(data['id'])

    creds = load_credentials()
    # Find stored credential by id
    stored = creds.get('webauthn', {}).get(websafe_encode(credential_id).decode('utf-8'))
    if not stored:
        return jsonify({'error': 'Unknown credential'}), 404

    # Build a dict expected by FIDO2 verify function
    # fido2_server.authenticate_complete expects registered credential objects; to keep this simple
    # we'll pass minimal info and rely on the library to verify signature
    try:
        fido2_server.authenticate_complete(state, [], client_data, auth_data, signature)
    except Exception as e:
        return jsonify({'error': 'Assertion verification failed', 'detail': str(e)}), 400

    # On success, log the admin in
    session['admin'] = creds.get('username')
    return jsonify({'status': 'ok'})

@app.route('/api/buses', methods=['GET'])
def get_all_buses():
    with open(BUSES_FILE, 'r') as f:
        buses = json.load(f)
    return jsonify(buses)

@app.route('/api/locations', methods=['GET'])
def get_locations():
    with open(LOCATIONS_FILE, 'r') as f:
        locations = json.load(f)
    return jsonify(locations)

@app.route('/api/hostels', methods=['GET'])
def get_hostels():
    with open(LOCATIONS_FILE, 'r') as f:
        locations = json.load(f)
    return jsonify(locations.get('hostels', []))

@app.route('/api/classes', methods=['GET'])
def get_classes():
    with open(LOCATIONS_FILE, 'r') as f:
        locations = json.load(f)
    return jsonify(locations.get('classes', []))

@app.route('/api/routes', methods=['GET'])
def get_routes():
    with open(LOCATIONS_FILE, 'r') as f:
        locations = json.load(f)
    return jsonify(locations.get('routes', []))

@app.route('/api/route', methods=['POST'])
def create_route():
    data = request.json
    
    with open(LOCATIONS_FILE, 'r') as f:
        locations = json.load(f)
    
    route = {
        'id': data.get('id', f"route_{int(len(locations.get('routes', [])) + 1)}"),
        'name': data['name'],
        'waypoints': data['waypoints'],
        'stops': data.get('stops', []),  # Add stop names
        'color': data.get('color', '#FF5722')
    }
    
    # Check if updating existing route
    routes = locations.get('routes', [])
    existing_idx = next((i for i, r in enumerate(routes) if r['id'] == route['id']), -1)
    
    if existing_idx >= 0:
        routes[existing_idx] = route
    else:
        routes.append(route)
    
    locations['routes'] = routes
    
    with open(LOCATIONS_FILE, 'w') as f:
        json.dump(locations, f, indent=2)
    
    return jsonify({'status': 'success', 'route': route})

@app.route('/api/route/<route_id>', methods=['DELETE'])
def delete_route(route_id):
    with open(LOCATIONS_FILE, 'r') as f:
        locations = json.load(f)
    
    routes = locations.get('routes', [])
    locations['routes'] = [r for r in routes if r['id'] != route_id]
    
    with open(LOCATIONS_FILE, 'w') as f:
        json.dump(locations, f, indent=2)
    
    return jsonify({'status': 'success'})

@app.route('/api/bus/<int:bus_number>', methods=['POST'])
def update_bus_location(bus_number):
    data = request.json
    
    with open(BUSES_FILE, 'r') as f:
        buses = json.load(f)
    
    # Preserve existing route assignment when updating location
    existing = buses.get(str(bus_number), {})
    route_id = data.get('routeId', existing.get('routeId'))

    buses[str(bus_number)] = {
        'lat': data['lat'],
        'lng': data['lng'],
        'lastUpdate': data.get('lastUpdate', ''),
        'routeId': route_id
    }
    
    with open(BUSES_FILE, 'w') as f:
        json.dump(buses, f)
    
    return jsonify({'status': 'success', 'bus': bus_number})

@app.route('/api/bus/<int:bus_number>', methods=['DELETE'])
def stop_bus(bus_number):
    with open(BUSES_FILE, 'r') as f:
        buses = json.load(f)
    
    if str(bus_number) in buses:
        del buses[str(bus_number)]
    
    with open(BUSES_FILE, 'w') as f:
        json.dump(buses, f)
    
    return jsonify({'status': 'success'})

@app.route('/api/hostel', methods=['POST'])
def create_hostel():
    data = request.json
    
    with open(LOCATIONS_FILE, 'r') as f:
        locations = json.load(f)
    
    hostel = {
        'id': f"hostel_{len(locations.get('hostels', [])) + 1}",
        'name': data['name'],
        'lat': data['lat'],
        'lng': data['lng'],
        'capacity': data.get('capacity', 100)
    }
    
    locations['hostels'].append(hostel)
    
    with open(LOCATIONS_FILE, 'w') as f:
        json.dump(locations, f, indent=2)
    
    return jsonify({'status': 'success', 'hostel': hostel})

@app.route('/api/hostel/<hostel_id>', methods=['DELETE'])
def delete_hostel(hostel_id):
    with open(LOCATIONS_FILE, 'r') as f:
        locations = json.load(f)
    
    locations['hostels'] = [h for h in locations.get('hostels', []) if h['id'] != hostel_id]
    
    with open(LOCATIONS_FILE, 'w') as f:
        json.dump(locations, f, indent=2)
    
    return jsonify({'status': 'success'})

@app.route('/api/class', methods=['POST'])
def create_class():
    data = request.json
    
    with open(LOCATIONS_FILE, 'r') as f:
        locations = json.load(f)
    
    cls = {
        'id': f"class_{len(locations.get('classes', [])) + 1}",
        'name': data['name'],
        'lat': data['lat'],
        'lng': data['lng'],
        'department': data.get('department', 'Unknown')
    }
    
    locations['classes'].append(cls)
    
    with open(LOCATIONS_FILE, 'w') as f:
        json.dump(locations, f, indent=2)
    
    return jsonify({'status': 'success', 'class': cls})

@app.route('/api/class/<class_id>', methods=['DELETE'])
def delete_class(class_id):
    with open(LOCATIONS_FILE, 'r') as f:
        locations = json.load(f)
    
    locations['classes'] = [c for c in locations.get('classes', []) if c['id'] != class_id]
    
    with open(LOCATIONS_FILE, 'w') as f:
        json.dump(locations, f, indent=2)
    
    return jsonify({'status': 'success'})

@app.route('/api/bus/<int:bus_number>/route', methods=['POST'])
def set_bus_route(bus_number):
    data = request.json
    route_id = data.get('routeId')
    
    with open(BUSES_FILE, 'r') as f:
        buses = json.load(f)
    
    if str(bus_number) in buses:
        buses[str(bus_number)]['routeId'] = route_id
    else:
        buses[str(bus_number)] = {
            'lat': 0,
            'lng': 0,
            'lastUpdate': '',
            'routeId': route_id
        }
    
    with open(BUSES_FILE, 'w') as f:
        json.dump(buses, f)
    
    return jsonify({'status': 'success'})

@app.route('/api/bus-routes', methods=['GET'])
def get_bus_routes():
    with open(BUSES_FILE, 'r') as f:
        buses = json.load(f)
    
    result = {}
    for bus_num, bus_info in buses.items():
        result[bus_num] = bus_info.get('routeId', None)
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))