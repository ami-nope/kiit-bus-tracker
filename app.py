from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import json
import os
from werkzeug.security import generate_password_hash, check_password_hash
import base64

app = Flask(__name__)
app.config['WTF_CSRF_ENABLED'] = False
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

# ...existing code...

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


def save_credentials(data: dict):
    with open(CREDENTIALS_FILE, 'w') as f:
        json.dump(data, f, indent=2)





@app.route('/')
def student_view():
    creds = load_credentials()
    institute = creds.get('institute_name', 'INSTITUTE')
    return render_template('student.html', institute_name=institute)


@app.route('/admin')
@login_required
def admin_view():
    creds = load_credentials()
    institute = creds.get('institute_name', 'INSTITUTE')
    user = session.get('admin')
    return render_template('admin.html', institute_name=institute, admin_user=user)

@app.route('/admin/users')
@login_required
def admin_users():
    creds = load_credentials()
    users = []
    # Admin user
    admin_username = creds.get('username')
    admin_password = creds.get('password_hash')
    if admin_username:
        users.append({
            'type': 'Admin',
            'username': admin_username,
            'password': '************' if admin_password else ''
        })
    # Student users (example: if you have a students list in credentials.json)
    for student in creds.get('students', []):
        users.append({
            'type': 'Student',
            'username': student.get('username', ''),
            'password': '************' if student.get('password_hash') else ''
        })
    return jsonify({'users': users})


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    creds = load_credentials()
    if request.method == 'GET':
        return render_template('admin_login.html', credentials_exist=bool(creds), institute_name=creds.get('institute_name', 'INSTITUTE'))

    data = request.form
    action = data.get('action')
    institute = data.get('institute_name', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    error_text = None

    if action == 'signup':
        signup_pin = data.get('signup_pin', '').strip()
        if creds:
            error_text = "Admin account already exists."
        elif not username:
            error_text = "Provide username."
        elif signup_pin != '456123':
            error_text = "Invalid signup pin."
        else:
            creds['institute_name'] = institute or 'INSTITUTE'
            creds['username'] = username
            if password:
                creds['password_hash'] = generate_password_hash(password)
            creds['pin_hash'] = generate_password_hash('456123')
            save_credentials(creds)
            session['admin'] = username
            return redirect(url_for('admin_view'))
        return render_template('admin_login.html', credentials_exist=bool(creds), institute_name=institute, error_text=error_text)

    elif action == 'login':
        if not creds:
            error_text = "No admin account exists. Please signup first."
        elif username != creds.get('username'):
            error_text = "Invalid username."
        elif password and creds.get('password_hash') and check_password_hash(creds['password_hash'], password):
            session['admin'] = username
            return redirect(url_for('admin_view'))
        else:
            error_text = "Invalid password."
        return render_template('admin_login.html', credentials_exist=bool(creds), institute_name=institute, error_text=error_text)

    return render_template('admin_login.html', credentials_exist=bool(creds), institute_name=institute, error_text="Invalid action.")


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))












    

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