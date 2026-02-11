# gevent monkey-patching must be first — makes threading/queue/time cooperative
try:
    from gevent import monkey
    monkey.patch_all()
except ImportError:
    pass  # Allow running without gevent (localhost dev)

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response, stream_with_context
from flask_cors import CORS
import json
import os
import math
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime, timezone
import threading
import queue
import time

# ---------- 1-D Kalman filter for GPS smoothing ----------
class GPSKalman:
    """Lightweight 1-D Kalman per axis. ~2 multiplications per update."""
    __slots__ = ('x', 'p', 'q', 'r')
    def __init__(self, process_noise=0.00001, measurement_noise=0.00005):
        self.x = None   # estimate
        self.p = 1.0     # error covariance
        self.q = process_noise
        self.r = measurement_noise
    def update(self, measurement):
        if self.x is None:
            self.x = measurement
            return measurement
        self.p += self.q
        k = self.p / (self.p + self.r)
        self.x += k * (measurement - self.x)
        self.p *= (1 - k)
        return self.x

_kalman_filters = {}  # bus_id -> {'lat': GPSKalman, 'lng': GPSKalman}

def kalman_smooth(bus_id, lat, lng):
    if bus_id not in _kalman_filters:
        _kalman_filters[bus_id] = {'lat': GPSKalman(), 'lng': GPSKalman()}
    kf = _kalman_filters[bus_id]
    return kf['lat'].update(lat), kf['lng'].update(lng)

# ---------- server-side stop detection ----------
def _haversine_m(lat1, lng1, lat2, lng2):
    """Fast equirectangular distance in meters — accurate at campus scale."""
    d2r = math.pi / 180
    dlat = (lat2 - lat1) * d2r
    dlng = (lng2 - lng1) * d2r
    x = dlng * math.cos((lat1 + lat2) * 0.5 * d2r)
    return 6371000 * math.sqrt(dlat * dlat + x * x)

_AT_STOP_M = 80  # meters — "at stop" threshold
_bus_stop_state = {}  # bus_id -> { 'atStop': str|None, 'nearestStopIdx': int, 'direction': 'up'|'down'|None }

def detect_stop_info(bus_id, lat, lng, route_id):
    """Detect nearest stop, at-stop, direction. Returns dict to merge into broadcast."""
    result = {'atStop': None, 'nearestStopIdx': None, 'nearestStopName': None, 'nextStopName': None, 'direction': None}
    if not route_id:
        return result
    locs = load_json(LOCATIONS_FILE, {"hostels": [], "classes": [], "routes": []})
    route = None
    for r in locs.get('routes', []):
        if str(r.get('id')) == str(route_id):
            route = r
            break
    if not route or not route.get('waypoints') or len(route['waypoints']) < 2:
        return result
    wps = route['waypoints']
    stops = route.get('stops', [])
    best_idx, best_d = 0, float('inf')
    for i, wp in enumerate(wps):
        d = _haversine_m(lat, lng, wp[0], wp[1])
        if d < best_d:
            best_d = d
            best_idx = i
    result['nearestStopIdx'] = best_idx
    stop_name = stops[best_idx] if best_idx < len(stops) and stops[best_idx] else f'Stop {best_idx + 1}'
    result['nearestStopName'] = stop_name
    # Determine next stop index and name
    next_idx = best_idx + 1 if best_idx + 1 < len(stops) else best_idx
    result['nextStopName'] = stops[next_idx] if next_idx < len(stops) and stops[next_idx] else f'Stop {next_idx + 1}' if next_idx != best_idx else None
    if best_d <= _AT_STOP_M:
        result['atStop'] = stop_name
    # Direction
    prev = _bus_stop_state.get(bus_id, {})
    prev_idx = prev.get('nearestStopIdx')
    direction = prev.get('direction')
    if prev_idx is not None and prev_idx != best_idx:
        direction = 'down' if best_idx > prev_idx else 'up'
    result['direction'] = direction
    _bus_stop_state[bus_id] = {'nearestStopIdx': best_idx, 'direction': direction, 'atStop': result['atStop']}
    return result

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['WTF_CSRF_ENABLED'] = False
app.secret_key = os.environ.get('FLASK_SECRET', 'dev-secret-change-this')

CORS(app, resources={r"/api/*": {"origins": "*"}})
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

RENDER_URL = os.environ.get('RENDER_EXTERNAL_URL', '')
ON_RENDER = bool(os.environ.get('RENDER') or RENDER_URL)
IS_HTTPS = RENDER_URL.startswith('https://')
app.config.update(
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=IS_HTTPS if ON_RENDER else False,
    PREFERRED_URL_SCHEME='https' if IS_HTTPS else 'http'
)

# ---------- file paths ----------
BUSES_FILE = os.path.join(BASE_DIR, 'buses_location.json')
LOCATIONS_FILE = os.path.join(BASE_DIR, 'locations.json')
CREDENTIALS_FILE = os.path.join(BASE_DIR, 'credentials.json')

# ---------- simple JSON helpers ----------
def load_json(path, default):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

def ensure_files():
    if not os.path.exists(BUSES_FILE):
        save_json(BUSES_FILE, {})
    if not os.path.exists(LOCATIONS_FILE):
        save_json(LOCATIONS_FILE, {"hostels": [], "classes": [], "routes": []})
    if not os.path.exists(CREDENTIALS_FILE):
        save_json(CREDENTIALS_FILE, {"admins": [], "institute_name": "INSTITUTE"})

# ---------- in-memory caches ----------
_buses = {}
_buses_lock = threading.Lock()
_worker_started = False

APP_START_TS = time.time()
REQUESTS_TOTAL = 0

def _init_app():
    global _buses, _worker_started
    ensure_files()
    raw = load_json(BUSES_FILE, {})
    # Filter out stale buses on startup (older than 60s)
    now = time.time()
    cleaned = {}
    for k, v in raw.items():
        try:
            ts = datetime.fromisoformat(v.get('lastUpdate', '').replace('Z', '+00:00')).timestamp()
            if (now - ts) <= 60:
                cleaned[k] = v
        except Exception:
            pass  # drop invalid entries
    _buses = cleaned
    if cleaned != raw:
        save_json(BUSES_FILE, cleaned)
    if not _worker_started:
        _worker_started = True
        threading.Thread(target=_sync_worker, daemon=True).start()

@app.before_request
def _before():
    global REQUESTS_TOTAL
    if not hasattr(app, '_ready'):
        _init_app()
        app._ready = True
    REQUESTS_TOTAL += 1

def _sync_worker():
    last = None
    while True:
        time.sleep(2)
        try:
            with _buses_lock:
                snap = {k: dict(v) for k, v in _buses.items()}
            snap_str = json.dumps(snap, sort_keys=True)
            if snap_str != last:
                save_json(BUSES_FILE, snap)
                last = snap_str
        except Exception:
            pass

# ---------- SSE ----------
_subscribers_lock = threading.Lock()
_subscribers = {}   # routeId|"all" -> [queue, ...]

def broadcast(payload):
    try:
        data = json.dumps(payload)
    except Exception:
        data = json.dumps({"error": "bad-payload"})
    # Extract routeId for targeted delivery
    route_id = None
    if isinstance(payload, dict):
        route_id = payload.get('routeId')
        if not route_id:
            bus_data = payload.get('data')
            if isinstance(bus_data, dict):
                route_id = bus_data.get('routeId')
    with _subscribers_lock:
        if route_id:
            # Targeted: send to "all" subscribers + matching route subscribers
            sent = set()
            for q in list(_subscribers.get('all', [])):
                sent.add(id(q))
                try:
                    q.put_nowait(data)
                except Exception:
                    pass
            for q in list(_subscribers.get(route_id, [])):
                if id(q) not in sent:
                    try:
                        q.put_nowait(data)
                    except Exception:
                        pass
        else:
            # No route context (buses_clear, etc.) — send to all subscribers
            sent = set()
            for group in _subscribers.values():
                for q in list(group):
                    if id(q) not in sent:
                        sent.add(id(q))
                        try:
                            q.put_nowait(data)
                        except Exception:
                            pass

@app.route('/events')
def sse_events():
    if os.environ.get('DISABLE_SSE', '').lower() in ('1', 'true', 'yes'):
        return Response('SSE disabled', status=503, mimetype='text/plain')
    route_id = request.args.get('routeId') or 'all'
    def stream():
        q = queue.Queue(maxsize=100)
        hb = max(5, int(os.environ.get('SSE_HEARTBEAT_SEC', '20')))
        with _subscribers_lock:
            _subscribers.setdefault(route_id, []).append(q)
        yield 'event: ping\ndata: "connected"\n\n'
        try:
            while True:
                try:
                    msg = q.get(timeout=hb)
                    yield f'data: {msg}\n\n'
                except queue.Empty:
                    yield 'event: ping\ndata: {}\n\n'
        finally:
            with _subscribers_lock:
                try:
                    subs = _subscribers.get(route_id)
                    if subs:
                        subs.remove(q)
                        if not subs:
                            del _subscribers[route_id]
                except (ValueError, KeyError):
                    pass
    return Response(stream_with_context(stream()), mimetype='text/event-stream',
                    headers={
                        'Cache-Control': 'no-cache, no-transform',
                        'X-Accel-Buffering': 'no',
                        'Connection': 'keep-alive',
                        'Content-Type': 'text/event-stream; charset=utf-8',
                        'Transfer-Encoding': 'chunked',
                    })

# ---------- credentials helpers ----------
def load_credentials():
    return load_json(CREDENTIALS_FILE, {"admins": [], "institute_name": "INSTITUTE"})

def save_credentials(data):
    save_json(CREDENTIALS_FILE, data)

# ---------- auth ----------
def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'admin' not in session:
            return redirect(url_for('admin_login'))
        return fn(*args, **kwargs)
    return wrapper

# ---------- page routes ----------
@app.route('/health')
def health_check():
    return 'OK', 200

@app.route('/')
def student_view():
    creds = load_credentials()
    return render_template('student.html', institute_name=creds.get('institute_name', 'INSTITUTE'))

@app.route('/driver')
def driver_view():
    creds = load_credentials()
    return render_template('driver.html', institute_name=creds.get('institute_name', 'INSTITUTE'))

@app.route('/simulator')
def simulator_view():
    creds = load_credentials()
    return render_template('simulator.html', institute_name=creds.get('institute_name', 'INSTITUTE'))

@app.route('/admin')
@login_required
def admin_view():
    creds = load_credentials()
    return render_template('admin.html', institute_name=creds.get('institute_name', 'INSTITUTE'), admin_user=session.get('admin'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    try:
        creds = load_credentials()
        if request.method == 'GET':
            return render_template('admin_login.html', credentials_exist=bool(creds.get('admins')),
                                   institute_name=creds.get('institute_name', 'INSTITUTE'))

        data = request.form
        action = data.get('action')
        institute = data.get('institute_name', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        error_text = None

        if 'admins' not in creds:
            creds['admins'] = []

        if action == 'signup':
            pin = (data.get('signup_pin', '') or '').strip()
            if pin != '456123':
                error_text = "Invalid signup pin."
            elif not username or not password:
                error_text = "Provide username and password."
            elif any(a.get('username') == username for a in creds['admins']):
                error_text = "Admin username already exists."
            else:
                creds['institute_name'] = institute or creds.get('institute_name', 'INSTITUTE')
                creds['admins'].append({'username': username, 'password_hash': generate_password_hash(password)})
                save_credentials(creds)
                session['admin'] = username
                return redirect(url_for('admin_view'))

        elif action == 'login':
            if not creds.get('admins'):
                error_text = "No admin accounts exist. Please signup first."
            else:
                admin = next((a for a in creds['admins'] if a.get('username') == username), None)
                if not admin:
                    error_text = "Invalid username."
                elif admin.get('password_hash') and check_password_hash(admin['password_hash'], password):
                    session['admin'] = username
                    return redirect(url_for('admin_view'))
                else:
                    error_text = "Invalid password."
        else:
            error_text = "Invalid action."

        return render_template('admin_login.html', credentials_exist=bool(creds.get('admins')),
                               institute_name=institute or creds.get('institute_name', 'INSTITUTE'), error_text=error_text)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"Server Error: {str(e)}", 500

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))

# ---------- admin user management ----------
@app.route('/admin/users')
@login_required
def admin_users():
    creds = load_credentials()
    users = []
    for adm in creds.get('admins', []):
        users.append({'type': 'Admin', 'username': adm.get('username', ''), 'password': '************'})
    for s in creds.get('students', []):
        users.append({'type': 'Student', 'username': s.get('username', ''), 'password': '************'})
    return jsonify({'users': users})

@app.route('/admin/admins', methods=['GET'])
@login_required
def list_admins():
    creds = load_credentials()
    return jsonify({'admins': [{'username': a.get('username', '')} for a in creds.get('admins', [])]})

@app.route('/admin/admins', methods=['POST'])
@login_required
def add_admin():
    data = request.json or {}
    username = (data.get('username', '') or '').strip()
    password = (data.get('password', '') or '').strip()
    pin = (data.get('pin', '') or '').strip()
    if pin != '456123':
        return jsonify({'error': 'Invalid pin'}), 400
    if not username or not password:
        return jsonify({'error': 'Provide username and password'}), 400
    creds = load_credentials()
    if any(a.get('username') == username for a in creds.get('admins', [])):
        return jsonify({'error': 'Admin username already exists'}), 400
    creds.setdefault('admins', []).append({'username': username, 'password_hash': generate_password_hash(password)})
    save_credentials(creds)
    return jsonify({'status': 'success', 'username': username})

@app.route('/admin/admins/<username>', methods=['DELETE'])
@login_required
def delete_admin(username):
    creds = load_credentials()
    admins = creds.get('admins', [])
    new = [a for a in admins if a.get('username') != username]
    if len(new) == len(admins):
        return jsonify({'error': 'Admin not found'}), 404
    creds['admins'] = new
    save_credentials(creds)
    if session.get('admin') == username:
        session.pop('admin', None)
    return jsonify({'status': 'success'})

@app.route('/admin/admins/<username>/password', methods=['POST'])
@login_required
def change_admin_password(username):
    data = request.json or {}
    new_pw = (data.get('password', '') or '').strip()
    pin = (data.get('pin', '') or '').strip()
    if pin != '456123':
        return jsonify({'error': 'Invalid pin'}), 400
    if not new_pw:
        return jsonify({'error': 'Provide new password'}), 400
    creds = load_credentials()
    admin = next((a for a in creds.get('admins', []) if a.get('username') == username), None)
    if not admin:
        return jsonify({'error': 'Admin not found'}), 404
    admin['password_hash'] = generate_password_hash(new_pw)
    save_credentials(creds)
    return jsonify({'status': 'success'})

# ---------- metrics ----------
@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    creds = load_credentials()
    return jsonify({'total_transports': int(creds.get('total_transports', 100))})

@app.route('/api/metrics', methods=['POST'])
@login_required
def update_metrics():
    data = request.json or {}
    try:
        total = int(data.get('total_transports'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid total_transports'}), 400
    if total < 0:
        return jsonify({'error': 'Provide non-negative total_transports'}), 400
    creds = load_credentials()
    creds['total_transports'] = total
    save_credentials(creds)
    return jsonify({'status': 'success', 'total_transports': total})

# ---------- bus APIs ----------
@app.route('/api/buses', methods=['GET'])
def get_all_buses():
    # Enrich with latest stop state for polling fallback
    with _buses_lock:
        result = {}
        for bus_id, data in _buses.items():
            entry = dict(data)
            ss = _bus_stop_state.get(bus_id, {})
            entry['atStop'] = ss.get('atStop')
            entry['nearestStopName'] = ss.get('nearestStopName') if 'nearestStopName' not in entry else entry['nearestStopName']
            entry['direction'] = ss.get('direction')
            result[bus_id] = entry
    return jsonify(result)

@app.route('/api/buses/clear', methods=['POST'])
def clear_all_buses():
    global _buses
    with _buses_lock:
        _buses = {}
    save_json(BUSES_FILE, {})
    try:
        broadcast({'type': 'buses_clear'})
    except Exception:
        pass
    return jsonify({'status': 'success'})

_bus_last_broadcast = {}  # bus_id -> monotonic timestamp of last broadcast

@app.route('/api/bus/<int:bus_number>', methods=['POST'])
def update_bus_location(bus_number):
    raw = request.get_json(silent=True) or request.form.to_dict() or {}
    try:
        raw_lat = float(raw.get('lat'))
        raw_lng = float(raw.get('lng'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Provide numeric lat and lng'}), 400
    # Kalman smoothing
    bus_id = str(bus_number)
    lat, lng = kalman_smooth(bus_id, raw_lat, raw_lng)
    last_update = raw.get('lastUpdate') or time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    heading = raw.get('heading')  # device heading from driver/simulator
    should_broadcast = True
    now_mono = time.monotonic()
    with _buses_lock:
        existing = _buses.get(bus_id, {})
        route_id = raw.get('routeId', existing.get('routeId'))
        # Skip broadcast if position hasn't meaningfully changed (~0.5m)
        # Always broadcast at least every 3s even when stationary (heartbeat)
        if existing and 'lat' in existing and 'lng' in existing:
            dlat = abs(lat - existing['lat'])
            dlng = abs(lng - existing['lng'])
            if dlat < 0.000005 and dlng < 0.000005:
                last_bc = _bus_last_broadcast.get(bus_id, 0)
                if (now_mono - last_bc) < 3:
                    should_broadcast = False
        entry = {'lat': lat, 'lng': lng, 'lastUpdate': last_update, 'routeId': route_id}
        if heading is not None:
            try:
                entry['heading'] = float(heading)
            except (TypeError, ValueError):
                pass
        _buses[bus_id] = entry
        current_data = dict(entry)
    # Server-side stop detection — enrich broadcast payload
    stop_info = detect_stop_info(bus_id, lat, lng, route_id)
    current_data.update(stop_info)
    try:
        if should_broadcast:
            _bus_last_broadcast[bus_id] = now_mono
            broadcast({'type': 'bus_update', 'bus': bus_id, 'data': current_data})
    except Exception:
        pass
    return jsonify({'status': 'success', 'bus': bus_number})

@app.route('/api/bus/<int:bus_number>', methods=['DELETE'])
def stop_bus(bus_number):
    bus_id = str(bus_number)
    with _buses_lock:
        removed = _buses.pop(bus_id, None)
    route_id = removed.get('routeId') if removed else None
    # Clean up Kalman + stop state
    _kalman_filters.pop(bus_id, None)
    _bus_stop_state.pop(bus_id, None)
    _bus_last_broadcast.pop(bus_id, None)
    try:
        broadcast({'type': 'bus_stop', 'bus': bus_id, 'routeId': route_id})
    except Exception:
        pass
    return jsonify({'status': 'success'})

@app.route('/api/bus/<int:bus_number>/route', methods=['POST'])
def set_bus_route(bus_number):
    data = request.get_json(silent=True) or {}
    route_id = data.get('routeId')
    bus_id = str(bus_number)
    with _buses_lock:
        if bus_id in _buses:
            _buses[bus_id]['routeId'] = route_id
        # Don't create a bus entry just for route assignment
    try:
        broadcast({'type': 'route_set', 'bus': bus_id, 'routeId': route_id})
    except Exception:
        pass
    return jsonify({'status': 'success'})

@app.route('/api/bus-routes', methods=['GET'])
def get_bus_routes():
    with _buses_lock:
        result = {k: v.get('routeId') for k, v in _buses.items()}
    return jsonify(result)

# ---------- location APIs ----------
@app.route('/api/locations', methods=['GET'])
def get_locations():
    return jsonify(load_json(LOCATIONS_FILE, {"hostels": [], "classes": [], "routes": []}))

@app.route('/api/hostels', methods=['GET'])
def get_hostels():
    locs = load_json(LOCATIONS_FILE, {"hostels": [], "classes": [], "routes": []})
    return jsonify(locs.get('hostels', []))

@app.route('/api/classes', methods=['GET'])
def get_classes():
    locs = load_json(LOCATIONS_FILE, {"hostels": [], "classes": [], "routes": []})
    return jsonify(locs.get('classes', []))

@app.route('/api/routes', methods=['GET'])
def get_routes():
    locs = load_json(LOCATIONS_FILE, {"hostels": [], "classes": [], "routes": []})
    return jsonify(locs.get('routes', []))

@app.route('/api/route', methods=['POST'])
def create_route():
    data = request.json
    locs = load_json(LOCATIONS_FILE, {"hostels": [], "classes": [], "routes": []})
    route = {
        'id': data.get('id', f"route_{len(locs.get('routes', [])) + 1}"),
        'name': data['name'],
        'waypoints': data['waypoints'],
        'stops': data.get('stops', []),
        'color': data.get('color', '#FF5722')
    }
    routes = locs.get('routes', [])
    idx = next((i for i, r in enumerate(routes) if r['id'] == route['id']), -1)
    if idx >= 0:
        routes[idx] = route
    else:
        routes.append(route)
    locs['routes'] = routes
    save_json(LOCATIONS_FILE, locs)
    return jsonify({'status': 'success', 'route': route})

@app.route('/api/route/<route_id>', methods=['DELETE'])
def delete_route(route_id):
    locs = load_json(LOCATIONS_FILE, {"hostels": [], "classes": [], "routes": []})
    locs['routes'] = [r for r in locs.get('routes', []) if r['id'] != route_id]
    save_json(LOCATIONS_FILE, locs)
    return jsonify({'status': 'success'})

@app.route('/api/hostel', methods=['POST'])
def create_hostel():
    data = request.json
    locs = load_json(LOCATIONS_FILE, {"hostels": [], "classes": [], "routes": []})
    hostel = {
        'id': f"hostel_{len(locs.get('hostels', [])) + 1}",
        'name': data['name'],
        'lat': data['lat'],
        'lng': data['lng'],
        'capacity': data.get('capacity', 100)
    }
    locs['hostels'].append(hostel)
    save_json(LOCATIONS_FILE, locs)
    return jsonify({'status': 'success', 'hostel': hostel})

@app.route('/api/hostel/<hostel_id>', methods=['DELETE'])
def delete_hostel(hostel_id):
    locs = load_json(LOCATIONS_FILE, {"hostels": [], "classes": [], "routes": []})
    locs['hostels'] = [h for h in locs.get('hostels', []) if h['id'] != hostel_id]
    save_json(LOCATIONS_FILE, locs)
    return jsonify({'status': 'success'})

@app.route('/api/class', methods=['POST'])
def create_class():
    data = request.json
    locs = load_json(LOCATIONS_FILE, {"hostels": [], "classes": [], "routes": []})
    cls = {
        'id': f"class_{len(locs.get('classes', [])) + 1}",
        'name': data['name'],
        'lat': data['lat'],
        'lng': data['lng'],
        'department': data.get('department', 'Unknown')
    }
    locs['classes'].append(cls)
    save_json(LOCATIONS_FILE, locs)
    return jsonify({'status': 'success', 'class': cls})

@app.route('/api/class/<class_id>', methods=['DELETE'])
def delete_class(class_id):
    locs = load_json(LOCATIONS_FILE, {"hostels": [], "classes": [], "routes": []})
    locs['classes'] = [c for c in locs.get('classes', []) if c['id'] != class_id]
    save_json(LOCATIONS_FILE, locs)
    return jsonify({'status': 'success'})

# ---------- health / status ----------
@app.route('/healthz')
def healthz():
    return jsonify({'status': 'ok', 'uptime_sec': int(time.time() - APP_START_TS)}), 200

@app.route('/status')
def status():
    locs = load_json(LOCATIONS_FILE, {"hostels": [], "classes": [], "routes": []})
    return jsonify({
        'uptime_sec': int(time.time() - APP_START_TS),
        'requests_total': REQUESTS_TOTAL,
        'sse_clients': sum(len(v) for v in _subscribers.values()),
        'buses_count': len(_buses),
        'routes_count': len(locs.get('routes', [])),
        'on_render': ON_RENDER,
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
