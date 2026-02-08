from flask import Flask, render_template, request, jsonify
import json
import os

app = Flask(__name__)

BUSES_FILE = 'buses_location.json'

if not os.path.exists(BUSES_FILE):
    with open(BUSES_FILE, 'w') as f:
        json.dump({}, f)

@app.route('/')
def student_view():
    return render_template('student.html')

@app.route('/driver')
def driver_view():
    return render_template('driver.html')

@app.route('/api/buses', methods=['GET'])
def get_all_buses():
    with open(BUSES_FILE, 'r') as f:
        buses = json.load(f)
    return jsonify(buses)

@app.route('/api/bus/<int:bus_number>', methods=['POST'])
def update_bus_location(bus_number):
    data = request.json
    
    with open(BUSES_FILE, 'r') as f:
        buses = json.load(f)
    
    buses[str(bus_number)] = {
        'lat': data['lat'],
        'lng': data['lng'],
        'lastUpdate': data.get('lastUpdate', '')
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))