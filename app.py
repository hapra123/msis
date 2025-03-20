from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
import hashlib
from datetime import datetime
import secrets
import firebase_admin
from firebase_admin import credentials, db
import json

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = secrets.token_hex(16)
CORS(app)

# Load Admin Credentials from JSON
with open("data/admin_credentials.json", "r") as file:
    admin_credentials = json.load(file)

# Initialize Firebase
cred = credentials.Certificate("firebase_credentials.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://msisdb-default-rtdb.firebaseio.com/'
})

# Firebase Database References
ref_points = db.reference("/points")
ref_history = db.reference("/history")

# Initialize Firebase data if empty
def initialize_firebase():
    if not ref_points.get():
        ref_points.set([
            {"group": "Alchemist", "sports": 0, "cultural": 0},
            {"group": "Mavericks", "sports": 0, "cultural": 0},
            {"group": "Phoenix", "sports": 0, "cultural": 0},
            {"group": "Titans", "sports": 0, "cultural": 0}
        ])
    
    if not ref_history.get():
        ref_history.set([])

initialize_firebase()

# Helper Functions
def verify_admin(username, password):
    entered_password_hash = hashlib.sha256(password.encode()).hexdigest()
    return username == admin_credentials["username"] and entered_password_hash == admin_credentials["password_hash"]

def calculate_ranks(points_data):
    for item in points_data:
        item["total"] = item["sports"] + item["cultural"]
    
    sorted_data = sorted(points_data, key=lambda x: x["total"], reverse=True)
    
    current_rank = 1
    prev_total = -1
    skip_ranks = 0

    for i, item in enumerate(sorted_data):
        if item["total"] != prev_total:
            current_rank = i + 1 - skip_ranks
            prev_total = item["total"]
        else:
            skip_ranks += 1

        item["rank"] = current_rank

    return sorted_data

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/points', methods=['GET'])
def get_points():
    points_data = ref_points.get()
    ranked_data = calculate_ranks(points_data)
    return jsonify(ranked_data)

@app.route('/api/points/history', methods=['GET'])
def get_points_history():
    return jsonify(ref_history.get())

@app.route('/api/points/update', methods=['POST'])
def update_points():
    if not session.get('admin_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    group = data.get('group')
    category = data.get('category')
    event = data.get('event')
    points = data.get('points')

    if not all([group, category, event, points]):
        return jsonify({"error": "Missing required fields"}), 400

    # Update Firebase points data
    points_data = ref_points.get()
    for item in points_data:
        if item["group"] == group:
            item[category] += points

    ref_points.set(points_data)

    # Add to Firebase history
    history_entry = {
        "timestamp": datetime.now().isoformat(),
        "group": group,
        "category": category,
        "event": event,
        "points": points
    }
    ref_history.push(history_entry)

    return jsonify({"success": True, "message": f"Added {points} points to {group} for {event}"})

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if verify_admin(username, password):
        session['admin_logged_in'] = True
        return jsonify({"success": True})
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    session.pop('admin_logged_in', None)
    return jsonify({"success": True})

@app.route('/api/admin/status', methods=['GET'])
def admin_status():
    return jsonify({"logged_in": session.get('admin_logged_in', False)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)