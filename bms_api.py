from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from bms import BuildingSystem, Family, Notice


from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
print("Starting Flask backend...")


app = Flask(__name__)
CORS(app)

# --- Config ---
app.config["JWT_SECRET_KEY"] = "my-super-secret-key-that-is-not-secret"
jwt = JWTManager(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)


# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))


class Building(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    apartments = db.relationship('Apartment', backref='building', lazy=True)


class Apartment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    unit_number = db.Column(db.String(20), nullable=False)
    floor = db.Column(db.Integer)
    bedrooms = db.Column(db.Integer)
    building_id = db.Column(db.Integer, db.ForeignKey('building.id'), nullable=False)
    resident_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=True)
    requests = db.relationship('MaintenanceRequest', backref='apartment', lazy=True)


class MaintenanceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Pending')
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    apartment_id = db.Column(db.Integer, db.ForeignKey('apartment.id'), nullable=False)


# --- Auth Routes (Unchanged) ---
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    full_name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not full_name or not email or not password:
        return jsonify({"status": "error", "message": "All fields are required"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"status": "error", "message": "Email already registered"}), 409

    try:
        new_user = User(
            full_name=full_name,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"status": "success", "message": "Registration successful"}), 201
    except Exception as e:
        db.session.rollback()
        print("Registration error:", e)
        return jsonify({"status": "error", "message": "Registration failed"}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=user.email)
        return jsonify({"status": "success", "token": access_token})

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# --- 1. NEW API ROUTES ---
# These are the new endpoints for your application.
# They are all "locked" with @jwt_required()

@app.route("/api/user_info", methods=['GET'])
@jwt_required()
def get_user_info():
    # Get the email from the "digital keycard" (token)
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    return jsonify({
        "status": "success",
        "full_name": user.full_name,
        "email": user.email
    }), 200


@app.route("/api/maintenance", methods=['POST'])
@jwt_required()
def create_maintenance_request():
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()

    # Find which apartment this user lives in
    # NOTE: This assumes the user is assigned to an apartment.
    # In a real app, you'd need an admin to assign users to apartments.
    apartment = Apartment.query.filter_by(resident_id=user.id).first()
    if not apartment:
        return jsonify({"status": "error", "message": "You are not assigned to an apartment"}), 400

    data = request.json
    description = data.get('description')
    if not description:
        return jsonify({"status": "error", "message": "Description is required"}), 400

    new_request = MaintenanceRequest(
        description=description,
        user_id=user.id,
        apartment_id=apartment.id,
        status="Pending"
    )
    db.session.add(new_request)
    db.session.commit()

    return jsonify({"status": "success", "message": "Request submitted"}), 201


@app.route("/api/maintenance", methods=['GET'])
@jwt_required()
def get_maintenance_requests():
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()

    # Find all requests submitted by this user
    requests = MaintenanceRequest.query.filter_by(user_id=user.id).order_by(MaintenanceRequest.created_at.desc()).all()

    # Format the data into a clean list for the Java app
    request_list = []
    for req in requests:
        request_list.append({
            "id": req.id,
            "description": req.description,
            "status": req.status,
            "created_at": req.created_at.strftime("%Y-%m-%d %H:%M")
        })

    return jsonify({"status": "success", "requests": request_list}), 200


# --------------------------

# --- Main Execution ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(port=5000, debug=True)
