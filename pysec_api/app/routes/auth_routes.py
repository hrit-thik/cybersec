from flask import Blueprint, request, jsonify, current_app
from functools import wraps # For token_required decorator
import jwt
from datetime import datetime, timedelta

from pysec_api.app.models import db, User # Adjusted import path
from pysec_api.app.utils.auth_utils import hash_password, check_password # Adjusted import path

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Placeholder for token_required decorator and routes
# (Will be implemented in subsequent steps of this subtask)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['sub'])
            if not current_user:
                return jsonify({'message': 'Token is invalid! User not found.'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing username, email, or password'}), 400

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'message': 'User with this username or email already exists'}), 409

    new_user = User(
        username=username,
        email=email,
        password_hash=hash_password(password)
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        'message': 'User registered successfully',
        'user': {
            'id': new_user.id,
            'username': new_user.username,
            'email': new_user.email
        }
    }), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'): # Assuming login with email
        return jsonify({'message': 'Missing email or password'}), 400

    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if not user or not check_password(user.password_hash, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    try:
        payload = {
            'sub': user.id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=current_app.config.get('JWT_EXPIRATION_HOURS', 24))
        }
        token = jwt.encode(
            payload,
            current_app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        return jsonify({'message': 'Login successful', 'token': token}), 200
    except Exception as e:
        current_app.logger.error(f"Error generating token: {e}")
        return jsonify({'message': 'Internal server error during token generation'}), 500
