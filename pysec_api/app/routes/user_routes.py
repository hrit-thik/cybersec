from flask import Blueprint, request, jsonify

from pysec_api.app.models import db, User # Adjusted import path
from pysec_api.app.routes.auth_routes import token_required # Adjusted import path

user_bp = Blueprint('user', __name__, url_prefix='/users')

# Placeholder for routes
# (Will be implemented in subsequent steps of this subtask)


@user_bp.route('/me', methods=['GET'])
@token_required
def get_current_user_profile(current_user: User): # current_user is passed by token_required
    """
    Get the profile of the currently authenticated user.
    """
    if not current_user:
        # This case should ideally be handled by token_required, but as a safeguard:
        return jsonify({"message": "User not found or token invalid."}), 404 
        
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'created_at': current_user.created_at.isoformat() if current_user.created_at else None
    }), 200


@user_bp.route('/me', methods=['PUT'])
@token_required
def update_current_user_profile(current_user: User): # current_user is passed by token_required
    """
    Update the profile of the currently authenticated user.
    Allows updating email and/or username.
    """
    data = request.get_json()

    if not data:
        return jsonify({'message': 'No input data provided'}), 400

    updated = False

    # Update email
    new_email = data.get('email')
    if new_email:
        if not isinstance(new_email, str) or not new_email.strip():
            return jsonify({'message': 'Email must be a non-empty string'}), 400
        
        existing_user_with_email = User.query.filter(User.email == new_email, User.id != current_user.id).first()
        if existing_user_with_email:
            return jsonify({'message': 'This email is already taken by another user'}), 409
        current_user.email = new_email
        updated = True

    # Update username
    new_username = data.get('username')
    if new_username:
        if not isinstance(new_username, str) or not new_username.strip():
            return jsonify({'message': 'Username must be a non-empty string'}), 400

        existing_user_with_username = User.query.filter(User.username == new_username, User.id != current_user.id).first()
        if existing_user_with_username:
            return jsonify({'message': 'This username is already taken by another user'}), 409
        current_user.username = new_username
        updated = True
    
    if updated:
        try:
            db.session.commit()
            return jsonify({
                'message': 'Profile updated successfully',
                'user': {
                    'id': current_user.id,
                    'username': current_user.username,
                    'email': current_user.email,
                    'created_at': current_user.created_at.isoformat() if current_user.created_at else None
                }
            }), 200
        except Exception as e: # pragma: no cover
            db.session.rollback()
            return jsonify({'message': f'Failed to update profile: {str(e)}'}), 500
    else:
        return jsonify({'message': 'No updatable fields provided or values are the same'}), 200 # Or 304 Not Modified
