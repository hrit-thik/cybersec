from flask import jsonify

def handle_400_bad_request(e):
    """Handles 400 Bad Request errors with a JSON response."""
    description = getattr(e, 'description', 'Bad request')
    return jsonify(error=description), 400

def handle_401_unauthorized(e):
    """Handles 401 Unauthorized errors with a JSON response."""
    description = getattr(e, 'description', 'Unauthorized')
    return jsonify(error=description), 401

def handle_403_forbidden(e):
    """Handles 403 Forbidden errors with a JSON response."""
    description = getattr(e, 'description', 'Forbidden')
    return jsonify(error=description), 403

def handle_404_not_found(e):
    """Handles 404 Not Found errors with a JSON response."""
    description = getattr(e, 'description', 'Not found')
    return jsonify(error=description), 404

def handle_409_conflict(e):
    """Handles 409 Conflict errors with a JSON response."""
    description = getattr(e, 'description', 'Conflict/Duplicate resource')
    return jsonify(error=description), 409

def handle_500_internal_server_error(e):
    """Handles 500 Internal Server Error with a JSON response."""
    # For 500 errors, we generally don't want to expose e.description or details from the original exception
    # to the client in production for security reasons.
    # The original exception 'e' will still be logged by Flask if DEBUG is False.
    return jsonify(error='Internal server error'), 500
