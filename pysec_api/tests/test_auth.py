import json

# This is needed to ensure that the app module can be found if tests are run directly
# using `pytest tests/test_auth.py` from the root project directory.
import sys
import os
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Test user registration
def test_register_user(client):
    """
    Test user registration endpoint.
    """
    response = client.post('/auth/register', 
                           json={'username': 'testuser_reg', 'email': 'test_reg@example.com', 'password': 'password'})
    
    assert response.status_code == 201
    response_data = response.get_json()
    assert 'User registered successfully' in response_data['message']
    assert response_data['user']['username'] == 'testuser_reg'
    assert response_data['user']['email'] == 'test_reg@example.com'

# Test user registration with existing username
def test_register_existing_username(client):
    """
    Test user registration with an already existing username.
    """
    # First, register a user
    client.post('/auth/register', 
                json={'username': 'existinguser', 'email': 'existing_user@example.com', 'password': 'password'})
    
    # Attempt to register another user with the same username
    response = client.post('/auth/register', 
                           json={'username': 'existinguser', 'email': 'another_email@example.com', 'password': 'password123'})
    
    assert response.status_code == 409
    assert 'User with this username or email already exists' in response.get_json()['message']

# Test user registration with existing email
def test_register_existing_email(client):
    """
    Test user registration with an already existing email.
    """
    # First, register a user
    client.post('/auth/register', 
                json={'username': 'anotheruser', 'email': 'existing_email@example.com', 'password': 'password'})

    # Attempt to register another user with the same email
    response = client.post('/auth/register', 
                           json={'username': 'yetanotheruser', 'email': 'existing_email@example.com', 'password': 'password123'})
    
    assert response.status_code == 409
    assert 'User with this username or email already exists' in response.get_json()['message']


# Test user login
def test_login_user(client):
    """
    Test user login endpoint.
    Relies on a user being registered.
    """
    # Register user first
    client.post('/auth/register', 
                json={'username': 'testlogin', 'email': 'login@example.com', 'password': 'password'})
    
    # Attempt to login
    response = client.post('/auth/login', 
                           json={'email': 'login@example.com', 'password': 'password'})
    
    assert response.status_code == 200
    response_data = response.get_json()
    assert 'token' in response_data
    assert 'Login successful' in response_data['message']

# Test user login with invalid credentials (wrong password)
def test_login_user_invalid_password(client):
    """
    Test user login with incorrect password.
    """
    client.post('/auth/register', 
                json={'username': 'testlogin_inv_pass', 'email': 'login_inv_pass@example.com', 'password': 'password'})
    
    response = client.post('/auth/login', 
                           json={'email': 'login_inv_pass@example.com', 'password': 'wrongpassword'})
    
    assert response.status_code == 401
    assert 'Invalid credentials' in response.get_json()['message']

# Test user login with non-existent email
def test_login_user_non_existent_email(client):
    """
    Test user login with an email that is not registered.
    """
    response = client.post('/auth/login', 
                           json={'email': 'nonexistent@example.com', 'password': 'password'})
    
    assert response.status_code == 401 # Or 404 depending on how you want to signal this
    assert 'Invalid credentials' in response.get_json()['message']


# Test accessing protected route without token
def test_access_protected_without_token(client):
    """
    Test accessing a protected route (/users/me) without an authentication token.
    """
    response = client.get('/users/me') # Assuming /users/me is a protected route
    
    assert response.status_code == 401
    response_data = response.get_json()
    # The error message comes from the token_required decorator's handling of missing token
    # or the centralized error handler for 401.
    # If centralized handler is active, it might be {'error': 'Unauthorized'} or similar.
    # The token_required decorator specifically returns {'message': 'Token is missing!'}
    assert 'Token is missing!' in response_data.get('message', response_data.get('error'))


# Test accessing protected route with an invalid token
def test_access_protected_with_invalid_token(client):
    """
    Test accessing a protected route with an invalid or malformed token.
    """
    response = client.get('/users/me', headers={'Authorization': 'Bearer invalidtoken123'})
    
    assert response.status_code == 401
    response_data = response.get_json()
    # Message from token_required decorator or centralized 401 handler
    assert 'Token is invalid!' in response_data.get('message', response_data.get('error'))


if __name__ == '__main__':
    # This allows running pytest directly on this file if needed.
    # `pytest tests/test_auth.py`
    # Make sure conftest.py is in the same directory or an importable path.
    pytest.main()
