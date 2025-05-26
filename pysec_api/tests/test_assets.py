import json

# This is needed to ensure that the app module can be found if tests are run directly
# using `pytest tests/test_assets.py` from the root project directory.
import sys
import os
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


# Helper function to register and login a user, then return the token
def get_auth_token(client, username='testassetuser', email='asset@example.com', password='password'):
    """
    Helper function to register a new user and get an authentication token.
    Uses unique usernames/emails by default to avoid conflicts if called multiple times.
    """
    # Ensure unique user for each call to avoid conflicts if tests run in certain orders
    # or if the database is not reset per test function.
    # For module-scoped DB, this uniqueness is important.
    unique_suffix = str(os.urandom(4).hex()) # Simple way to get a short unique string
    reg_username = f"{username}_{unique_suffix}"
    reg_email = f"{unique_suffix}_{email}"

    reg_response = client.post('/auth/register', 
                               json={'username': reg_username, 'email': reg_email, 'password': password})
    
    # Check if registration was successful or if user already exists (e.g. if suffix wasn't unique enough, highly unlikely)
    if reg_response.status_code not in [201, 409]: # 409 if by some miracle user exists
        raise Exception(f"Failed to register user for token generation. Status: {reg_response.status_code}, Data: {reg_response.data}")

    login_res = client.post('/auth/login', 
                            json={'email': reg_email, 'password': password})
    
    if login_res.status_code != 200:
        raise Exception(f"Failed to login user for token generation. Status: {login_res.status_code}, Data: {login_res.data}")
        
    return login_res.get_json()['token']


def test_create_asset(client):
    """
    Test asset creation endpoint.
    """
    token = get_auth_token(client, username='create_asset_user', email='create_asset@example.com')
    
    response = client.post('/assets', 
                           json={'name': 'Test Asset Create', 'url': 'http://example-create.com'}, 
                           headers={'Authorization': f'Bearer {token}'})
    
    assert response.status_code == 201
    response_data = response.get_json()
    assert response_data['name'] == 'Test Asset Create'
    assert response_data['url'] == 'http://example-create.com'
    assert 'id' in response_data
    assert 'owner_id' in response_data # Should be set to the current_user's ID


def test_get_assets(client):
    """
    Test retrieving assets owned by the user.
    """
    token = get_auth_token(client, username='get_assets_user', email='get_assets@example.com')
    
    # Create a couple of assets for this user
    client.post('/assets', 
                json={'name': 'Asset1 for Get', 'url': 'http://example1-get.com'}, 
                headers={'Authorization': f'Bearer {token}'})
    client.post('/assets', 
                json={'name': 'Asset2 for Get', 'url': 'http://example2-get.com'}, 
                headers={'Authorization': f'Bearer {token}'})
    
    # Retrieve assets
    response = client.get('/assets', headers={'Authorization': f'Bearer {token}'})
    
    assert response.status_code == 200
    response_data = response.get_json()
    assert isinstance(response_data, list)
    # We expect at least the 2 assets we created. Could be more if other tests ran & didn't clean perfectly
    # or if the DB scope is module and user is shared. Using unique users per token helps.
    
    # Filter for assets created in this test to make assertion more robust
    # This assumes the get_auth_token helper creates genuinely unique users for each call.
    found_asset1 = any(item['name'] == 'Asset1 for Get' for item in response_data)
    found_asset2 = any(item['name'] == 'Asset2 for Get' for item in response_data)
    assert found_asset1
    assert found_asset2
    assert len(response_data) >= 2 # Check that at least these two are present


def test_get_specific_asset(client):
    """
    Test retrieving a specific asset by its ID.
    """
    token = get_auth_token(client, username='get_specific_user', email='get_specific@example.com')
    
    create_res = client.post('/assets', 
                             json={'name': 'Specific Asset', 'url': 'http://specific-asset.com'}, 
                             headers={'Authorization': f'Bearer {token}'})
    assert create_res.status_code == 201
    asset_id = create_res.get_json()['id']
    
    response = client.get(f'/assets/{asset_id}', headers={'Authorization': f'Bearer {token}'})
    
    assert response.status_code == 200
    response_data = response.get_json()
    assert response_data['id'] == asset_id
    assert response_data['name'] == 'Specific Asset'


def test_update_asset(client):
    """
    Test updating an existing asset.
    """
    token = get_auth_token(client, username='update_asset_user', email='update_asset@example.com')
    
    create_res = client.post('/assets', 
                             json={'name': 'Asset to Update', 'url': 'http://update-me.com', 'total_findings': 5}, 
                             headers={'Authorization': f'Bearer {token}'})
    assert create_res.status_code == 201
    asset_id = create_res.get_json()['id']
    
    update_payload = {'name': 'Updated Asset Name', 'url': 'http://updated-url.com', 'total_findings': 10}
    response = client.put(f'/assets/{asset_id}', 
                          json=update_payload, 
                          headers={'Authorization': f'Bearer {token}'})
    
    assert response.status_code == 200
    response_data = response.get_json()
    assert response_data['name'] == 'Updated Asset Name'
    assert response_data['url'] == 'http://updated-url.com'
    assert response_data['total_findings'] == 10


def test_delete_asset(client):
    """
    Test deleting an asset.
    """
    token = get_auth_token(client, username='delete_asset_user', email='delete_asset@example.com')
    
    create_res = client.post('/assets', 
                             json={'name': 'Asset to Delete', 'url': 'http://delete-me.com'}, 
                             headers={'Authorization': f'Bearer {token}'})
    assert create_res.status_code == 201
    asset_id = create_res.get_json()['id']
    
    delete_response = client.delete(f'/assets/{asset_id}', headers={'Authorization': f'Bearer {token}'})
    assert delete_response.status_code == 204 # No Content
    
    # Verify asset is gone
    get_response = client.get(f'/assets/{asset_id}', headers={'Authorization': f'Bearer {token}'})
    assert get_response.status_code == 404 # Not Found


def test_asset_access_forbidden_for_other_user(client):
    """
    Test that a user cannot access/modify another user's asset.
    """
    # User A (owner)
    owner_token = get_auth_token(client, username='owner_user', email='owner@example.com')
    create_res = client.post('/assets', 
                             json={'name': "Owner's Asset", 'url': 'http://owner-asset.com'}, 
                             headers={'Authorization': f'Bearer {owner_token}'})
    assert create_res.status_code == 201
    asset_id = create_res.get_json()['id']

    # User B (attacker)
    attacker_token = get_auth_token(client, username='attacker_user', email='attacker@example.com')

    # Attacker tries to GET, PUT, DELETE Owner's asset
    response_get = client.get(f'/assets/{asset_id}', headers={'Authorization': f'Bearer {attacker_token}'})
    assert response_get.status_code == 403 # Forbidden

    response_put = client.put(f'/assets/{asset_id}', 
                              json={'name': 'Attacker Update Attempt'}, 
                              headers={'Authorization': f'Bearer {attacker_token}'})
    assert response_put.status_code == 403 # Forbidden

    response_delete = client.delete(f'/assets/{asset_id}', headers={'Authorization': f'Bearer {attacker_token}'})
    assert response_delete.status_code == 403 # Forbidden


if __name__ == '__main__':
    pytest.main()
