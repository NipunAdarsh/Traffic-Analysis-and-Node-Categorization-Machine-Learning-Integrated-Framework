def test_root_redirects_to_login(client):
    response = client.get('/')
    assert response.status_code == 302
    assert b'/login' in response.data

def test_dashboard_redirect_unauthorized(client):
    response = client.get('/dashboard')
    # Should redirect to login if not authenticated
    assert response.status_code == 302
    assert b'/login' in response.data

def test_login_page(client):
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Traffic Analysis System' in response.data
