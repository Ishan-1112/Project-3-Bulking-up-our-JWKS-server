from main import app

def test_index():
    # Create a test client using the Flask application context
    with app.test_client() as client:
        # Send a GET request to the '/' route
        response = client.get('/')
        # Assert that the response status code is 200
        assert response.status_code == 200
        # Assert that the response data matches the expected message
        assert b'Welcome to the main page!' in response.data

def test_jwks():
    # Create a test client using the Flask application context
    with app.test_client() as client:
        # Send a GET request to the '/jwks' route
        response = client.get('/jwks')
        # Assert that the response status code is 404 (assuming '/jwks' is not defined in your routes)
        assert response.status_code == 404

def test_auth():
    # Create a test client using the Flask application context
    with app.test_client() as client:
        # Send a POST request to the '/auth' route
        response = client.post('/auth')
        # Assert that the response status code is 500 (assuming there is an internal server error in the '/auth' route)
        assert response.status_code == 500
