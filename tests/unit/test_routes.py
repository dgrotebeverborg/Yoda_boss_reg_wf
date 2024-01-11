import pytest
from app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_home_page(client):
    """ Test for the home page route. """
    response = client.get('/apply')
    print(response)
    assert response.status_code == 200
    assert b"Expected Content on Home Page" in response.data
