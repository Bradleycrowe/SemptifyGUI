import pytest
from Semptify import app
import json

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_get_methods(client):
    rv = client.get('/semptify-gui/api/delivery/methods')
    assert rv.status_code == 200
    data = rv.get_json()
    assert 'methods' in data
    assert any(m['id'] == 'email' for m in data['methods'])


def test_create_email_delivery(client):
    payload = {"method": "email", "details": {"email": "bob@example.com"}}
    rv = client.post('/semptify-gui/api/delivery', data=json.dumps(payload), content_type='application/json')
    assert rv.status_code == 200
    data = rv.get_json()
    assert 'delivery' in data
    assert data['delivery']['status'] == 'delivered'


def test_create_missing_field(client):
    payload = {"method": "email", "details": {}}
    rv = client.post('/semptify-gui/api/delivery', data=json.dumps(payload), content_type='application/json')
    assert rv.status_code == 400
    data = rv.get_json()
    assert 'error' in data
