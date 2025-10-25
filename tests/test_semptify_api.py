import pytest
from Semptify import app
import json

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_complaint_api_json(client):
    payload = {"name": "Bob", "issue": "broken sidewalk"}
    rv = client.post('/semptify-gui/api/complaint', data=json.dumps(payload), content_type='application/json')
    assert rv.status_code == 200
    data = rv.get_json()
    assert data and 'complaint' in data
    assert 'Bob' in data['complaint']


def test_complaint_api_form(client):
    rv = client.post('/semptify-gui/api/complaint', data={'name': 'Carol', 'issue': 'late rent'})
    assert rv.status_code == 200
    data = rv.get_json()
    assert data and 'complaint' in data
    assert 'Carol' in data['complaint']
