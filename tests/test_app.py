import os
import tempfile
import pytest
from SemptifyGUI import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_index(client):
    rv = client.get('/')
    assert rv.status_code == 200
    # Check for key landing page elements
    assert b"Semptify" in rv.data
    assert b"Tenant Justice Automation" in rv.data
    assert b"Learn More" in rv.data
