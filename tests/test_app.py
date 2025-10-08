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
    assert b"SemptifyGUI is live" in rv.data

def test_index_has_viewport(client):
    rv = client.get('/')
    assert rv.status_code == 200
    assert b'<meta name="viewport" content="width=device-width, initial-scale=1">' in rv.data

def test_admin_has_viewport(client):
    rv = client.get('/admin?token=devtoken')
    assert rv.status_code == 200
    assert b'<meta name="viewport" content="width=device-width, initial-scale=1">' in rv.data

def test_sbom_list_has_viewport(client):
    rv = client.get('/sbom?token=devtoken')
    assert rv.status_code == 200
    assert b'<meta name="viewport" content="width=device-width, initial-scale=1">' in rv.data

def test_release_history_has_viewport(client):
    rv = client.get('/release_history?token=devtoken')
    assert rv.status_code == 200
    assert b'<meta name="viewport" content="width=device-width, initial-scale=1">' in rv.data

