import pytest
from SemptifyGUI import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_virtual_office_page(client):
    """Test that the virtual office landing page loads correctly"""
    rv = client.get('/office')
    assert rv.status_code == 200
    assert b'Virtual Office' in rv.data
    assert b'Meeting Room' in rv.data
    assert b'AI Assistant' in rv.data

def test_virtual_meeting_page(client):
    """Test that the virtual meeting room page loads correctly"""
    rv = client.get('/office/meeting')
    assert rv.status_code == 200
    assert b'Meeting Room' in rv.data
    assert b'Meeting Notes' in rv.data
    assert b'AI Assistant' in rv.data

def test_office_navigation_links(client):
    """Test that navigation links work on virtual office page"""
    rv = client.get('/office')
    assert rv.status_code == 200
    assert b'/office/meeting' in rv.data
    assert b'/copilot' in rv.data
    assert b'/vault' in rv.data
    assert b'/resources' in rv.data

def test_meeting_room_features(client):
    """Test that meeting room has expected features"""
    rv = client.get('/office/meeting')
    assert rv.status_code == 200
    assert b'meeting-notes' in rv.data
    assert b'Save Notes' in rv.data
    assert b'assistant-form' in rv.data or b'AI provider is not configured' in rv.data
