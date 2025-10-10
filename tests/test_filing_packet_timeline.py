"""Tests for filing packet timeline feature."""
import pytest
from SemptifyGUI import app as flask_app
import json
import os


@pytest.fixture
def app():
    """Flask app fixture."""
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    yield flask_app


@pytest.fixture
def client(app):
    """Test client fixture."""
    return app.test_client()


def test_packet_form_has_timeline_field(client):
    """Test that the filing packet form includes a timeline field."""
    resp = client.get('/resources/filing_packet')
    assert resp.status_code == 200
    html = resp.data.decode('utf-8')
    assert 'name="timeline"' in html
    assert 'Timeline (one event per line, format: YYYY-MM-DD - Event description)' in html
    assert 'YYYY-MM-DD - Event description' in html


def test_packet_preview_displays_timeline(client):
    """Test that the preview page displays timeline data."""
    # Get CSRF token first
    form_resp = client.get('/resources/filing_packet')
    assert form_resp.status_code == 200
    
    # Submit form with timeline data
    timeline_data = """2024-01-15 - Lease signed
2024-03-10 - First complaint about maintenance issue
2024-04-01 - Written notice sent to landlord"""
    
    resp = client.post('/resources/filing_packet_preview', data={
        'title': 'Security Deposit Dispute',
        'summary': 'Landlord failed to return deposit',
        'issues': 'Improper deductions',
        'parties': 'Jane Tenant, ABC Landlord',
        'date': '2024-05-20',
        'timeline': timeline_data,
        'sig_name': 'Jane Tenant',
        'sig_consented': 'on'
    }, follow_redirects=True)
    
    assert resp.status_code == 200
    html = resp.data.decode('utf-8')
    assert 'Timeline (Calendar Format)' in html
    assert '2024-01-15 - Lease signed' in html
    assert '2024-03-10 - First complaint about maintenance issue' in html
    assert '2024-04-01 - Written notice sent to landlord' in html


def test_packet_preview_without_timeline(client):
    """Test that the preview page handles missing timeline gracefully."""
    resp = client.post('/resources/filing_packet_preview', data={
        'title': 'Security Deposit Dispute',
        'summary': 'Landlord failed to return deposit',
        'issues': 'Improper deductions',
        'parties': 'Jane Tenant, ABC Landlord',
        'date': '2024-05-20',
        'sig_name': 'Jane Tenant',
        'sig_consented': 'on'
    }, follow_redirects=True)
    
    assert resp.status_code == 200
    html = resp.data.decode('utf-8')
    assert 'Timeline (Calendar Format)' in html
    assert '(No timeline entries provided)' in html


def test_packet_save_includes_timeline(client, tmp_path, monkeypatch):
    """Test that saving a packet includes timeline data."""
    # Mock vault directory
    vault_dir = tmp_path / "vault_test"
    vault_dir.mkdir()
    
    def mock_vault_user_dir(user_id):
        user_dir = vault_dir / user_id
        user_dir.mkdir(exist_ok=True)
        return str(user_dir)
    
    # Create a test user
    test_user = {
        'id': 'test_user_123',
        'name': 'Test User',
        'hash': 'test_hash',
        'enabled': True
    }
    
    # Mock authentication
    def mock_require_user():
        return test_user
    
    # Apply mocks
    import SemptifyGUI
    monkeypatch.setattr(SemptifyGUI, '_vault_user_dir', mock_vault_user_dir)
    monkeypatch.setattr(SemptifyGUI, '_require_user_or_401', mock_require_user)
    
    timeline_data = """2024-01-15 - Lease signed
2024-03-10 - First complaint"""
    
    resp = client.post('/resources/filing_packet_save', data={
        'title': 'Test Packet',
        'summary': 'Test summary',
        'issues': 'Test issues',
        'parties': 'Test parties',
        'date': '2024-05-20',
        'timeline': timeline_data,
        'sig_name': 'Test User',
        'sig_consented': 'on',
        'user_token': 'test_token'
    }, follow_redirects=True)
    
    assert resp.status_code == 200
    
    # Check that timeline was saved in the file
    files = list(vault_dir.glob('test_user_123/packet_*.txt'))
    assert len(files) > 0
    
    with open(files[0], 'r') as f:
        content = f.read()
        assert 'Timeline (Calendar Format)' in content
        assert '2024-01-15 - Lease signed' in content
        assert '2024-03-10 - First complaint' in content
