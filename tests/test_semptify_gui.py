import pytest
from Semptify import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c

def test_semptify_gui_index(client):
    rv = client.get('/semptify-gui/')
    assert rv.status_code == 200
    assert b"Semptify GUI (placeholder)" in rv.data
