import pytest
from unittest.mock import MagicMock
import bcrypt
from datetime import datetime, timezone
import uuid
from sqlalchemy.exc import IntegrityError
import os

os.environ.setdefault("AWS_REGION", "us-east-1")

@pytest.fixture
def client(mocker):
    """Set up a test client with mocked database connections."""
    # Mock the SQLAlchemy engine
    mock_engine = mocker.MagicMock()
    mocker.patch('main.engine', mock_engine)
    
    from main import app  # Import after the patches are applied
    with app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def aws_region(monkeypatch):
    """Set AWS region for boto3 calls."""
    monkeypatch.setenv("AWS_REGION", "us-east-1")

def test_health_check(mocker, client):
    """Test health check endpoint"""
    mock_connection = mocker.MagicMock()
    mocker.patch('main.engine.connect', return_value=mock_connection)
    mock_connection.exec_driver_sql.return_value = None
    
    response = client.get('/healthz')
    assert response.status_code == 200

def test_create_user_success(mocker, client):
    """Test creating a user with mock DB"""
    mock_session = mocker.MagicMock()
    mocker.patch('main.Session', return_value=mock_session)

    mock_user = mocker.MagicMock()
    mock_user.id = uuid.uuid4()
    mock_user.first_name = 'Test'
    mock_user.last_name = 'User'
    mock_user.email = 'test.user@example.com'
    mock_user.account_created = datetime.now(timezone.utc)
    mock_user.account_updated = datetime.now(timezone.utc)

    mock_session.query.return_value.filter_by.return_value.first.return_value = mock_user

    payload = {
        'first_name': 'Test',
        'last_name': 'User',
        'password': 'testpassword',
        'email': 'test.user@example.com'
    }
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    response = client.post('/v1/user', json=payload, headers=headers)
    assert response.status_code == 201

def test_create_user_existing_email(mocker, client):
    """Test creating a user with an existing email (mocked)"""
    mock_session = mocker.MagicMock()
    mocker.patch('main.Session', return_value=mock_session)
    mock_session.commit.side_effect = IntegrityError(None, None, Exception("Integrity error"))

    payload = {
        'first_name': 'Test',
        'last_name': 'User',
        'password': 'testpassword',
        'email': 'test.user@example.com'
    }
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    response = client.post('/v1/user', json=payload, headers=headers)
    assert response.status_code == 400

def test_authenticate_user_success(mocker, client):
    """Test successful user authentication"""
    mock_session = mocker.MagicMock()
    mocker.patch('main.Session', return_value=mock_session)

    mock_user = mocker.MagicMock()
    mock_user.password = bcrypt.hashpw(b'testpassword', bcrypt.gensalt())
    mock_user.id = uuid.uuid4()
    mock_user.first_name = 'Test'
    mock_user.last_name = 'User'
    mock_user.email = 'test.user@example.com'
    mock_user.account_created = datetime.now(timezone.utc)
    mock_user.account_updated = datetime.now(timezone.utc)

    mock_session.query.return_value.filter_by.return_value.first.return_value = mock_user

    auth_headers = {
        'Authorization': 'Basic dGVzdC51c2VyQGV4YW1wbGUuY29tOnRlc3RwYXNzd29yZA=='  # Base64 of test.user@example.com:testpassword
    }

    response = client.get('/v1/user/self', headers=auth_headers)
    assert response.status_code == 200