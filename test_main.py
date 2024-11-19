import pytest
from unittest.mock import MagicMock, patch
import bcrypt
from datetime import datetime, timezone
import uuid
import logging
import os
from sqlalchemy.exc import IntegrityError  # Import IntegrityError

# Suppress Deprecation Warnings
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Set environment variables before importing main
os.environ['DB_USERNAME'] = 'test_user'
os.environ['DB_PASSWORD'] = 'test_pass'
os.environ['SNS_TOPIC_ARN'] = 'arn:aws:sns:us-east-1:123456789012:TestTopic'

# Mock necessary components before importing main
with patch('logging.getLogger') as mock_get_logger, \
     patch('statsd.StatsClient', MagicMock()), \
     patch('sqlalchemy.create_engine') as mock_create_engine, \
     patch('sqlalchemy.orm.sessionmaker') as mock_sessionmaker, \
     patch('boto3.client') as mock_boto3_client:  # Mock boto3.client

    # Mock the logger to prevent actual logging during tests
    mock_logger = logging.getLogger('test_logger')
    mock_get_logger.return_value = mock_logger

    # Mock the engine and sessionmaker
    mock_engine = MagicMock()
    mock_create_engine.return_value = mock_engine

    mock_sessionmaker_instance = MagicMock()
    mock_sessionmaker.return_value = mock_sessionmaker_instance

    # Mock SNS client
    mock_sns_client = MagicMock()
    mock_boto3_client.return_value = mock_sns_client

    from main import app, Session  # Import Session directly

# Fixture for the test client
@pytest.fixture(scope='function')
def client():
    with app.test_client() as client:
        yield client

def test_health_check(client):
    """Test health check endpoint"""
    response = client.get('/healthz')
    assert response.status_code == 200

def test_create_user_success(client):
    """Test creating a user with mocked DB interactions"""
    # Mock session
    mock_session = MagicMock()
    mock_sessionmaker_instance.return_value = mock_session  # Use the mocked sessionmaker instance

    # Simulate no existing user with the same email
    mock_session.query.return_value.filter_by.return_value.first.return_value = None

    # Simulate successful commit
    mock_session.commit.return_value = None

    # Simulate the return of the created user after commit
    mock_user = MagicMock()
    mock_user.id = uuid.uuid4()
    mock_user.first_name = 'Test'
    mock_user.last_name = 'User'
    mock_user.email = 'test.user@example.com'
    mock_user.account_created = datetime.now(timezone.utc)
    mock_user.account_updated = datetime.now(timezone.utc)
    mock_session.query.return_value.filter_by.return_value.first.return_value = mock_user  # Simulate retrieval

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

    # Verify SNS client was called
    mock_boto3_client.assert_called_once_with('sns', region_name='us-east-1')
    mock_sns_client.publish.assert_called_once()

    assert response.status_code == 201

def test_create_user_existing_email(client):
    """Test creating a user with an existing email (mocked)"""
    # Mock session
    mock_session = MagicMock()
    mock_sessionmaker_instance.return_value = mock_session  # Use the mocked sessionmaker instance

    # Simulate user already exists
    mock_user = MagicMock()
    mock_session.query.return_value.filter_by.return_value.first.return_value = mock_user

    # Simulate IntegrityError on commit
    mock_session.commit.side_effect = IntegrityError(None, None, Exception("Integrity error"))

    payload = {
        'first_name': 'Test',
        'last_name': 'User',
        'password': 'testpassword',
        'email': 'existing.user@example.com'
    }
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    response = client.post('/v1/user', json=payload, headers=headers)
    assert response.status_code == 400

def test_authenticate_user_success(client):
    """Test successful user authentication"""
    # Mock session
    mock_session = MagicMock()
    mock_sessionmaker_instance.return_value = mock_session  # Use the mocked sessionmaker instance

    # Mock user object with hashed password
    hashed_password = bcrypt.hashpw(b'testpassword', bcrypt.gensalt())
    mock_user = MagicMock()
    mock_user.password = hashed_password
    mock_user.id = uuid.uuid4()
    mock_user.first_name = 'Test'
    mock_user.last_name = 'User'
    mock_user.email = 'test.user@example.com'
    mock_user.account_created = datetime.now(timezone.utc)
    mock_user.account_updated = datetime.now(timezone.utc)

    # Simulate user found in the database
    mock_session.query.return_value.filter_by.return_value.first.return_value = mock_user

    # Base64 encoded 'test.user@example.com:testpassword'
    auth_headers = {
        'Authorization': 'Basic dGVzdC51c2VyQGV4YW1wbGUuY29tOnRlc3RwYXNzd29yZA==',
        'Content-Type': 'application/json'
    }

    response = client.get('/v1/user/self', headers=auth_headers)
    assert response.status_code == 200