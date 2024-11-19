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

    # Mock different AWS services
    mock_sns_client = MagicMock()
    mock_s3_client = MagicMock()
    mock_logs_client = MagicMock()

    def boto3_client_side_effect(service_name, *args, **kwargs):
        if service_name == 'sns':
            return mock_sns_client
        elif service_name == 's3':
            return mock_s3_client
        elif service_name == 'logs':
            return mock_logs_client
        else:
            raise ValueError(f"Unexpected service: {service_name}")

    mock_boto3_client.side_effect = boto3_client_side_effect

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
    mock_sns_client.publish.assert_called_once_with(
        TopicArn=os.environ['SNS_TOPIC_ARN'],
        Message=MagicMock()
    )

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