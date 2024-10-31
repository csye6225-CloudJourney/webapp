import json
from flask import Flask, request, Response, jsonify
from sqlalchemy import create_engine, Column, String, DateTime, ForeignKey, event
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
import os
import re
import bcrypt
from collections import OrderedDict
from sqlalchemy import LargeBinary
from dotenv import load_dotenv
from statsd import StatsClient
import time
import logging
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Set up StatsD client
statsd = StatsClient(host='localhost', port=8125, prefix='webapp')

# Set up logging to console
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
logger.addHandler(console_handler)

# Database setup
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "webapp_db")

if not DB_USERNAME or not DB_PASSWORD:
    logger.error("Database credentials are not set in environment variables.")
    raise EnvironmentError("Database credentials are not set in environment variables.")

DATABASE_URL = f"postgresql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
engine = create_engine(DATABASE_URL)
Base = declarative_base()
Session = sessionmaker(bind=engine)

# Database Models
class User(Base):
    __tablename__ = 'users'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    password = Column(LargeBinary, nullable=False)
    email = Column(String, unique=True, nullable=False)
    account_created = Column(DateTime(timezone=True), server_default=func.now())
    account_updated = Column(DateTime(timezone=True), onupdate=func.now())

class Image(Base):
    __tablename__ = 'images'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    file_name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    upload_date = Column(DateTime(timezone=True), default=func.now())
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)

# Bootstrap database
def bootstrap_database():
    try:
        Base.metadata.create_all(engine)
        logger.info("Database bootstrapped successfully.")
    except SQLAlchemyError as e:
        logger.error(f"Error bootstrapping the database: {e}")
        raise

# Helper functions
def format_datetime_utc(dt):
    return dt.astimezone().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Authentication helper
def authenticate_user():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return None
    session = Session()
    try:
        user = session.query(User).filter_by(email=auth.username).first()
        if user and bcrypt.checkpw(auth.password.encode('utf-8'), user.password):
            return user
        else:
            return None
    except Exception as e:
        logger.error(f"Error during authentication: {e}")
        return None
    finally:
        session.close()

# Decorator to track API metrics
def track_metrics(endpoint):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            statsd.incr(f"{endpoint}.count")
            try:
                response = func(*args, **kwargs)
                return response
            finally:
                elapsed_time = (time.time() - start_time) * 1000  # milliseconds
                statsd.timing(f"{endpoint}.response_time", elapsed_time)
        return wrapper
    return decorator

# Endpoints
@app.route('/v1/user', methods=['POST'])
@track_metrics('user_create')
def create_user():
    if request.content_type != 'application/json' or 'Accept' not in request.headers:
        logger.error("Invalid content type or missing Accept header.")
        return Response(status=400)

    data = request.get_json()
    required_fields = ['first_name', 'last_name', 'password', 'email']
    if not all(field in data for field in required_fields):
        logger.error("Missing required fields in the request.")
        return Response(status=400)

    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, data['email']):
        logger.error("Invalid email format.")
        return Response(status=400)

    hashed_password = hash_password(data['password'])
    new_user = User(
        first_name=data['first_name'],
        last_name=data['last_name'],
        password=hashed_password,
        email=data['email']
    )

    session = Session()
    try:
        session.add(new_user)
        session.commit()
        created_user = session.query(User).filter_by(email=new_user.email).first()
        account_updated = created_user.account_updated or created_user.account_created
        response_data = OrderedDict([
            ('id', str(created_user.id)),
            ('first_name', created_user.first_name),
            ('last_name', created_user.last_name),
            ('email', created_user.email),
            ('account_created', format_datetime_utc(created_user.account_created)),
            ('account_updated', format_datetime_utc(account_updated))
        ])
        response_json = json.dumps(response_data)
        logger.info(f"User created successfully: {created_user.email}")
        return Response(response=response_json, status=201, mimetype='application/json')
    except IntegrityError:
        session.rollback()
        logger.error("Email already exists.")
        return Response(status=400)
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Database error during user creation: {e}")
        return Response(status=503)
    finally:
        session.close()

@app.route('/v1/user/self', methods=['GET', 'PUT'])
@track_metrics('user_self')
def user_self():
    user = authenticate_user()
    if not user:
        logger.error("Authentication failed.")
        return Response(status=401)

    if request.method == 'GET':
        response_data = OrderedDict([
            ('id', str(user.id)),
            ('first_name', user.first_name),
            ('last_name', user.last_name),
            ('email', user.email),
            ('account_created', format_datetime_utc(user.account_created)),
            ('account_updated', format_datetime_utc(user.account_updated or user.account_created))
        ])
        response_json = json.dumps(response_data)
        logger.info(f"User details retrieved: {user.email}")
        return Response(response=response_json, status=200, mimetype='application/json')

    elif request.method == 'PUT':
        if request.content_type != 'application/json' or 'Accept' not in request.headers:
            logger.error("Invalid content type or missing Accept header.")
            return Response(status=400)

        data = request.get_json()
        if not data:
            logger.error("No data provided in the request.")
            return Response(status=204)

        allowed_fields = ['first_name', 'last_name', 'password']
        if not any(field in data for field in allowed_fields):
            logger.error("No valid fields to update.")
            return Response(status=400)

        session = Session()
        try:
            user_in_db = session.query(User).filter_by(id=user.id).first()
            if 'first_name' in data:
                user_in_db.first_name = data['first_name']
            if 'last_name' in data:
                user_in_db.last_name = data['last_name']
            if 'password' in data:
                user_in_db.password = hash_password(data['password'])
            user_in_db.account_updated = func.now()
            session.commit()
            logger.info(f"User updated successfully: {user.email}")
            return Response(status=204)
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error during user update: {e}")
            return Response(status=503)
        finally:
            session.close()

# Health check endpoint
@app.route('/healthz', methods=['GET'])
@track_metrics('health_check')
def health_check():
    if request.args or request.data:
        logger.error("Health check endpoint received unexpected data.")
        return Response(status=400)

    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
            headers = {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'X-Content-Type-Options': 'nosniff'
            }
            logger.info("Health check successful.")
            return Response(status=200, headers=headers)
    except SQLAlchemyError as e:
        headers = {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'X-Content-Type-Options': 'nosniff'
        }
        logger.error(f"Health check failed: {e}")
        return Response(status=503, headers=headers)

# Method Not Allowed responses for disallowed methods on /healthz
@app.route('/healthz', methods=['POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def method_not_allowed():
    headers = {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'X-Content-Type-Options': 'nosniff'
    }
    return Response(status=405, headers=headers)

if __name__ == '__main__':
    bootstrap_database()
    app.run(host='0.0.0.0', port=8080)