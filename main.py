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
import boto3
from botocore.exceptions import ClientError
from statsd import StatsClient
import time
import logging
import watchtower

load_dotenv()

app = Flask(__name__)

# Setting up StatsD client
statsd = StatsClient(host='localhost', port=8125, prefix='webapp')

# Setting up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create a CloudWatch Logs handler
handler = watchtower.CloudWatchLogHandler(log_group='webapp-logs')
logger.addHandler(handler)

# Optionally, add a StreamHandler to log to console as well
console_handler = logging.StreamHandler()
logger.addHandler(console_handler)

# Setting up environment variables for the database
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "webapp_db")

# Error for missing database credentials
if not DB_USERNAME or not DB_PASSWORD:
    logger.error("Database credentials are not set in environment variables.")
    raise EnvironmentError("Database credentials are not set in environment variables.")

DATABASE_URL = f"postgresql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Creating the SQLAlchemy engine
engine = create_engine(DATABASE_URL)

# Bootstrapping the database
Base = declarative_base()
Session = sessionmaker(bind=engine)

# SQLAlchemy event listeners for query timing
@event.listens_for(engine, "before_cursor_execute")
def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    conn.info.setdefault('query_start_time', []).append(time.time())

@event.listens_for(engine, "after_cursor_execute")
def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    total_time = time.time() - conn.info['query_start_time'].pop(-1)
    statsd.timing('db.query_time', total_time * 1000)  # milliseconds

# S3 setup with wrapper
class S3ClientWrapper:
    def __init__(self, client):
        self.client = client

    def __getattr__(self, name):
        func = getattr(self.client, name)

        def wrapped_func(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            elapsed_time = (time.time() - start_time) * 1000  # milliseconds
            statsd.timing(f"s3.{name}", elapsed_time)
            return result

        return wrapped_func

s3_client = S3ClientWrapper(boto3.client('s3'))
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")

# User table definition
class User(Base):
    __tablename__ = 'users'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    password = Column(LargeBinary, nullable=False)
    email = Column(String, unique=True, nullable=False)
    account_created = Column(DateTime(timezone=True), server_default=func.now())
    account_updated = Column(DateTime(timezone=True), onupdate=func.now())

# Image table definition
class Image(Base):
    __tablename__ = 'images'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    file_name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    upload_date = Column(DateTime(timezone=True), default=func.now())
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)

# Initialize database
def bootstrap_database():
    try:
        Base.metadata.create_all(engine)
        logger.info("Database bootstrapped successfully.")
    except SQLAlchemyError as e:
        logger.error(f"Error bootstrapping the database: {e}")
        raise

# Formatting datetime to UTC
def format_datetime_utc(dt):
    return dt.astimezone().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

# Hash passwords using BCrypt
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

# Endpoint for creating a user
@app.route('/v1/user', methods=['POST'])
@track_metrics('user_create')
def create_user():
    # Check for payload
    if request.content_type != 'application/json' or 'Accept' not in request.headers:
        logger.error("Invalid content type or missing Accept header.")
        return Response(status=400)
    
    data = request.get_json()

    # Ensure all fields are present
    required_fields = ['first_name', 'last_name', 'password', 'email']
    if not all(field in data for field in required_fields):
        logger.error("Missing required fields in the request.")
        return Response(status=400)

    # Validate email format
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, data['email']):
        logger.error("Invalid email format.")
        return Response(status=400)
    
    # Hash the password
    hashed_password = hash_password(data['password'])

    # Create a new user object
    new_user = User(
        first_name=data['first_name'],
        last_name=data['last_name'],
        password=hashed_password,
        email=data['email']
    )
    
    session = Session()
    try:
        # Add and commit the new user to the database
        session.add(new_user)
        session.commit()

        # Fetch created user details
        created_user = session.query(User).filter_by(email=new_user.email).first()

        # Setting account_updated to match account_created initially
        account_updated = created_user.account_updated or created_user.account_created

        # Response payload
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

# Endpoint for user self details
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

        if 'email' in data and data['email'] != user.email:
            logger.error("Email change is not allowed.")
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
            session.commit()
            logger.info(f"User updated successfully: {user.email}")
            return Response(status=204)
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error during user update: {e}")
            return Response(status=503)
        finally:
            session.close()

# Endpoint for Profile Picture Management
@app.route('/v1/user/self/pic', methods=['POST', 'GET', 'DELETE'])
@track_metrics('user_self_pic')
def user_pic():
    user = authenticate_user()
    if not user:
        logger.error("Authentication failed.")
        return Response(status=401)

    if request.method == 'POST':
        return upload_image(user)
    elif request.method == 'GET':
        return get_image_metadata(user)
    elif request.method == 'DELETE':
        return delete_image(user)

@app.route('/v1/user/self/pic', methods=['PUT', 'PATCH', 'HEAD', 'OPTIONS'])
def pic_method_not_allowed():
    return Response(status=405)

def upload_image(user):
    if 'file' not in request.files:
        logger.error("No file provided in the request.")
        return Response("No file provided", status=400)

    file = request.files['file']
    if file.filename == '':
        logger.error("No file selected in the request.")
        return Response("No file selected", status=400)

    allowed_extensions = {'png', 'jpg', 'jpeg'}
    if not ('.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
        logger.error("Invalid file type.")
        return Response("Invalid file type", status=400)

    file_extension = file.filename.rsplit('.', 1)[1].lower()
    file_name = f"{uuid.uuid4()}.{file_extension}"
    s3_key = f"{user.id}/{file_name}"  

    try:
        s3_client.upload_fileobj(file, S3_BUCKET_NAME, s3_key)
        logger.info(f"Image uploaded to S3: {s3_key}")
    except ClientError as e:
        logger.error(f"Failed to upload to S3: {e}")
        return Response("Failed to upload to S3", status=400)

    session = Session()
    image = Image(
        file_name=file_name,
        url=f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{s3_key}",
        user_id=user.id
    )
    try:
        # Check if user already has an image
        existing_image = session.query(Image).filter_by(user_id=user.id).first()
        if existing_image:
            # Delete existing image from S3
            existing_s3_key = f"{user.id}/{existing_image.file_name}"
            try:
                s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=existing_s3_key)
                logger.info(f"Existing image deleted from S3: {existing_s3_key}")
            except ClientError as e:
                logger.error(f"Failed to delete existing image from S3: {e}")
                return Response("Failed to delete existing image from S3", status=400)
            # Delete existing image record
            session.delete(existing_image)
            session.commit()
            logger.info("Existing image record deleted from the database.")

        # Add new image record
        session.add(image)
        session.commit()
        response_data = {
            "file_name": image.file_name,
            "id": str(image.id),
            "url": image.url,
            "upload_date": image.upload_date.strftime('%Y-%m-%d'),
            "user_id": str(user.id)
        }
        logger.info(f"Image metadata saved to database for user {user.email}")
        return jsonify(response_data), 201
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Failed to save image metadata: {e}")
        return Response("Failed to save image metadata", status=400)
    finally:
        session.close()

def get_image_metadata(user):
    session = Session()
    try:
        image = session.query(Image).filter_by(user_id=user.id).first()
        if not image:
            logger.error("Image not found for user.")
            return Response("Image not found", status=404)

        response_data = {
            "file_name": image.file_name,
            "id": str(image.id),
            "url": image.url,
            "upload_date": image.upload_date.strftime('%Y-%m-%d'),
            "user_id": str(user.id)
        }
        logger.info(f"Image metadata retrieved for user {user.email}")
        return jsonify(response_data), 200
    except SQLAlchemyError as e:
        logger.error(f"Error retrieving image metadata: {e}")
        return Response("Error retrieving image metadata", status=404)
    finally:
        session.close()

def delete_image(user):
    session = Session()
    try:
        # Retrieve the image associated with the user
        image = session.query(Image).filter_by(user_id=user.id).first()
        if not image:
            logger.error("Image not found for user.")
            return Response("Image not found", status=404)

        # Define the S3 object key based on the stored URL
        s3_key = f"{user.id}/{image.file_name}"

        # Attempt to delete the image from the S3 bucket
        try:
            s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
            logger.info(f"S3 deletion successful for key: {s3_key}")
        except ClientError as e:
            logger.error(f"Failed to delete image from S3: {e}")
            return Response("Failed to delete image from S3", status=400)

        # Delete the image record from the database
        session.delete(image)
        session.commit()
        logger.info("Image record successfully deleted from the database.")
        return Response(status=204)

    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Error deleting image from the database: {e}")
        return Response("Error deleting image metadata", status=404)
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

if __name__ == '__main__':
    bootstrap_database()
    app.run(host='0.0.0.0', port=8080)