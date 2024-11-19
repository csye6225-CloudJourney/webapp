import json
from flask import Flask, request, Response, jsonify
from sqlalchemy import create_engine, Column, String, DateTime, ForeignKey
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
import boto3
from functools import wraps
from datetime import datetime

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Set up StatsD client
statsd = StatsClient(host='localhost', port=8125, prefix='webapp')

# Set up CloudWatch logging
cloudwatch_logs_client = boto3.client('logs', region_name=os.getenv('AWS_REGION', 'us-east-1'))
log_group_name = '/webapp/application_logs'
log_stream_name = f'{datetime.utcnow().strftime("%Y/%m/%d")}/webapp'

# Create log group and stream if they don't exist
try:
    cloudwatch_logs_client.create_log_group(logGroupName=log_group_name)
except cloudwatch_logs_client.exceptions.ResourceAlreadyExistsException:
    pass
try:
    cloudwatch_logs_client.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)
except cloudwatch_logs_client.exceptions.ResourceAlreadyExistsException:
    pass

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Custom handler to send logs to CloudWatch
class CloudWatchHandler(logging.Handler):
    def emit(self, record):
        try:
            cloudwatch_logs_client.put_log_events(
                logGroupName=log_group_name,
                logStreamName=log_stream_name,
                logEvents=[{
                    'timestamp': int(time.time() * 1000),
                    'message': self.format(record)
                }]
            )
        except Exception as e:
            print(f"Failed to send log to CloudWatch: {e}")

cloudwatch_handler = CloudWatchHandler()
cloudwatch_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
cloudwatch_handler.setFormatter(formatter)
logger.addHandler(cloudwatch_handler)

# Database setup
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "webapp_db")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")

DATABASE_URL = f"postgresql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
engine = create_engine(DATABASE_URL)
Base = declarative_base()
Session = sessionmaker(bind=engine)

# Initialize S3 client
s3_client = boto3.client('s3', region_name=os.getenv('AWS_REGION', 'us-east-1'))

# Decorator to count API calls and track response time
def track_api_metrics(endpoint):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            statsd.incr(f"{endpoint}.count")  # Count metric for API call
            try:
                response = func(*args, **kwargs)
                return response
            finally:
                elapsed_time = (time.time() - start_time) * 1000  # milliseconds
                statsd.timing(f"{endpoint}.response_time", elapsed_time)  # Timer for API call duration
        return wrapper
    return decorator

# Wrapper to time database queries
def track_database_query(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        elapsed_time = (time.time() - start_time) * 1000  # milliseconds
        statsd.timing('database.query_time', elapsed_time)  # Timer for DB query
        return result
    return wrapper

# Updated upload_to_s3 function to track timing
def upload_to_s3(file_data, bucket_name, key):
    try:
        start_time = time.time()
        response = s3_client.put_object(Bucket=bucket_name, Key=key, Body=file_data)
        elapsed_time = (time.time() - start_time) * 1000  # milliseconds
        statsd.timing('s3.upload_time', elapsed_time)  # Timer for S3 upload time
        return f"s3://{bucket_name}/{key}"
    except Exception as e:
        logger.error(f"Failed to upload to S3: {e}")
        return None

def delete_from_s3(bucket_name, key):
    try:
        start_time = time.time()
        s3_client.delete_object(Bucket=bucket_name, Key=key)
        elapsed_time = (time.time() - start_time) * 1000  # milliseconds
        statsd.timing('s3.delete_time', elapsed_time)  # Timer for S3 delete time
    except Exception as e:
        logger.error(f"Failed to delete from S3: {e}")

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
    is_verified = Column(String, nullable=False, default=False)  

class TokenBlacklist(Base):
    __tablename__ = 'token_blacklist'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    token = Column(String, unique=True, nullable=False)
    blacklisted_at = Column(DateTime(timezone=True), server_default=func.now())

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
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')

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

# v1/user/self/pic endpoints
@app.route('/v1/user/self/pic', methods=['POST', 'GET', 'DELETE'])
@track_api_metrics('user_self_pic')
def user_profile_pic():
    user = authenticate_user()
    if not user:
        return Response(status=401)

    session = Session()
    try:
        if request.method == 'POST':
            existing_pic = session.query(Image).filter_by(user_id=user.id).first()
            if existing_pic:
                return jsonify({"error": "Image already exists. Please delete the existing image before uploading a new one."}), 409

            if 'file' not in request.files:
                return jsonify({"error": "No file provided"}), 400
            file = request.files['file']
            file_extension = file.filename.rsplit('.', 1)[-1].lower()
            if file_extension not in ('png', 'jpg', 'jpeg'):
                return jsonify({"error": "Invalid file type"}), 400

            key = f"{user.id}/{file.filename}"
            file_content = file.read()

            url = upload_to_s3(file_content, S3_BUCKET_NAME, key)
            if not url:
                return jsonify({"error": "Failed to upload image to S3"}), 500

            new_image = Image(
                file_name=file.filename,
                url=url,
                user_id=user.id,
                upload_date=datetime.utcnow()
            )
            session.add(new_image)
            session.commit()

            return jsonify({
                "file_name": new_image.file_name,
                "id": str(new_image.id),
                "url": new_image.url,
                "upload_date": format_datetime_utc(new_image.upload_date),
                "user_id": str(new_image.user_id)
            }), 201
        
        elif request.method == 'GET':
            image = session.query(Image).filter_by(user_id=user.id).first()
            if not image:
                return jsonify({"error": "No profile image found"}), 404
            return jsonify({
                "file_name": image.file_name,
                "id": str(image.id),
                "url": image.url,
                "upload_date": format_datetime_utc(image.upload_date),
                "user_id": str(image.user_id)
            })

        elif request.method == 'DELETE':
            image = session.query(Image).filter_by(user_id=user.id).first()
            if not image:
                return jsonify({"error": "No profile image found"}), 404

            delete_from_s3(S3_BUCKET_NAME, f"{user.id}/{image.file_name}")
            session.delete(image)
            session.commit()
            return Response(status=204)

    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Database error: {e}")
        return Response(status=503)
    finally:
        session.close()

# Endpoints for user account creation and management
@app.route('/v1/user', methods=['POST'])
@track_api_metrics('create_user')
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
        email=data['email'],
        is_verified=False  
    )

    session = Session()
    try:
        session.add(new_user)
        session.commit()

        # Publish SNS message for email verification
        sns_client = boto3.client('sns', region_name=os.getenv('AWS_REGION', 'us-east-1'))
        sns_topic_arn = os.getenv('SNS_TOPIC_ARN')

        if not sns_topic_arn:
            logger.error("SNS_TOPIC_ARN is not set in environment variables.")
            raise EnvironmentError("SNS_TOPIC_ARN environment variable is missing")

        sns_message = json.dumps({"email": new_user.email, "user_id": str(new_user.id)})
        sns_client.publish(
            TopicArn=sns_topic_arn,
            Message=sns_message
        )
        logger.info(f"SNS message sent for email verification: {sns_message}")

        created_user = session.query(User).filter_by(email=new_user.email).first()
        account_updated = created_user.account_updated or created_user.account_created
        response_data = OrderedDict([
            ('id', str(created_user.id)),
            ('first_name', created_user.first_name),
            ('last_name', created_user.last_name),
            ('email', created_user.email),
            ('account_created', format_datetime_utc(created_user.account_created)),
            ('account_updated', format_datetime_utc(account_updated)),
            ('is_verified', created_user.is_verified)
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

def authenticate_user():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return None
    session = Session()
    try:
        user = session.query(User).filter_by(email=auth.username).first()
        if user and bcrypt.checkpw(auth.password.encode('utf-8'), user.password):
            if not user.is_verified:
                logger.warning(f"Unverified user tried to authenticate: {auth.username}")
                return None  # Deny access for unverified users
            return user
        else:
            return None
    except Exception as e:
        logger.error(f"Error during authentication: {e}")
        return None
    finally:
        session.close()

@app.route('/v1/user/self', methods=['GET', 'PUT'])
@track_api_metrics('user_self')
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

@app.route('/v1/verify-email', methods=['GET'])
@track_api_metrics('verify_email')
def verify_email():
    """
    Verify the email of a user using the provided token.
    """
    token = request.args.get('token')
    if not token:
        return jsonify({"error": "Token is required"}), 400

    session = Session()
    try:
        # Check if token is blacklisted
        blacklisted_token = session.query(TokenBlacklist).filter_by(token=token).first()
        if blacklisted_token:
            return jsonify({"error": "Token is invalid or already used"}), 400

        # Extract user_id and expiration time from the token
        user_id, expiration_time = token.split(':')
        expiration_time = datetime.fromisoformat(expiration_time)

        # Check if the token has expired
        if datetime.utcnow() > expiration_time:
            # Add expired token to the blacklist
            blacklisted = TokenBlacklist(token=token)
            session.add(blacklisted)
            session.commit()
            return jsonify({"error": "Verification link has expired"}), 400

        # Verify user in the database
        user = session.query(User).filter_by(id=user_id).first()

        if not user:
            return jsonify({"error": "User not found"}), 404

        if user.is_verified:
            return jsonify({"message": "Email is already verified"}), 200

        # Mark user as verified and blacklist the token
        user.is_verified = True
        session.add(TokenBlacklist(token=token))  # Add token to blacklist
        session.commit()

        return jsonify({"message": "Email verified successfully"}), 200

    except Exception as e:
        logger.error(f"Error during email verification: {e}")
        return jsonify({"error": "Failed to verify email"}), 500

    finally:
        session.close()
        
# Health check endpoint
@app.route('/healthz', methods=['GET'])
@track_api_metrics('health_check')
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