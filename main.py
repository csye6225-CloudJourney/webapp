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
import boto3
from botocore.exceptions import ClientError

load_dotenv()

app = Flask(__name__)

# Setting up environment variables for the database
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "webapp_db")

# Error for missing database credentials
if not DB_USERNAME or not DB_PASSWORD:
    raise EnvironmentError("Database credentials are not set in environment variables.")

DATABASE_URL = f"postgresql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Creating the SQLAlchemy engine
engine = create_engine(DATABASE_URL)

# Bootstrapping the database
Base = declarative_base()
Session = sessionmaker(bind=engine)

# S3 setup
s3_client = boto3.client('s3')
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
        print("Database bootstrapped successfully.")
    except SQLAlchemyError as e:
        print(f"Error bootstrapping the database: {e}")
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
    finally:
        session.close()

# Endpoint for creating a user
@app.route('/v1/user', methods=['POST'])
def create_user():
    # Check for payload
    if request.content_type != 'application/json' or 'Accept' not in request.headers:
        return Response(status=400)
    
    data = request.get_json()

    # Ensure all fields are present
    required_fields = ['first_name', 'last_name', 'password', 'email']
    if not all(field in data for field in required_fields):
        return Response(status=400)

    # Validate email format
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, data['email']):
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
        return Response(response=response_json, status=201, mimetype='application/json')
    except IntegrityError:
        session.rollback()
        return Response(status=400)
    except SQLAlchemyError as e:
        session.rollback()
        return Response(status=503)
    finally:
        session.close()

# Endpoint for user self details
@app.route('/v1/user/self', methods=['GET', 'PUT'])
def user_self():
    user = authenticate_user()
    if not user:
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
        return Response(response=response_json, status=200, mimetype='application/json')

    elif request.method == 'PUT':
        if request.content_type != 'application/json' or 'Accept' not in request.headers:
            return Response(status=400)
        
        data = request.get_json()
        if not data:
            return Response(status=204)

        allowed_fields = ['first_name', 'last_name', 'password', 'email']
        if not any(field in data for field in allowed_fields):
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
            if 'email' in data and data['email'] != user.email:
                return Response(status=400)
            session.commit()
            return Response(status=204)
        except SQLAlchemyError as e:
            session.rollback()
            return Response(status=503)
        finally:
            session.close()

# New Endpoint for Profile Picture Management
@app.route('/v1/user/self/pic', methods=['POST', 'GET', 'DELETE'])
def user_pic():
    user = authenticate_user()
    if not user:
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
        return Response("No file provided", status=400)

    file = request.files['file']
    if file.filename == '':
        return Response("No file selected", status=400)

    allowed_extensions = {'png', 'jpg', 'jpeg'}
    if not ('.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
        return Response("Invalid file type", status=400)

    file_name = f"{uuid.uuid4()}_{file.filename}"
    s3_key = f"{user.id}/{image.file_name}"  
    try:
        s3_client.upload_fileobj(file, S3_BUCKET_NAME, s3_key)
    except ClientError as e:
        print(e)
        return Response("Failed to upload to S3", status=400)

    session = Session()
    image = Image(
        file_name=file.filename,
        url=f"{S3_BUCKET_NAME}/{s3_key}",
        user_id=user.id
    )
    try:
        session.add(image)
        session.commit()
        response_data = {
            "file_name": image.file_name,
            "id": str(image.id),
            "url": image.url,
            "upload_date": image.upload_date.strftime('%Y-%m-%d'),
            "user_id": str(user.id)
        }
        return jsonify(response_data), 201
    except SQLAlchemyError as e:
        session.rollback()
        print(e)
        return Response("Failed to save image metadata", status=400)
    finally:
        session.close()

def get_image_metadata(user):
    session = Session()
    try:
        image = session.query(Image).filter_by(user_id=user.id).first()
        if not image:
            return Response("Image not found", status=404)

        response_data = {
            "file_name": image.file_name,
            "id": str(image.id),
            "url": image.url,
            "upload_date": image.upload_date.strftime('%Y-%m-%d'),
            "user_id": str(user.id)
        }
        return jsonify(response_data), 200
    except SQLAlchemyError as e:
        print(e)
        return Response("Error retrieving image metadata", status=404)
    finally:
        session.close()

def delete_image(user):
    session = Session()
    try:
        # Retrieve the image associated with the user
        image = session.query(Image).filter_by(user_id=user.id).first()
        if not image:
            return Response("Image not found", status=404)

        # Define the S3 object key based on the stored URL
        s3_key = image.url  # Ensure this matches the format you use in S3, e.g., "{user.id}/{image.file_name}"

        # Attempt to delete the image from the S3 bucket
        try:
            s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
            print("S3 deletion successful for key:", s3_key)
        except ClientError as e:
            print("Failed to delete image from S3:", e)
            return Response("Failed to delete image from S3", status=400)

        # Delete the image record from the database
        session.delete(image)
        session.commit()
        print("Image record successfully deleted from the database.")
        return Response(status=204)

    except SQLAlchemyError as e:
        session.rollback()
        print("Error deleting image from the database:", e)
        return Response("Error deleting image metadata", status=404)
    finally:
        session.close()

# Health check endpoint
@app.route('/healthz', methods=['GET'])
def health_check():
    if request.args or request.data:
        return Response(status=400)

    try:
        with engine.connect() as connection:
            result = connection.exec_driver_sql("SELECT 1")
            headers = {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'X-Content-Type-Options': 'nosniff'
            }
            return Response(status=200, headers=headers)
    except SQLAlchemyError:
        headers = {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'X-Content-Type-Options': 'nosniff'
        }
        return Response(status=503, headers=headers)

if __name__ == '__main__':
    bootstrap_database()
    app.run(host='0.0.0.0', port=8080)