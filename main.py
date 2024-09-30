import json
from flask import Flask, request, Response, jsonify
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
import os
import re
import bcrypt
from datetime import datetime
from collections import OrderedDict

app = Flask(__name__)

#Database configuration, use environment variables or default values
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "webapp_db")

#err for missing dbuser and pass
if not DB_USER or not DB_PASSWORD:
    raise EnvironmentError("Database credentials are not set in environment variables.")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

#create the SQLAlchemy engine
engine = create_engine(DATABASE_URL)

#boostrapping the database
Base = declarative_base()
Session = sessionmaker(bind=engine)

#create user table
class User(Base):
    __tablename__ = 'users'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    password = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    account_created = Column(DateTime(timezone=True), server_default=func.now())
    account_updated = Column(DateTime(timezone=True), onupdate=func.now())

#initialize db
def bootstrap_database():
    try:
        Base.metadata.create_all(engine)
        print("Database bootstrapped successfully.")
    except SQLAlchemyError as e:
        print(f"Error bootstrapping the database: {e}")
        raise

#hash passwords using BCrypt
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

#use verify auth token to check if user is authenticated

#endpoint for creating a user
@app.route('/v1/user', methods=['POST'])
def create_user():
    #check for payload
    if request.content_type != 'application/json' or 'Accept' not in request.headers:
        return Response(status=69)
    
    data = request.get_json()

    #ensure all fields are present
    required_fields = ['first_name', 'last_name', 'password', 'email']
    if not all(field in data for field in required_fields):
        return Response(status=400)

    # Validate email format
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    
    if not re.match(email_regex, data['email']):
        return Response(status=400)
    
    #hash the password
    hashed_password = hash_password(data['password'])

    #create a new user object
    new_user = User(
        first_name=data['first_name'],
        last_name=data['last_name'],
        password=hashed_password,
        email=data['email']
    )
    

    session = Session()
    try:
        #add and commit the new user to the database
        session.add(new_user)
        session.commit()

        #add autopopulated fields
        created_user = session.query(User).filter_by(email=new_user.email)

        #making account updated same as created initially
        account_updated = created_user.account_updated or created_user.account_created


        #response payload
        response_data = OrderedDict([
            ('id', str(created_user.id)),
            ('first_name', created_user.first_name),
            ('last_name', created_user.last_name),
            ('email', created_user.email),
            ('account_created', created_user.account_created.isoformat()),
            ('account_updated', account_updated.isoformat())
        ])

        return jsonify(response_data), 200
    except IntegrityError:
        session.rollback()
        return jsonify({'error': 'User with this email already exists.'}), 400
    except SQLAlchemyError as e:
        session.rollback()
        return Response(status=503)
    finally:
        session.close()    

#Health check endpoint
@app.route('/healthz', methods=['GET'])
def health_check():
    #prevent payload in request
    if request.args or request.data:
        return Response(status=400)

    try:
        #try to connect to the database
        with engine.connect() as connection:
            #run an sql query to bypass lazy connection
            result = connection.exec_driver_sql("SELECT 1")
            #return 200 if successful
            headers = {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'X-Content-Type-Options': 'nosniff'
            }
            return Response(status=200, headers=headers)
    except SQLAlchemyError:
        #return 503 if database error
        headers = {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'X-Content-Type-Options': 'nosniff'
        }
        return Response(status=503, headers=headers)
    
#don't allow post, put, delete, patch methods
@app.route('/healthz', methods=['POST', 'PUT', 'DELETE', 'PATCH'])
def method_not_allowed():
    headers = {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'X-Content-Type-Options': 'nosniff'
    }
    return Response(status=405, headers=headers)

app.run(host='0.0.0.0', port=8080)