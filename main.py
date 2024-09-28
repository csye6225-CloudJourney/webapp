from flask import Flask, request, Response
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
import os

app = Flask(__name__)

#Database configuration, use environment variables or default values
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "webapp_db")

#prompt for dbuser and pass
if not DB_USER or not DB_PASSWORD:
    raise EnvironmentError("Database credentials are not set in environment variables.")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

#create the SQLAlchemy engine
engine = create_engine(DATABASE_URL)

#Health check endpoint
@app.route('/healthz', methods=['GET'])
def health_check():
    #prevent payload in request
    if request.args:
        return Response(status=400)

    try:
        #Try to connect to the database
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
    
# Only allow GET method
@app.route('/healthz', methods=['POST', 'PUT', 'DELETE', 'PATCH'])
def method_not_allowed():
    headers = {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'X-Content-Type-Options': 'nosniff'
    }
    return Response(status=405, headers=headers)

app.run(host='0.0.0.0', port=8080)