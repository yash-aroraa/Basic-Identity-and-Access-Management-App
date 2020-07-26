import os
from dotenv import load_dotenv
from flask import Flask
from flask_restful import Api
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask_jwt_extended import JWTManager
import redis

app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv("SECRET_KEY").encode('utf8')
#Connection to Postgresql
db = create_engine(os.getenv("POSTGRES_DATABASE_URI"))
Base = declarative_base()
Session = sessionmaker(bind=db)
session = Session()

#redis server initialization
r = redis.StrictRedis(host="127.0.0.1",port="6379", db=0)

#jwt
jwt = JWTManager(app)

#Restful
api = Api(app)

#Routes Initialization
from app.routes import initialize_routes
initialize_routes(api)