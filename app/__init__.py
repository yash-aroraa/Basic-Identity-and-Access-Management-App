import os
from dotenv import load_dotenv
from flask import Flask
from flask_restful import Api
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask_jwt_extended import JWTManager

app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv("SECRET_KEY").encode('utf8')
#Connection to Postgresql
db = create_engine(os.getenv("POSTGRES_DATABASE_URI"))
Base = declarative_base()
Session = sessionmaker(bind=db)
session = Session()

#Restful
api = Api(app)

#jwt
jwt = JWTManager(app)

from app.views import User, UserCreation, UserLogin, JWTVerification, Users


#Endpoint generation for each resource
api.add_resource(UserCreation,'/user/create')
api.add_resource(User,'/user/<int:userId>')
api.add_resource(UserLogin,'/user/login')
api.add_resource(JWTVerification, '/jwt')
api.add_resource(Users, '/users')


