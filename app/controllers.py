from app import r,session, jwt, producer
from app.models import user_schema, users_schema, UserModel
from flask import request
from flask_restful import Resource
from marshmallow import ValidationError
from flask_jwt_extended import create_access_token, decode_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from sqlalchemy.exc import IntegrityError, InvalidRequestError
from http import HTTPStatus
from functools import wraps
from datetime import datetime
import hashlib
import json

def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        identity = get_jwt_identity()
        if identity['is_admin']:
            return function(*args,**kwargs)
        else:
            return {"errors":"Only admin is permitted for this action"}, HTTPStatus.FORBIDDEN 
    return wrapper

def kafkaMessage(model, id, data, action):
    return {"model": model,
    "id":id,
    "data":data,
    "action": action,
    "action_time": datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    }

def updateUser(userId, data):
    user = r.get(name=str(userId))
    if user:
        r.delete(userId)
    userQuery = session.query(UserModel).filter(UserModel.id == userId)
    user = userQuery.first()
    if user:
        userQuery.update(data)
        producer.send('ims',kafkaMessage("UserModel",userId,data,"UPDATE")) #KAFKA
        session.commit()
        return {"message": "User updated successfully"}, HTTPStatus.OK

    return {"errors": "User with this id does not exist"}, HTTPStatus.NOT_FOUND

class UserCreation(Resource):
    @admin_required
    def post(self):
        data = request.get_json()
        data["password"] = hashlib.sha256(data["password"].encode("utf-8")).hexdigest()

        try:
            new_user = user_schema.load(data)
            id = new_user.save_to_db()
            producer.send('ims',kafkaMessage("UserModel",id,data,"CREATE")) #KAFKA
            return {"message": "User created successfully"}, HTTPStatus.CREATED
        except ValidationError as err:
            return {"errors":err.messages}, HTTPStatus.BAD_REQUEST
        except IntegrityError as err:
            session.rollback()
            return {"errors":str(err.__cause__)}, HTTPStatus.BAD_REQUEST

#Resource for reading, updating and deleting a specific user
class User(Resource):
    def get(self, userId):
        user = r.get(name=str(userId))

        if user is None:
            user = session.query(UserModel).get(userId)
            if user:
                user = user_schema.dump(user)
                user = json.dumps(user)
                r.set(name=str(userId), value=user, ex=3000)
            else:
                return {"errors":"User does not exist"}, HTTPStatus.NOT_FOUND

        return json.loads(user)

    @admin_required
    def put(self, userId):
        data = request.get_json()
        try:
            user_schema.load(data)
            data["password"] = hashlib.sha256(data["password"].encode("utf-8")).hexdigest()
            return updateUser(userId, data) 
        except ValidationError as err:
            return {"errors":err.messages}, HTTPStatus.BAD_REQUEST
        except IntegrityError as err:
            session.rollback()
            return {"errors":str(err.__cause__)}, HTTPStatus.BAD_REQUEST

    @admin_required
    def patch(self, userId):
        data = request.get_json()
        
        for key in data:
            if key=="password":
                data[key] = hashlib.sha256(data[key].encode("utf-8")).hexdigest()

        try:
            return updateUser(userId, data)
        except (IntegrityError, InvalidRequestError) as err:
            session.rollback()
            return {"errors":str(err.__cause__)}, HTTPStatus.BAD_REQUEST
        except Exception as err:
            return {"errors":str(err.__cause__)}, HTTPStatus.BAD_REQUEST        
        
    @admin_required
    def delete(self, userId):
        user = session.query(UserModel).get(userId)
        if user:
            user.remove_from_db()
            r.delete(userId)
            producer.send('ims',kafkaMessage(userId,"DELETE")) #KAFKA
            return {"message": "User successfully deleted"}, HTTPStatus.OK
        else:
            return {"errors": "User does not exist"}, HTTPStatus.NOT_FOUND

class UserLogin(Resource):
    def post(self):
        data = request.get_json()

        user = session.query(UserModel).filter(UserModel.username == data["username"]).first()

        if user and not user.is_active:
            return {"errors": "Your account is inactive."}, HTTPStatus.FORBIDDEN

        if user and user.password == hashlib.sha256(data["password"].encode("utf-8")).hexdigest():
            user_identity = {
                "id": user.id,
                "username": user.username,
                "is_admin": user.is_admin
                }
            jwt_accessToken = create_access_token(identity=user_identity, fresh=True)
            return {"access_token": jwt_accessToken}, HTTPStatus.OK

        return {"errors": "Invalid username or password"}, HTTPStatus.UNAUTHORIZED

class JWTVerification(Resource):
    def post(self):
        data = request.get_json()
        decoded_token = decode_token(data["access_token"])

        return decoded_token

class Users(Resource):
    def get(self):
        args = request.args
        if args:
            try:
                result = session.query(UserModel).filter_by(**args).all()
                return users_schema.dump(result), HTTPStatus.OK
            except InvalidRequestError as err:
                return {"errors":str(err.__cause__)}, HTTPStatus.BAD_REQUEST                
        
        result = session.query(UserModel).all()

        return users_schema.dump(result), HTTPStatus.OK
