from app import r,session, jwt
from app.models import user_schema, users_schema, UserModel
from flask import request
from flask_restful import Resource
from marshmallow import ValidationError
from flask_jwt_extended import create_access_token, decode_token, jwt_required, get_jwt_identity
from sqlalchemy.exc import IntegrityError, InvalidRequestError
from http import HTTPStatus
import hashlib
import pickle


def updateUser(userId, data):
    user = r.get(name=str(userId))
    if user:
        r.delete(userId)
    userQuery = session.query(UserModel).filter(UserModel.id == userId)
    user = userQuery.first()
    if user:
        userQuery.update(data)
        session.commit()
        return {"message": "User updated successfully"}, HTTPStatus.OK

    return {"errors": "User with this id does not exist"}

class UserCreation(Resource):
    @jwt_required
    def post(self):
        identity = get_jwt_identity()
        if identity["is_admin"]:
            data = request.get_json()
            data["password"] = hashlib.sha256(data["password"].encode("utf-8")).hexdigest()

            try:
                new_user = user_schema.load(data)

                new_user.save_to_db()
                return {"message": "User created successfully"}, HTTPStatus.CREATED
            except ValidationError as err:
                return {"errors":err.messages}, HTTPStatus.BAD_REQUEST
            except IntegrityError as err:
                session.rollback()
                return {"errors":str(err.__cause__)}, HTTPStatus.BAD_REQUEST
        return {"errors":"Only admin is permitted for this action"}, HTTPStatus.FORBIDDEN

#Resource for reading, updating and deleting a specific user
class User(Resource):
    def get(self, userId):
        user = r.get(name=str(userId))

        if user is None or len(user) <= 1:
            user = session.query(UserModel).get(userId)
            if user:
                user = user_schema.dump(user)
                user = pickle.dumps(user)
                r.set(name=str(userId), value=user, ex=3000)
            else:
                return {"errors":"User does not exist"}, HTTPStatus.NOT_FOUND

        return pickle.loads(user)

    @jwt_required
    def put(self, userId):
        identity = get_jwt_identity()
        if identity["is_admin"]:
            data = request.get_json()
            data["password"] = hashlib.sha256(data["password"].encode("utf-8")).hexdigest()
            try:
                user_schema.load(data)
                return updateUser(userId, data) 
            except ValidationError as err:
                return {"errors":err.messages}, HTTPStatus.BAD_REQUEST
            except IntegrityError as err:
                session.rollback()
                return {"errors":str(err.__cause__)}, HTTPStatus.BAD_REQUEST
        return {"errors":"Only admin is permitted for this action"}, HTTPStatus.FORBIDDEN

    @jwt_required
    def patch(self, userId):
        identity = get_jwt_identity()
        if identity["is_admin"]:
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
        return {"errors":"Only admin is permitted for this action"}, HTTPStatus.FORBIDDEN
        
    @jwt_required
    def delete(self, userId):
        identity = get_jwt_identity()
        if identity["is_admin"]:
            user = session.query(UserModel).get(userId)
            if user:
                user.remove_from_db()
                r.delete(userId)
                return {"message": "User successfully deleted"}, HTTPStatus.OK
            else:
                return {"errors": "User does not exist"}, HTTPStatus.NOT_FOUND
        return {"errors":"Only admin is permitted for this action"}, HTTPStatus.FORBIDDEN

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
