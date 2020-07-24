from app import session, jwt
from app.models import user_schema, users_schema, UserModel
from flask import request
from flask_restful import Resource
from marshmallow import ValidationError
from flask_jwt_extended import create_access_token, decode_token
from sqlalchemy.exc import IntegrityError, InvalidRequestError
from http import HTTPStatus
import hashlib


class UserCreation(Resource):
    def post(self):
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

#Resource for reading, updating and deleting a specific user
class User(Resource):
    def get(self, userId):
        user = session.query(UserModel).get(userId)
        if user:
            return user_schema.dump(user)
        return {"errors":"User does not exist"}, HTTPStatus.NOT_FOUND

    def put(self, userId):
        data = request.get_json()
        data["password"] = hashlib.sha256(data["password"].encode("utf-8")).hexdigest()
        try:
            updated_user = user_schema.load(data)
            user = session.query(UserModel).filter(UserModel.id == userId).update(data)
            session.commit()
            return {"message": "User updated successfully"}, HTTPStatus.OK
        except ValidationError as err:
            return {"errors":err.messages}, HTTPStatus.BAD_REQUEST
        except IntegrityError as err:
            session.rollback()
            return {"errors":str(err.__cause__)}, HTTPStatus.BAD_REQUEST

    def patch(self, userId):
        data = request.get_json()
        
        for key in data:
            if key=="password":
                data[key] = hashlib.sha256(data[key].encode("utf-8")).hexdigest()

        try:
            user = session.query(UserModel).filter(UserModel.id == userId).update(data)
            session.commit()
            return {"message": "User updated successfully"}, HTTPStatus.OK
        except (IntegrityError, InvalidRequestError) as err:
            session.rollback()
            return {"errors":str(err.__cause__)}, HTTPStatus.BAD_REQUEST        
        

    def delete(self, userId):
        user = session.query(UserModel).get(userId)
        if user:
            user.remove_from_db()
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
            jwt_accessToken = create_access_token(identity=user.id, fresh=True)
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
