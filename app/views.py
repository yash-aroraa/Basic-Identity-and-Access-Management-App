from app import api, session, jwt
from app.models import user_schema, users_schema, UserModel
from flask import request, jsonify
from flask_restful import Resource
from marshmallow import ValidationError
from flask_jwt_extended import create_access_token, verify_jwt_in_request, decode_token
from sqlalchemy import text
import hashlib



class UserCreation(Resource):
    def post(self):
        data = request.get_json()
        data["password"] = hashlib.sha256(data["password"].encode("utf-8")).hexdigest()

        try:
            new_user = user_schema.load(data)
        except ValidationError as err:
            return {"errors":err.messages}, 400

        if session.query(UserModel).filter(UserModel.username == new_user.username).first() is not None:
            return {"errors":"Username already exists"}, 400
        
        if session.query(UserModel).filter(UserModel.email == new_user.email).first() is not None:
            return {"errors":"Email already exists"}, 400

        if session.query(UserModel).filter(UserModel.phone == new_user.phone).first() is not None:
            return {"errors":"Phone already exists"}, 400

        new_user.save_to_db()
        return {"message": "User created successfully"}, 201

#Resource for reading, updating and deleting a specific user
class User(Resource):
    def get(self, userId):
        user = session.query(UserModel).get(userId)
        if user:
            return user_schema.dump(user)
        return {"errors":"User does not exist"}, 404

    def put(self, userId):
        data = request.get_json()
        data["password"] = hashlib.sha256(data["password"].encode("utf-8")).hexdigest()
        print(data)
        try:
            updated_user = user_schema.load(data)
            print(updated_user)
        except ValidationError as err:
            return {"errors":err.messages}, 400

        if session.query(UserModel).filter(UserModel.username == updated_user.username, UserModel.id != userId).first() is not None:
            return {"errors":"Username already exists"}, 400
        
        if session.query(UserModel).filter(UserModel.email == updated_user.email, UserModel.id != userId).first() is not None:
            return {"errors":"Email already exists"}, 400

        if session.query(UserModel).filter(UserModel.phone == updated_user.phone, UserModel.id != userId).first() is not None:
            return {"errors":"Phone already exists"}, 400

        user = session.query(UserModel).filter(UserModel.id == userId).update(data)
        session.commit()
        return {"message": "User updated successfully"}, 200

    def patch(self, userId):
        data = request.get_json()
        print(data)
        for key in data:
            if key=="password":
                data[key] = hashlib.sha256(data[key].encode("utf-8")).hexdigest()
            if key=="username":
                if session.query(UserModel).filter(UserModel.username == data[key], UserModel.id != userId).first() is not None:
                    return {"errors":"Username already exists"}, 400
            if key=="email":
                if session.query(UserModel).filter(UserModel.email == data[key], UserModel.id != userId).first() is not None:
                    return {"errors":"Email already exists"}, 400
            if key=="phone":
                if session.query(UserModel).filter(UserModel.phone == data[key], UserModel.id != userId).first() is not None:
                    return {"errors":"Phone already exists"}, 400
            if key not in [column.key for column in UserModel.__table__.columns]:
                return {"errors":key + " column does not exist in the table"}, 400
        user = session.query(UserModel).filter(UserModel.id == userId).update(data)
        session.commit()
        return {"message": "User updated successfully"}, 200

    def delete(self, userId):
        user = session.query(UserModel).get(userId)
        if user:
            user.remove_from_db()
            return {"message": "User successfully deleted"}, 200
        else:
            return {"errors": "User does not exist"}, 404

class UserLogin(Resource):
    def post(self):
        data = request.get_json()

        user = session.query(UserModel).filter(UserModel.username == data["username"]).first()

        if user and not user.is_active:
            return {"errors": "Your account is inactive."}, 403

        if user and user.password == hashlib.sha256(data["password"].encode("utf-8")).hexdigest():
            jwt_accessToken = create_access_token(identity=user.id, fresh=True)
            return {"access_token": jwt_accessToken}, 200

        return {"errors": "Invalid username or password"}, 401

class JWTVerification(Resource):
    def post(self):
        data = request.get_json()
        decoded_token = decode_token(data["token"])

        return decoded_token

class Users(Resource):
    def get(self):
        args = request.args
        print(args)
        if args:

            for key in args:
                if key not in [column.key for column in UserModel.__table__.columns]:
                    return {"errors":key + " query parameter does not exist in the table"}, 400

            

            result = session.query(UserModel).filter_by(**args).all()
            return users_schema.dump(result), 200
        
        return {"errors": "No query params received"}
