import sqlalchemy
from app import Base, session
from marshmallow import fields, validate, Schema, post_load

class UserModel(Base):
    __tablename__ = "users"
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key = True)
    firstName = sqlalchemy.Column(sqlalchemy.String(100), nullable = False)
    lastName = sqlalchemy.Column(sqlalchemy.String(100), nullable = False)
    username = sqlalchemy.Column(sqlalchemy.String(30), nullable = False, unique = True)
    password = sqlalchemy.Column(sqlalchemy.Text, nullable = False)
    phone = sqlalchemy.Column(sqlalchemy.String(10), nullable = False, unique = True)
    email = sqlalchemy.Column(sqlalchemy.Text, nullable = False, unique = True)
    is_active = sqlalchemy.Column(sqlalchemy.Boolean, nullable = False)
    is_admin  = sqlalchemy.Column(sqlalchemy.Boolean, nullable = False)

    def __init__(self,firstName, lastName, username, password, phone, email, is_active, is_admin):
        self.firstName = firstName
        self.lastName = lastName
        self.username = username
        self.password = password
        self.phone = phone
        self.email = email
        self.is_active = is_active
        self.is_admin = is_admin

    def save_to_db(self):
        session.add(self)
        session.commit()

    def remove_from_db(self):
        session.delete(self)
        session.commit()


#User Schema for validation
class UserModelSchema(Schema):
    firstName = fields.Str(required=True)
    lastName  = fields.Str(required=True)
    username  = fields.Str(required=True)
    password = fields.Str(required=True)
    phone = fields.Str(required=True, validate=[validate.Regexp('^[0-9]{10}$',error="Not a valid phone number")])
    email = fields.Email(required=True)
    is_active = fields.Bool(required=True)
    is_admin = fields.Bool(required=True)

    class Meta:
        model = UserModel

    @post_load
    def makeUser(self,data,**kwargs):
        return UserModel(**data)

#Schema Instantiation
user_schema = UserModelSchema()
users_schema  = UserModelSchema(many=True)
