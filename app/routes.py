from app.views import User, UserCreation, UserLogin, JWTVerification, Users


#Endpoint generation for each resource
def initialize_routes(api):
    api.add_resource(UserCreation,'/user/create')
    api.add_resource(User,'/user/<int:userId>')
    api.add_resource(UserLogin,'/user/login')
    api.add_resource(JWTVerification, '/jwt')
    api.add_resource(Users, '/users')
