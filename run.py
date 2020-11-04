from app import app, Base, db

if __name__=='__main__':
    @app.before_first_request
    def create_tables():
        Base.metadata.create_all(db)
    app.run(debug=True)