from app import app, Base, engine

if __name__ == '__main__':
    app.app_context().push()  # without app_context, this error occurs: working outside of application context
    Base.metadata.create_all(engine)
    app.run(debug=True)
