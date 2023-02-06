from flask import Flask
import pymysql
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# initializing flask app
app = Flask(__name__)
app.secret_key = "secret_key"

# sqlalchemy+mysql session
pymysql.install_as_MySQLdb()
engine = create_engine("mysql://root:password@localhost/rad", pool_size=10)
Base = declarative_base()
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# routes
from app import routes
