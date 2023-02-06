from app import Base
from sqlalchemy import Column, Integer, String, ForeignKey, Float


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password = Column(String(80), unique=True, nullable=False)
    location = Column(String(120))
    pan = Column(String(120))
    address = Column(String(120))
    contact = Column(String(120))
    sex = Column(String(120))
    nationality = Column(String(120))


class Account(Base):
    __tablename__ = "account"
    user_id = Column(Integer, ForeignKey(User.id), primary_key=True)
    amount = Column(Float)
