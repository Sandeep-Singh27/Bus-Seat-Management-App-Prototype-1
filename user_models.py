from sqlalchemy import Column, Integer, String, Enum
import enum
from database import Base
from database import engine

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String(50), nullable=False)
    college = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)