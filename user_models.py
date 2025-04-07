from sqlalchemy import Column, Integer, String,CheckConstraint
from database import Base,engine

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String(50), nullable=False)
    college = Column(String, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "role IN ('student', 'admin', 'checker')", name="check_user_role"
        ),
    )

Base.metadata.create_all(bind=engine)