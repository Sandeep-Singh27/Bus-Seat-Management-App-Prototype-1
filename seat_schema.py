from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from database import Base
from pydantic import BaseModel
from user_models import User
from database import engine
Base.metadata.create_all(bind=engine)

class Seat(Base):
    __tablename__ = "seats"

    college = Column(String, primary_key=True)
    bus_no = Column(Integer, primary_key=True)
    seat_no = Column(Integer, primary_key=True)
    occupied_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    status = Column(String, default="not occupied")  
    occupied_by = relationship(User)

class OccupySeatRequest(BaseModel):
    qr_data: str  # e.g., "iist-57-5"
