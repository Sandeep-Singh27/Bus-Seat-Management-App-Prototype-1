from sqlalchemy import Column, Integer, String, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from database import Base
from user_models import User

class CheckerAssignment(Base):
    __tablename__ = "checker_assignments"
    __table_args__ = (
        UniqueConstraint("college", "bus_no", name="checker_assignments_college_bus_no_key"),
    )

    id = Column(Integer, primary_key=True, index=True)
    checker_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    college = Column(String, nullable=False)
    bus_no = Column(Integer, nullable=False)

    checker = relationship(User, backref="assigned_buses")
