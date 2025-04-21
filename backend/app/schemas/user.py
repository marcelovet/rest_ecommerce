from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String

from app.db.base import Base


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, doc="Unique identifier for each role")
    name = Column(String(50), unique=True, doc="Name of the role")
