from sqlalchemy.orm import sessionmaker

from .init_db import engine

Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
