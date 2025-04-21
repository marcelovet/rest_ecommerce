from sqlalchemy.orm import sessionmaker

from app.db.init_db import engine

Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
