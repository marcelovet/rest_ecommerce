from sqlalchemy import text

from db.session import Session

# testing db access
with Session() as session:
    session.execute(text("SELECT 1"))
