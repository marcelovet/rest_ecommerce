import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import Session as DbSession
from app.schemas import Role

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def init_db(session: Session) -> None:
    # Tables should be created with Alembic migrations
    # just run the alembic upgrade head

    roles = session.scalars(select(Role)).all()
    if not roles:
        logger.info("Creating roles")
        roles = [
            Role(name="customer", id=0),
            Role(name="staff", id=1),
            Role(name="inventory_manager", id=2),
            Role(name="order_processor", id=3),
            Role(name="store_manager", id=4),
            Role(name="admin", id=5),
        ]
        session.add_all(roles)
        session.commit()


def init() -> None:
    with DbSession() as session:
        init_db(session)


def main() -> None:
    logger.info("Creating initial data")
    init()
    logger.info("Initial data created")


if __name__ == "__main__":
    main()
