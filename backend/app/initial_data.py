import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings as st
from app.db.session import Session as DbSession
from app.schemas import Role
from app.schemas import User
from app.services.auth_service import hash_password

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def init_db(session: Session) -> None:
    # Tables should be created with Alembic migrations
    # just run the alembic upgrade head

    logger.info("Creating initial data")

    roles = session.scalars(select(Role)).all()  # type: ignore[attr-defined]
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
        logger.info("Roles created")

    admin = session.scalar(select(User).where(User.role_id == 5))
    if not admin:
        logger.info("Creating admin user")
        admin = User(
            email=st.SUPERUSER_EMAIL,
            hashed_password=hash_password(st.SUPERUSER_PASSWORD),
            full_name="Admin",
            is_active=True,
            is_verified=True,
            role_id=5,
        )
        session.add(admin)
        session.commit()
        logger.info("Admin created")


def init() -> None:
    with DbSession() as session:
        init_db(session)


def main() -> None:
    logger.info("Creating initial data")
    init()
    logger.info("Initial data created")


if __name__ == "__main__":
    main()
