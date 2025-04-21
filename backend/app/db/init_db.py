import urllib.parse

from sqlalchemy import create_engine

from app.core.config import settings as st

CONN_STRING = "postgresql+psycopg2://"
CONN_STRING += f"{urllib.parse.quote_plus(st.POSTGRES_USER)}"
CONN_STRING += f":{urllib.parse.quote_plus(st.POSTGRES_PASSWORD)}@"
CONN_STRING += f"{st.POSTGRES_HOST}:{st.POSTGRES_PORT}/"
CONN_STRING += f"{st.POSTGRES_DB}"

engine = create_engine(CONN_STRING)
