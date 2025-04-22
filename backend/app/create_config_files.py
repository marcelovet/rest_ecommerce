#!/usr/bin/env python3
import configparser
import getpass
import secrets
import string

from app.core.config import settings as st

DIR_PATH = st.BASE_DIR.parent


def generate_secure_password(length=32):
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def create_config_ini():
    """Create config.ini file with user input."""
    print("\n=== Creating config.ini ===")
    config = configparser.ConfigParser()

    # Admin section
    config["admin"] = {}
    config["admin"]["email"] = (
        input("Admin email [admin@example.com]: ") or "admin@example.com"
    )
    config["admin"]["password"] = getpass.getpass("Admin password [admin]: ") or "admin"

    # PostgreSQL section
    config["postgresql"] = {}
    config["postgresql"]["host"] = input("PostgreSQL host [postgres]: ") or "postgres"
    config["postgresql"]["port"] = input("PostgreSQL port [5432]: ") or "5432"
    config["postgresql"]["database"] = (
        input("PostgreSQL database [ecommerce_postgres]: ") or "ecommerce_postgres"
    )
    config["postgresql"]["user"] = input(
        "PostgreSQL user (leave empty for random): ",
    ) or generate_secure_password(24)
    pg_password = getpass.getpass("PostgreSQL password (leave empty for random): ")
    config["postgresql"]["password"] = (
        pg_password if pg_password else generate_secure_password()
    )

    # Mail section
    config["mail"] = {}
    config["mail"]["host"] = input("SMTP host [smtp_host]: ") or "smtp_host"
    config["mail"]["port"] = input("SMTP port [5432]: ") or "5432"
    config["mail"]["user"] = input("SMTP user [smtp_user]: ") or "smtp_user"
    config["mail"]["password"] = (
        getpass.getpass("SMTP password [smtp_password]: ") or "smtp_password"
    )
    config["mail"]["from"] = input("Mail from address [smtp_user]: ") or "smtp_user"
    config["mail"]["timeout"] = input("Mail timeout [20]: ") or "20"
    config["mail"]["use_tls"] = input("Use TLS (1/0) [1]: ") or "1"
    config["mail"]["fail_silently"] = input("Fail silently (1/0) [0]: ") or "0"
    config["mail"]["admin"] = input("Mail admin [smtp_user]: ") or "smtp_user"

    # Redis section
    config["redis"] = {}
    config["redis"]["host"] = input("Redis host [redis]: ") or "redis"
    config["redis"]["port"] = input("Redis port [6379]: ") or "6379"

    # Write config to file
    with (st.BASE_DIR / "config.ini").open("w") as configfile:
        config.write(configfile)

    print("✅ config.ini created successfully")
    return config


def create_fastapi_env(config):
    """Create .fastapi environment file."""
    print("\n=== Creating .fastapi ===")

    content = f"REDIS_URL=redis://{config['redis']['host']}:{config['redis']['port']}/0"

    path = DIR_PATH / "compose" / "production" / "fastapi" / ".fastapi"
    with path.open("w") as f:
        f.write(content)

    print("✅ .fastapi created successfully")


def create_postgres_env(config):
    """Create .postgres environment file."""
    print("\n=== Creating .postgres ===")

    content = (
        "# PostgreSQL\n"
        f"POSTGRES_HOST={config['postgresql']['host']}\n"
        f"POSTGRES_PORT={config['postgresql']['port']}\n"
        f"POSTGRES_DB={config['postgresql']['database']}\n"
        f"POSTGRES_USER={config['postgresql']['user']}\n"
        f"POSTGRES_PASSWORD={config['postgresql']['password']}\n"
    )

    path = DIR_PATH / "compose" / "production" / "postgres" / ".postgres"
    with path.open("w") as f:
        f.write(content)

    print("✅ .postgres created successfully")


def main():
    """Main function to create all config files."""
    print("Creating configuration files for application!")
    print("This will create config.ini, .fastapi, and .postgres files.")
    print("Press Enter to accept default values in [brackets].")

    # Create config files
    config = create_config_ini()
    create_fastapi_env(config)
    create_postgres_env(config)

    print("\n✨ All configuration files created successfully!")
    print(
        "Make sure to keep your passwords safe and not commit them to version control.",
    )


if __name__ == "__main__":
    main()
