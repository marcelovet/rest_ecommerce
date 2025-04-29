import configparser
import getpass
import secrets
import string
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DIR_PATH = BASE_DIR.parent


def generate_secure_password(length=32):
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def get_int_input(prompt: str, default: int | None = None) -> int | None:
    """Get an integer input from the user."""
    result = default
    while True:
        value = input(prompt)
        if value == "":
            break
        try:
            result = int(value)
            break
        except ValueError:
            print("Invalid input. Please enter an integer.")  # noqa: T201
    return result


def yes_no(prompt: str, default: int) -> int:
    """Get a yes/no input from the user."""
    result = default
    while True:
        value = input(prompt)
        if value == "":
            break
        if value.lower() == "yes":
            result = 1
            break
        if value.lower() == "no":
            result = 0
            break
        print(
            "Invalid input. Please enter 'yes', 'no' "
            "or leave empty to accept the default.",
        )
    return result


def set_time(var: str, default_time: int, default_time_type: str) -> int:
    """Set time variable"""
    time_types = {
        "s": 1,
        "m": 60,
        "h": 60 * 60,
        "d": 24 * 60 * 60,
    }
    time_type = default_time_type
    time = default_time
    while True:
        input_msg = f"Chose {var} time type (s/m/h/d) [{default_time_type}]: "
        time_type = input(input_msg)
        if time_type == "":
            time_type = default_time_type
            break
        if time_type not in time_types:
            print("Invalid time type. Please enter 's', 'm', 'h' or 'd'.")  # noqa: T201
            continue
        break
    while True:
        input_msg = f"Set {var} time [{default_time}]: "
        time_input = input(input_msg)
        if time_input == "":
            break
        try:
            time_input = int(time)
            time = time_input
            break
        except ValueError:
            print("Invalid input. Please enter an integer.")  # noqa: T201
    return time * time_types[time_type]


def set_api_version(default_version: str) -> str:
    """Set API version."""
    while True:
        input_msg = f"Set API version [{default_version}]: "
        version = input(input_msg)
        if version == "":
            version = default_version
            break
        if version.replace(".", "").isdigit():
            break
        print("Invalid input. Please enter a valid API version.")  # noqa: T201
    return version


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
    config["postgresql"]["port"] = str(
        get_int_input("PostgreSQL port [5432]: ", 5432),
    )
    database = (
        input("PostgreSQL database [ecommerce_postgres]: ") or "ecommerce_postgres"
    )
    user = input(
        "PostgreSQL user (leave empty for random): ",
    ) or generate_secure_password(24)
    pg_password = getpass.getpass("PostgreSQL password (leave empty for random): ")
    pwd = pg_password if pg_password else generate_secure_password()
    config["postgresql"]["database"] = database
    config["postgresql"]["user"] = user
    config["postgresql"]["password"] = pwd

    # Mail section
    config["mail"] = {}
    config["mail"]["host"] = input("SMTP host [smtp_host]: ") or "smtp_host"
    config["mail"]["port"] = str(
        get_int_input("SMTP port [587]: ", 587),
    )
    config["mail"]["user"] = input("SMTP user [smtp_user]: ") or "smtp_user"
    config["mail"]["password"] = (
        getpass.getpass("SMTP password [smtp_password]: ") or "smtp_password"
    )
    config["mail"]["from"] = input("Mail from address [smtp_user]: ") or "smtp_user"
    config["mail"]["timeout"] = str(set_time("Mail timeout", 20, "s"))
    config["mail"]["use_tls"] = str(yes_no("Use TLS (yes/no) [yes]: ", 1))
    config["mail"]["fail_silently"] = str(yes_no("Fail silently (yes/no) [no]: ", 0))
    config["mail"]["admin"] = input("Mail admin [smtp_user]: ") or "smtp_user"

    # Redis section
    config["redis"] = {}
    config["redis"]["port"] = str(6379)
    config["redis"]["host"] = "redis"
    config["redis"]["celery_db"] = str(0)
    config["redis"]["repository_db"] = str(1)
    config["redis"]["cache_db"] = str(2)
    config["redis"]["security_db"] = str(3)

    # JWT section
    config["jwt"] = {}
    config["jwt"]["algorithm"] = "RS256"
    config["jwt"]["access_token_expire"] = str(
        set_time("Access Token expiration", 30, "m"),
    )
    config["jwt"]["refresh_token_expire"] = str(
        set_time("Refresh Token expiration", 7, "d"),
    )
    config["jwt"]["verification_token_expire"] = str(
        set_time("Verification Token expiration", 1, "d"),
    )
    config["jwt"]["limited_token_expire"] = str(
        set_time("Limited Token expiration", 30, "m"),
    )
    config["jwt"]["reset_password_expire"] = str(
        set_time("Reset Password Token expiration", 10, "m"),
    )

    # MISC
    config["misc"] = {}
    config["misc"]["api_version"] = set_api_version("1.0.0")
    config["misc"]["domain"] = (
        input("Set Back-End domain [localhost:8000]: ") or "localhost:8000"
    )
    config["misc"]["front_end"] = (
        input("Set Front-End domain [localhost:5173]: ") or "localhost:5173"
    )
    should_be_local = bool(
        yes_no("Configure app for development mode? (yes/no) [yes]: ", 1),
    )
    config["misc"]["app_type"] = "local" if should_be_local else "production"

    if should_be_local:
        config["devel_mode"] = {}
        config["devel_mode"]["redis_host"] = (
            input("Redis development host [localhost]: ") or "localhost"
        )
        config["devel_mode"]["redis_port"] = str(
            get_int_input(
                "Redis port in development (make sure to expose redis on this port "
                "on docker-compose-local.yml, if you not set to default) [6379]: ",
                6379,
            ),
        )
        config["devel_mode"]["pg_host"] = (
            input("Postgres development host [localhost]: ") or "localhost"
        )
        config["devel_mode"]["pg_port"] = str(
            get_int_input(
                "Postgres port in development (make sure to expose postgres on "
                "this port on docker-compose-local.yml, if you not set to "
                "default) [15432]: ",
                15432,
            ),
        )

    # Write config to file
    with (BASE_DIR / "config.ini").open("w") as configfile:
        config.write(configfile)

    print("✅ config.ini created successfully")
    return config


def create_fastapi_env(config):
    """Create .fastapi environment file."""
    print("\n=== Creating .fastapi ===")

    content = f"REDIS_URL=redis://{config['redis']['host']}:{config['redis']['port']}/{config['redis']['celery_db']}"

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
