# E-commerce RESTful API

A comprehensive backend API for e-commerce platforms built with FastAPI, demonstrating modern best practices for scalable backend development.

## 🚀 Features

- **Complete Product Management** (TODO)
  - CRUD operations for products, categories, and variants
  - Inventory tracking across warehouses
  - Review and rating system

- **User Authentication & Authorization** (TODO)
  - JWT-based authentication with token refresh
  - Role-based access control (Customer, Admin, Inventory Manager)
  - Secure password handling with Argon2

- **Shopping Experience** (TODO)
  - Cart management with persistent sessions
  - Wishlists and saved items
  - Personalized product recommendations

- **Order Processing** (TODO)
  - Checkout workflow with validation
  - Payment processing (Stripe/PayPal integration)
  - Order tracking and history

- **Advanced Features** (TODO)
  - Coupon and discount system
  - Real-time inventory alerts
  - Analytics endpoints for sales performance

## 🛠️ Tech Stack

- **FastAPI** - High-performance web framework
- **SQLAlchemy** - ORM for database interactions
- **Pydantic** - Data validation and settings management
- **Postgres** - Primary database
- **Redis** - Caching and session management
- **JWT** - Secure authentication
- **Docker** - Containerization
- **Pytest** - Testing framework

---



## Backend Setup

#### Requirements

* [Docker](https://www.docker.com/).
* [uv](https://docs.astral.sh/uv/) for Python package and environment management.

By default, the dependencies are managed with [uv](https://docs.astral.sh/uv/)

1. **Create a virtual environment**
   ```bash
   cd backend # Assuming you are in the project directory
   uv sync
   source .venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Generate RSA keys**
   ```bash
   openssl genrsa -out private_key.pem 2048
   openssl rsa -in private_key.pem -pubout -out public_key.pem
   ```

3. **Configure the .ini file**
   ```bash
   touch config.ini
   ```

   Add the same sections and values to `.env/config.ini` as in `ini_example`.

4. **Run alembic migrations**
   ```bash
   alembic upgrade head
   ```

5. **add initial data to database**
   ```bash
   python app/initial_data.py
   ```

6. **...**

This project is being created as a portfolio piece to demonstrate backend development capabilities with FastAPI and modern web technologies.