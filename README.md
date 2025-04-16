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
- **Supabase** - Primary database and storage
- **Redis** - Caching and session management
- **JWT** - Secure authentication
- **Docker** - Containerization
- **Pytest** - Testing framework

---

### Supabase Setup

1. **Create Your .env File**
  
  Create a `.env` file in the supabase directory of the project (use env_example.env as a template).

2. **Pull the images**
   ```bash
   cd supabase # Assuming you are in the project directory
   docker compose pull
   ```

3. **Run the containers**
   ```bash
   docker compose up -d
   ```
### Backend Setup

1. **Create a virtual environment**
   ```bash
   cd app # Assuming you are in the project directory
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Generate RSA keys**
   ```bash
   openssl genrsa -out private_key.pem 2048
   openssl rsa -in private_key.pem -pubout -out public_key.pem
   ```

4. **Configure the .ini file**
   ```bash
   mkdir .envs
   touch .envs/config.ini
   ```

   Add the same sections and values to `.env/config.ini` as in `config_example.ini`.

5. **...**

This project is being created as a portfolio piece to demonstrate backend development capabilities with FastAPI and modern web technologies.