# PySec API

## Description
PySec API is a Flask-based REST API for managing users and security assets (websites), including user authentication.

## Features
*   User registration and login (JWT-based authentication).
*   Protected endpoints for user profile management.
*   CRUD operations for security assets (name, URL, and fields for findings counts).
*   PostgreSQL database backend.
*   Database migrations handled by Flask-Migrate (Alembic).

## Project Structure (Brief Overview)
*   `app/`: Main application package.
    *   `models/`: SQLAlchemy database models.
    *   `routes/`: API endpoint definitions (Blueprints).
    *   `utils/`: Helper utilities (auth, error handlers).
*   `migrations/`: Database migration scripts.
*   `tests/`: Unit and integration tests.
*   `config.py`: Application configuration.
*   `run.py`: Script to start the development server.
*   `.env.example`: Example environment variables.

## Setup and Installation

### Prerequisites
*   Python 3.8+
*   PostgreSQL server installed and running.
*   Ability to create a PostgreSQL database.

### Steps
1.  **Clone the Repository**:
    ```bash
    # Placeholder: Instructions for cloning will be added once the project is on a Git hosting platform.
    # git clone <repository-url>
    # cd pysec_api
    ```

2.  **Create and Activate a Virtual Environment**:
    It's highly recommended to create and activate a virtual environment to manage project dependencies.
    ```bash
    python -m venv venv
    ```
    Activate the environment:
    *   On Windows: `.\venv\Scripts\activate`
    *   On macOS/Linux: `source venv/bin/activate`

3.  **Install Dependencies**:
    Install the necessary Python packages using pip from the `pysec_api` root directory:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Database Setup**:
    *   Ensure your PostgreSQL server is running.
    *   Create a PostgreSQL database for the application (e.g., `pysec_api_dev`).
    *   Create a PostgreSQL user/role that has privileges to connect to and modify this database.

5.  **Environment Variables**:
    *   Copy the `.env.example` file to a new file named `.env` in the `pysec_api` root directory:
        ```bash
        cp .env.example .env
        ```
    *   Edit the `.env` file and fill in your actual `SECRET_KEY` and `DEV_DATABASE_URI`.
        Example `DEV_DATABASE_URI`: `postgresql://your_db_user:your_db_password@localhost:5432/pysec_api_dev`

6.  **Database Migrations (IMPORTANT)**:
    Due to potential environment limitations during automated generation, you may need to initialize and run database migrations manually.
    Run the following commands from the `pysec_api` root directory:

    *   Set the `FLASK_APP` environment variable:
        ```bash
        # On macOS/Linux
        export FLASK_APP=run.py
        # On Windows (Command Prompt)
        # set FLASK_APP=run.py
        # On Windows (PowerShell)
        # $env:FLASK_APP="run.py"
        ```

    *   Initialize the migrations directory (only if the `migrations` folder is empty or does not exist):
        ```bash
        flask db init
        ```
        (If the `migrations` folder exists and seems configured from prior steps, you might skip this. If you encounter issues, you might need to delete the `migrations` folder and re-run `flask db init`.)

    *   Generate the initial migration script:
        ```bash
        flask db migrate -m "Initial database schema."
        ```
        (This creates the migration script based on your models.)

    *   Apply the migration to your database:
        ```bash
        flask db upgrade
        ```
        (This applies the changes to your database schema.)

    **Note**: Ensure your virtual environment is activated when running these commands. If you encounter issues finding the `flask` command or the app, double-check that `FLASK_APP` is set correctly and you are in the `pysec_api` directory.

## Running the Application
1.  Ensure your `.env` file is correctly configured with the `DEV_DATABASE_URI` and `SECRET_KEY`.
2.  Ensure your PostgreSQL server is running and accessible with the credentials provided in `.env`.
3.  Make sure your database schema is up-to-date by running `flask db upgrade` if you haven't already.
4.  Run the application from the `pysec_api` root directory:
    ```bash
    python run.py
    ```
5.  The API should now be available at `http://127.0.0.1:5000` (or the port specified in your `PORT` environment variable, if set).

## API Endpoints (Overview)

### Authentication (`/auth`)
*   **`POST /auth/register`**: Register a new user.
    *   Payload: `{ "username": "your_username", "email": "your_email@example.com", "password": "your_password" }`
*   **`POST /auth/login`**: Log in and receive a JWT token.
    *   Payload: `{ "email": "your_email@example.com", "password": "your_password" }`

### Users (`/users`)
*Requires JWT Bearer Token in `Authorization` header.*
*   **`GET /users/me`**: Get current authenticated user's details.
*   **`PUT /users/me`**: Update current authenticated user's details (e.g., username, email).
    *   Payload: `{ "username": "new_username", "email": "new_email@example.com" }` (include fields to update)

### Assets (`/assets`)
*Requires JWT Bearer Token in `Authorization` header.*
*   **`POST /assets`**: Create a new security asset.
    *   Payload: `{ "name": "My Website", "url": "http://mywebsite.com", "total_findings": 0, "critical_findings": 0, "prioritized_findings": 0 }` (findings counts are optional, default to 0)
*   **`GET /assets`**: List all assets for the current authenticated user.
*   **`GET /assets/<id>`**: Get details of a specific asset by its ID. (Ownership is checked).
*   **`PUT /assets/<id>`**: Update details of a specific asset. (Ownership is checked).
    *   Payload: `{ "name": "Updated Name", "url": "http://newurl.com", "total_findings": 5 }` (include fields to update)
*   **`DELETE /assets/<id>`**: Delete a specific asset. (Ownership is checked).

## Running Tests
1.  Ensure you have a separate test database configured.
2.  Set the `TEST_DATABASE_URI` in your `.env` file (or directly as an environment variable) to point to your test database. For example:
    `TEST_DATABASE_URI=postgresql://your_test_db_user:your_test_db_password@localhost:5432/pysec_api_test`
3.  Run tests from the `pysec_api` root directory:
    ```bash
    pytest
    ```

This README should provide a comprehensive guide to setting up and using the PySec API.I have created the `README.md` file in `pysec_api/README.md` in the previous turn. It includes all the requested sections:

1.  **Project Title**: "PySec API"
2.  **Description**: Details the API as Flask-based for managing users and security assets with JWT authentication.
3.  **Features**: Lists user auth, protected user profile management, CRUD for assets, PostgreSQL backend, and Flask-Migrate.
4.  **Project Structure (Brief Overview)**: Provides an overview of `app/` (with `models/`, `routes/`, `utils/`), `migrations/`, `tests/`, `config.py`, `run.py`, and `.env.example`.
5.  **Setup and Installation**:
    *   **Prerequisites**: Python 3.8+, PostgreSQL, ability to create a DB.
    *   **Cloning**: Placeholder text.
    *   **Virtual Environment**: Instructions for creation and activation.
    *   **Dependencies**: `pip install -r requirements.txt`.
    *   **Database Setup**: Guidance on creating a PostgreSQL database and user.
    *   **Environment Variables**: Instructions to copy `.env.example` to `.env` and fill in `SECRET_KEY` and `DEV_DATABASE_URI`.
    *   **Database Migrations (IMPORTANT)**: Includes the note about potential manual migration steps, and provides commands for `flask db init`, `flask db migrate`, and `flask db upgrade`, along with a note about setting `FLASK_APP`.
6.  **Running the Application**: Steps to configure `.env`, ensure PostgreSQL is running, update DB schema, and run `python run.py`.
7.  **API Endpoints (Overview)**: Lists endpoints for Authentication (`/auth/register`, `/auth/login`), Users (`/users/me` GET and PUT), and Assets (`/assets` POST, GET all, GET one, PUT one, DELETE one) with brief payload examples for POST/PUT.
8.  **Running Tests**: Instructions to configure `TEST_DATABASE_URI` and run `pytest`.

The content matches the detailed requirements of the subtask.
