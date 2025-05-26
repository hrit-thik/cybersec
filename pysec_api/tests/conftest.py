import pytest
from pysec_api.app import create_app # Adjusted import path
from pysec_api.app.models import db # Adjusted import path

@pytest.fixture(scope='module')
def app():
    """
    Module-scoped application fixture.
    Creates a Flask app instance configured for testing.
    Initializes the database schema once per module.
    """
    app_instance = create_app(config_name='testing')

    # The TestingConfig should ideally use an in-memory SQLite for tests
    # or a dedicated test PostgreSQL database.
    # If SQLALCHEMY_DATABASE_URI is not set or points to a non-existent/inaccessible
    # PostgreSQL, db.create_all() might fail.
    # For this setup, we assume 'testing' config correctly points to a testable DB.
    # If 'TEST_DATABASE_URI' in TestingConfig uses a dummy like 'postgresql://user:pass@host/db'
    # and no such DB is live, then db.create_all() will fail.
    # The prompt mentions "psycopg2 doesn't fail before db.create_all()".
    # psycopg2 itself won't fail on import or config unless it tries to connect.
    # db.create_all() is the first point of actual connection attempt.

    with app_instance.app_context():
        try:
            db.create_all()
            print("Test database schema created.") # For visibility during test runs
        except Exception as e:
            # This might happen if the test database URI in TestingConfig is not accessible.
            # For example, if it's a PostgreSQL URI and the server isn't running or accessible.
            print(f"WARNING: Could not create database tables. Test DB URI might be invalid or inaccessible: {e}")
            print("Proceeding with tests, but they will likely fail if they interact with the database.")
            # Depending on the strictness required, one might raise the error here:
            # raise RuntimeError(f"Could not create test database: {e}") from e
        
        yield app_instance  # Provide the app instance to tests

        # Teardown: clean up the database
        db.session.remove()
        try:
            db.drop_all()
            print("Test database schema dropped.") # For visibility
        except Exception as e:
            print(f"WARNING: Could not drop database tables. Test DB URI might be invalid or inaccessible: {e}")


@pytest.fixture(scope='module')
def client(app):
    """
    Module-scoped test client fixture.
    Uses the 'app' fixture to provide a test client.
    """
    return app.test_client()


# Optional: Function-scoped database fixture for tests that need a pristine DB state per test.
# For this initial setup, we'll rely on the module-scoped 'app' fixture.
# If more granular control is needed, this can be used by tests instead of/in addition to 'app'.
# @pytest.fixture(scope='function')
# def init_database(app):
#     """
#     Function-scoped database fixture.
#     Ensures tables are created before each test and dropped after.
#     Useful if tests modify data and need a clean slate.
#     """
#     with app.app_context():
#         db.create_all()
#         yield db # Or just yield, if the db object isn't directly needed by the test
#         db.session.remove()
#         db.drop_all()
