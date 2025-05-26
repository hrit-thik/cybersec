from flask import Flask
from flask_sqlalchemy import SQLAlchemy # For db object definition, though models.__init__ also has it
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt

from config import config_by_name
from .models import db # Import the db instance from app.models

# Initialize extensions
bcrypt = Bcrypt()
migrate = Migrate()

def create_app(config_name: str = 'development'):
    """
    Application Factory Function.

    Args:
        config_name (str): The configuration environment to use ('development', 'testing', 'production').
                           Defaults to 'development'.

    Returns:
        Flask: The Flask application instance.
    """
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config_by_name[config_name])

    # Initialize extensions with the app
    db.init_app(app)       # Initialize SQLAlchemy with the app
    migrate.init_app(app, db) # Initialize Flask-Migrate
    bcrypt.init_app(app)    # Initialize Flask-Bcrypt

    # Register Blueprints here
    from .routes.auth_routes import auth_bp
    app.register_blueprint(auth_bp) # url_prefix is already set in auth_bp

    from .routes.user_routes import user_bp
    app.register_blueprint(user_bp) # url_prefix is already set in user_bp

    from .routes.asset_routes import asset_bp
    app.register_blueprint(asset_bp) # url_prefix is already set in asset_bp

    # Register custom error handlers
    from .utils import error_handlers
    app.register_error_handler(400, error_handlers.handle_400_bad_request)
    app.register_error_handler(401, error_handlers.handle_401_unauthorized)
    app.register_error_handler(403, error_handlers.handle_403_forbidden)
    app.register_error_handler(404, error_handlers.handle_404_not_found)
    app.register_error_handler(409, error_handlers.handle_409_conflict)
    app.register_error_handler(500, error_handlers.handle_500_internal_server_error)

    return app
