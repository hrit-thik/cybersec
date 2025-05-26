from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Import models here to make them accessible for Flask-Migrate and the application
from .user import User
from .asset import Asset
