import os
from dotenv import load_dotenv

# Load environment variables from .env file, if it exists.
load_dotenv()

class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-should-really-change-this'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Add other default configurations here, e.g., JWT settings if needed globally
    # JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'another-strong-jwt-secret'


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    # It's highly recommended to set this in your .env file
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URI') or \
                              'postgresql://user:password@localhost:5432/pysec_api_dev'


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    # It's highly recommended to set this in your .env file
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URI') or \
                              'postgresql://user:password@localhost:5432/pysec_api_test'
    SECRET_KEY = 'test-secret-key' # Consistent secret key for testing
    DEBUG = True # Often helpful for debugging tests
    SQLALCHEMY_ECHO = False # Can be True if you want to see SQL queries during tests


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    # Ensure SQLALCHEMY_DATABASE_URI is set via environment variable in production
    SQLALCHEMY_DATABASE_URI = os.environ.get('PROD_DATABASE_URI')
    # SECRET_KEY must be set via environment variable in production
    # JWT_SECRET_KEY must be set via environment variable in production


config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
