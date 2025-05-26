from pysec_api.app import bcrypt # Correct import path assuming bcrypt is initialized in app's __init__

def hash_password(password: str) -> str:
    """
    Hashes a plain text password using Bcrypt.

    Args:
        password: The plain text password.

    Returns:
        The hashed password string.
    """
    return bcrypt.generate_password_hash(password).decode('utf-8')

def check_password(hashed_password: str, plain_password: str) -> bool:
    """
    Checks a plain text password against a stored hashed password.

    Args:
        hashed_password: The stored hashed password.
        plain_password: The plain text password to check.

    Returns:
        True if the passwords match, False otherwise.
    """
    return bcrypt.check_password_hash(hashed_password.encode('utf-8'), plain_password)
