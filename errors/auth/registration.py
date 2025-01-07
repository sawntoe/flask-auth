"""
This contains registration errors for use by flask-auth.
"""


class UserAlreadyExists(Exception):
    """
    User already exists and cannot be registered.
    """
