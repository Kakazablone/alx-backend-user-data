#!/usr/bin/env python3
"""
Authentication Module
Handles user authentication, session management, and password resets.
"""

import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from typing import Union
from user import User
from uuid import uuid4


def _hash_password(password: str) -> str:
    """
    Returns a salted hash of the input password.

    Args:
        password (str): The plaintext password to hash.

    Returns:
        str: The hashed password.
    """
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed


def _generate_uuid() -> str:
    """
    Returns a string representation of a new UUID.

    Returns:
        str: A newly generated UUID string.
    """
    UUID = uuid4()
    return str(UUID)


class Auth:
    """
    Auth class to interact with the authentication database.
    Provides methods for user registration, session management,
    and password reset functionality.
    """

    def __init__(self):
        """Initializes the Auth class with a database instance."""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a user in the database.

        Args:
            email (str): The email of the user.
            password (str): The plaintext password of the user.

        Raises:
            ValueError: If a user with the provided email already exists.

        Returns:
            User: The User object that was created.
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password)
            return user
        else:
            raise ValueError(f'User {email} already exists')

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validates the login credentials of a user.

        Args:
            email (str): The user's email.
            password (str): The plaintext password provided.

        Returns:
            bool: True if login credentials are valid, otherwise False.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        user_password = user.hashed_password
        encoded_password = password.encode()

        if bcrypt.checkpw(encoded_password, user_password):
            return True

        return False

    def create_session(self, email: str) -> Union[str, None]:
        """
        Creates a session for the user.

        Args:
            email (str): The user's email.

        Returns:
            str: The session ID, or None if user not found.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)

        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """
        Retrieves a user by their session ID.

        Args:
            session_id (str): The session ID.

        Returns:
            User or None: The User object associated with the session ID,
                          or None if no user is found.
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: int) -> None:
        """
        Destroys the session associated with a user
        by setting the session ID to None.

        Args:
            user_id (int): The ID of the user whose
            session should be destroyed.

        Returns:
            None
        """
        try:
            user = self._db.find_user_by(id=user_id)
        except NoResultFound:
            return None

        self._db.update_user(user.id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        """
        Generates a reset password token for a user.

        Args:
            email (str): The email of the user requesting a password reset.

        Raises:
            ValueError: If no user with the provided email is found.

        Returns:
            str: The reset password token.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError("User not found")

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)

        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Updates the user's password using a valid reset token.

        Args:
            reset_token (str): The reset token provided to the user.
            password (str): The new plaintext password.

        Raises:
            ValueError: If the reset token is invalid
            or the user does not exist.

        Returns:
            None
        """
        if reset_token is None or password is None:
            return None

        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError("Invalid reset token")

        hashed_password = _hash_password(password)
        self._db.update_user(user.id,
                             hashed_password=hashed_password,
                             reset_token=None)
