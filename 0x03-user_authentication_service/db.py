#!/usr/bin/env python3
"""
Database for ORM.
Handles interactions with the database using SQLAlchemy ORM.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from typing import TypeVar
from user import Base, User


class DB:
    """DB Class for Object Relational Mapping (ORM) interactions."""

    def __init__(self):
        """Constructor method that initializes the database engine and session."""
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)  # Drops all tables (use with caution)
        Base.metadata.create_all(self._engine)  # Creates all tables
        self.__session = None

    @property
    def _session(self):
        """
        Getter method for the database session.

        Returns:
            SQLAlchemy session: A database session to perform transactions.
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        Adds a new user to the database.

        Args:
            email (str): The email of the user.
            hashed_password (str): The hashed password of the user.

        Returns:
            User: The User object that was added to the database.
        """
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """
        Finds a user in the database by keyword arguments.

        Args:
            **kwargs: Arbitrary keyword arguments (e.g., email='example@example.com').

        Raises:
            InvalidRequestError: If no valid column names are provided.
            NoResultFound: If no user is found.

        Returns:
            User: The first user found that matches the filters.
        """
        if not kwargs:
            raise InvalidRequestError("No filter arguments were provided.")

        column_names = User.__table__.columns.keys()
        for key in kwargs.keys():
            if key not in column_names:
                raise InvalidRequestError(f"Invalid column: {key}")

        user = self._session.query(User).filter_by(**kwargs).first()

        if user is None:
            raise NoResultFound("No user found with the provided filters.")

        return user

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Updates a user's attributes in the database.

        Args:
            user_id (int): The ID of the user to update.
            **kwargs: Arbitrary keyword arguments containing the attributes to update.

        Raises:
            ValueError: If any provided key is not a valid column.

        Returns:
            None
        """
        user = self.find_user_by(id=user_id)

        column_names = User.__table__.columns.keys()
        for key in kwargs.keys():
            if key not in column_names:
                raise ValueError(f"Invalid attribute: {key}")

        for key, value in kwargs.items():
            setattr(user, key, value)

        self._session.commit()
