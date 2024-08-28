#!/usr/bin/env python3
"""
Module for filtering and formatting log records.
"""

import logging
import mysql.connector
import os
from datetime import datetime
from typing import List, Tuple
import re

# Define the PII fields that need to be filtered
PII_FIELDS: Tuple[str, ...] = ("name", "email", "phone", "ssn", "password")

class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class."""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"

    def __init__(self, fields: Tuple[str, ...]) -> None:
        super().__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        for field in self.fields:
            regex = fr'({field}=[^;]*)'
            message = re.sub(regex, lambda m: f'{field}={self.REDACTION}', message)
        record.message = message
        return super().format(record)

def get_db() -> mysql.connector.connection.MySQLConnection:
    """Return a MySQL database connection."""
    db_username = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    db_password = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    db_host = os.getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')

    return mysql.connector.connect(
        user=db_username,
        password=db_password,
        host=db_host,
        database=db_name
    )

def get_logger() -> logging.Logger:
    """Return a logger configured for the application."""
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(fields=PII_FIELDS))
    logger.addHandler(handler)
    return logger

def main() -> None:
    """Retrieve and display all rows in the users table."""
    logger = get_logger()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users")

    for row in cursor.fetchall():
        # Construct a log message with the retrieved row data
        field_names = ["name", "email", "phone", "ssn", "password", "ip", "last_login", "user_agent"]
        field_values = [f"{field}={value}" for field, value in zip(field_names, row)]
        log_message = "; ".join(field_values) + ";"

        # Log the formatted message
        logger.info(log_message)

    cursor.close()
    db.close()

if __name__ == "__main__":
    main()
