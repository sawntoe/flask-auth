"""
This module serves as a lightweight authentication library for flask.
"""

import datetime
import secrets
import string
import time
from hashlib import sha256
from uuid import uuid4

import flask
import psycopg2
import psycopg2.extras
import psycopg2.extensions

from flask_auth import errors.auth.login
from flask_auth import errors.auth.generic
from flask_auth import errors.auth.registration


class AuthenticationManager:
    """
    Manages authentication
    """

    def __init__(
        self,
        conn: psycopg2.extensions.connection,
        config: dict = None
    ) -> None:
        psycopg2.extras.register_uuid()
        self.db_conn = conn
        self.config = config
        self._init_db()

    def _init_db(self):
        cur = self.db_conn.cursor()
        cur.execute(
                    '''
                    CREATE TABLE IF NOT EXISTS users (
                        id text,
                        username text,
                        hash char(64),
                        salt char(64),
                        groups text[]
                    );

                    CREATE TABLE IF NOT EXISTS sessions (
                        id text,
                        token text, 
                        expiry int
                    );
                    '''
                    )

    def _sha256hash(self, data: str, salt: str) -> str:
        """
        Internal function to calculate sha256 digest of a given string and a salt
        """
        sha256hash = sha256()
        sha256hash.update(data.encode("UTF-8"))
        sha256hash.update(salt.encode("UTF-8"))

        return sha256hash.hexdigest()

    def create_session_token(self, uid: str, expiry: datetime.timedelta = datetime.timedelta(days=30)) -> flask.Response:
        """
        Creates a session code for a given user.
        """
        cur = self.db_conn.cursor()
        token = str(uuid4())
        expire_date = datetime.datetime.now()
        expire_date = expire_date + expiry
        cur.execute(
            "INSERT INTO sessions (id, token, expiry) VALUES (%s, %s, %s)",
            (uid, token, int(expire_date.timestamp())),
        )
        return token


    def create_session(self, uid: str, response: flask.Response, expiry: datetime.timedelta = datetime.timedelta(days=30)) -> flask.Response:
        """
        Internal function to create a response containing a session code for a given user.
        Can be called externally without consequences.
        """
        token = self.create_session_token(uid, expiry) 
        response.set_cookie("auth", token, expires=expire_date,secure=True,httponly=True)
        return response

    def register(self, username: str, password: str, groups: list[str]) -> None:
        """
        Register a user.
        """
        cur = self.db_conn.cursor()
        salt = "".join(
            secrets.choice(string.ascii_letters + string.digits + string.punctuation)
            for _ in range(64)
        )
        phash = self._sha256hash(password, salt)
        cur.execute("SELECT * FROM users WHERE username=%s", (username,))
        if cur.fetchone():
            raise errors.auth.registration.UserAlreadyExists
        uid = str(uuid4())
        cur.execute(
            "INSERT INTO users (id, username, hash, salt, groups) VALUES (%s, %s, %s, %s, %s)",
            (uid, username, phash, salt, groups),
        )

    def login(
        self, username: str, password: str, response: flask.Response
    ) -> flask.Response:
        """
        Logs in a user.
        """
        cur = self.db_conn.cursor()
        cur.execute(
            "SELECT id, username, hash, salt FROM users WHERE username=%s", (username,)
        )
        user = cur.fetchone()
        if user is None:
            raise errors.auth.login.AuthenticationFailure
        phash = self._sha256hash(password, user[3])
        print(phash)
        if phash != user[2]:
            raise errors.auth.login.AuthenticationFailure(f"{phash} {user[2]}")
        cur.execute("DELETE FROM sessions WHERE id=%s", (user[0],))

        if self.config:
            return self.create_session(user[0], response, self.config["expiry"])

        return self.create_session(user[0], response)

    def get_user(self) -> tuple | None:
        """
        Returns a tuple corresponding to schema of `users` table if a user has a valid session.
        """
        cur = self.db_conn.cursor()
        if not isinstance(token := flask.request.cookies.get("auth"), str):
            return None

        cur.execute("SELECT * FROM sessions WHERE token=%s", (token,))
        session = cur.fetchone()
        if session is None:
            return None
        if session[2] < int(time.time()):
            return None

        uid = session[0]

        cur.execute("SELECT * FROM users WHERE id=%s", (uid,))

        user = cur.fetchone()
        return user

    def change_password(self, uid: str, old_password: str, new_password: str) -> None:
        """
        Validates a user's password and changes it to a supplied string.
        This function does not provide filtering.
        """
        cur = self.db_conn.cursor()
        cur.execute("SELECT hash, salt FROM users WHERE id=%s", (uid,))
        phash, salt = cur.fetchone()
        if self._sha256hash(old_password, salt) != phash:
            raise errors.auth.generic.PasswordValidationError
        salt = "".join(
            secrets.choice(string.ascii_letters + string.digits + string.punctuation)
            for _ in range(64)
        )
        phash = self._sha256hash(new_password, salt)
        cur.execute("UPDATE users SET hash=%s, salt=%s WHERE id=%s", (phash, salt, uid))
        cur.execute("DELETE FROM sessions WHERE id=%s", (uid,))

    def get_groups(self) -> list[str] | None:
        """
        Returns a list of groups for the current logged-in user.
        """
        cur = self.db_conn.cursor()
        if not isinstance(token := flask.request.cookies.get("auth"), str):
            return None
        cur.execute("SELECT id FROM sessions WHERE token=%s", (token,))
        uid = cur.fetchone()[0]
        cur.execute("SELECT groups FROM users WHERE id=%s", (uid,))
        groups = cur.fetchone()[0]
        return groups

