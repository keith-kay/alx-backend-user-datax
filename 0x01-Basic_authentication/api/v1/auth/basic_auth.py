#!/usr/bin/env python3
"""Defines the class BasicAuth
"""


from api.v1.auth.auth import Auth
import base64
import binascii
from typing import TypeVar
from models.user import User
from flask import request


class BasicAuth(Auth):
    """Inherits from Auth
    """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """Returns the Base64 part of the Authorization header
        for a Basic Authentication"""
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None

        token = authorization_header.split(" ")[-1]
        return token

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Returns the decoded value of a Base64 string
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded_value = base64.b64decode(
                    base64_authorization_header).decode('utf-8')
            return decoded_value
        except (binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """Returns the user email and password from the Base64 decoded value.
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None

        email, password = decoded_base64_authorization_header.split(':', 1)
        return email, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Returns the User instance based on his email and password
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        users = User.search({'email': user_email})
        if not users:
            return None

        user = users[0]

        if not user.is_valid_password(user_pwd):
            return None

        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """Overloads Auth and retrieves the User instance for a request
        """
        if request is None:
            return None

        authorization_header = self.authorization_header(request)
        if authorization_header is None:
            return None

        base64_auth_header = self.extract_base64_authorization_header(
                authorization_header)
        if base64_auth_header is None:
            return None

        user_email, user_pwd = self.extract_user_credentials(
                base64_auth_header)
        if user_email is None or user_pwd is None:
            return None

        user = self.user_object_from_credentials(user_email, user_pwd)
        return user