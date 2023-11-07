#!/usr/bin/env python3
"""Defines a class auth
"""


from flask import request
from typing import List, TypeVar


class Auth():
    """ defines authentication system
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Manages paths
        """
        if path is None:
            return True
        if excluded_paths is None or not excluded_paths:
            return True
        for excluded_path in excluded_paths:
            if path.startswith(excluded_path.rstrip('/')):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """Handles authentication requests
        """
        if request is None:
            return None
        header = request.headers.get('Authorization')
        return header if header else None

    def current_user(self, request=None) -> TypeVar('User'):
        """Handles authentication users
        """
        return None