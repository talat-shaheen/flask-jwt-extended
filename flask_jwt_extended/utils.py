import os
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Union

from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash

from flask_jwt_extended.exceptions import JWTDecodeError
from flask_jwt_extended.config import config


def generate_mfa_secret():
    return base64.b32encode(os.urandom(10)).decode('utf-8')


def verify_mfa_token(secret: str, token: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(token)


def create_access_token(identity: Union[str, Dict[str, Any]], 
                        fresh: bool = False, 
                        expires_delta: Optional[timedelta] = None, 
                        user_claims: Optional[Dict[str, Any]] = None,
                        additional_factor: Optional[str] = None) -> str:
    """
    Create a new access token with optional multi-factor authentication.

    :param identity: The identity of this token, which can be any data that is
                     json serializable. It can also be a python object, in which
                     case you can use the user_identity_loader to define a
                     function that will be used to pull a json serializable
                     identity out of the object.
    :param fresh: If this token should be marked as fresh, defaults to False
    :param expires_delta: An optional timedelta of how long this token should
                          last before it expires. If omitted, the
                          JWT_ACCESS_TOKEN_EXPIRES config value will be used
    :param user_claims: Optional JSON serializable to override registered claims
                        or add custom claims.
    :param additional