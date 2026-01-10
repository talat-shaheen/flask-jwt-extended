import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from flask import current_app
from flask_jwt_extended.exceptions import JWTDecodeError
from flask_jwt_extended.config import config


def create_access_token(identity: Any, fresh: bool = False, expires_delta: Optional[timedelta] = None, user_claims: Optional[Dict[str, Any]] = None) -> str:
    """
    Create a new access token with unique identification.

    :param identity: The identity of this token, which can be any data that is
                     json serializable. It can also be a python object, in which
                     case you can use the user_identity_loader to define a
                     function that will be used to pull a json serializable
                     identity out of the object.
    :param fresh: If this token should be marked as fresh, defaults to False
    :param expires_delta: A timedelta of how long this token should last before
                          it expires. Defaults to None, which uses the
                          JWT_ACCESS_TOKEN_EXPIRES config value
    :param user_claims: Optional JSON serializable to add user claims to the
                        access token.
    :return: A new access token
    """
    if expires_delta is None:
        expires_delta = config.access_expires

    now = datetime.utcnow()
    token_data = {
        'iat': now,
        'nbf': now,
        'jti': str(uuid.uuid4()),
        'exp': now + expires_delta,
        'identity': get_identity(identity),
        'fresh': fresh,
        'type': 'access'
    }

    if user_claims:
        token_data['user_claims'] = user_claims

    encoded_token = current_app.jwt_manager._encode_jwt_token(token_data)
    return encoded_token


def get_identity(identity: Any) -> str:
    # Use the identity loader if it's defined
    if current_app.jwt_manager._user_identity_loader:
        identity = current_app.jwt_manager._user_identity_loader(identity)
    
    # Ensure the identity is a string
    if not isinstance(identity, str):
        try:
            identity = str(identity)
        except Exception as e:
            raise JWTDecodeError(f"Unable to convert identity to string: {e}")
    
    return identity


def verify_token_not_blocklisted(jti: str) -> bool:
    """
    Check if the given token is blocklisted.
    This function should be implemented to integrate with your token blocklist storage.
    """
    # TODO: Implement token blocklist check
    return True  # Placeholder, replace with actual blocklist check


def get_jwt_identity():
    """
    Get the identity of the current user from the JWT in the request.
    """
    try:
        token_data = get_jwt()
        return token_data['sub']
    except Exception as e:
        current_app.logger.error(f"Failed to get JWT identity: {e}")
        return None


def get_jwt():
    """
    Get the JWT token from the current request.
    """
    try:
        return current_app.jwt_manager.get_jwt()
    except Exception as e:
        current_app.logger.error(f"Failed to get JWT: {e}")
        return None