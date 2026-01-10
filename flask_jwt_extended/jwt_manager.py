import logging
from datetime import datetime
from typing import Dict, Any, Optional

from flask import Flask


class AccountManager:
    
    def __init__(self, app: Flask):
        self.app = app
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.logger = logging.getLogger(__name__)
    
    def create_account(self, username: str, password: str) -> bool:
        if username in self.accounts:
            self.logger.warning(f"Account creation failed: {username} already exists")
            return False
        
        self.accounts[username] = {
            'password': password,  # In practice, use a secure hashing method
            'created_at': datetime.utcnow(),
            'last_login': None,
            'is_active': True
        }
        self.logger.info(f"Account created: {username}")
        return True
    
    def disable_account(self, username: str) -> bool:
        if username not in self.accounts:
            self.logger.warning(f"Account disable failed: {username} not found")
            return False
        
        self.accounts[username]['is_active'] = False
        self.logger.info(f"Account disabled: {username}")
        return True
    
    def enable_account(self, username: str) -> bool:
        if username not in self.accounts:
            self.logger.warning(f"Account enable failed: {username} not found")
            return False
        
        self.accounts[username]['is_active'] = True
        self.logger.info(f"Account enabled: {username}")
        return True
    
    def delete_account(self, username: str) -> bool:
        if username not in self.accounts:
            self.logger.warning(f"Account deletion failed: {username} not found")
            return False
        
        del self.accounts[username]
        self.logger.info(f"Account deleted: {username}")
        return True
    
    def update_last_login(self, username: str) -> bool:
        if username not in self.accounts:
            self.logger.warning(f"Last login update failed: {username} not found")
            return False
        
        self.accounts[username]['last_login'] = datetime.utcnow()
        return True


class JWTManager:
    
    def __init__(self, app: Optional[Flask] = None):
        self._user_claims_callback = None
        self._expired_token_callback = None
        self._invalid_token_callback = None
        self._token_in_blacklist_callback = None
        self.account_manager: Optional[AccountManager] = None
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        self.account_manager = AccountManager(app)
    
    def create_account(self, username: str, password: str) -> bool:
        if self.account_manager is None:
            raise RuntimeError("JWTManager must be initialized with an app")
        return self.account_manager.create_account(username, password)
    
    def disable_account(self, username: str) -> bool:
        if self.account_manager is None:
            raise RuntimeError("JWTManager must be initialized with an app")
        return self.account_manager.disable_account(username)
    
    def enable_account(self, username: str) -> bool:
        if self.account_manager is None:
            raise RuntimeError("JWTManager must be initialized with an app")
        return self.account_manager.enable_account(username)
    
    def delete_account(self, username: str) -> bool:
        if self.account_manager is None:
            raise RuntimeError("JWTManager must be initialized with an app")
        return self.account_manager.delete_account(username)
    
    def update_last_login(self, username: str) -> bool:
        if self.account_manager is None:
            raise RuntimeError("JWTManager must be initialized with an app")
        return self.account_manager.update_last_login(username)